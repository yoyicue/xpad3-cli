mod apk;
mod catalog;
mod device;
mod embedded;
mod error;
mod install;
mod logging;
mod model;
mod ota;
mod profile;
mod root;
mod transaction;
mod update;
mod util;

use crate::catalog::Catalog;
use crate::error::{Error, Result, msg, needs_reboot};
use crate::logging::TransactionLog;
use crate::model::{ComponentState, Receipt};
use crate::util::{OperationLock, Paths, boot_id, selinux};
use serde_json::json;
use std::path::{Path, PathBuf};

fn main() {
    match run_main() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("xpad3: {error}");
            std::process::exit(if error.requires_reboot() { 75 } else { 1 });
        }
    }
}

fn run_main() -> Result<()> {
    let (args, cache_override) = parse_global_options(std::env::args().skip(1).collect())?;
    let catalog = Catalog::load()?;
    let paths = Paths::new(
        cache_override.as_deref(),
        &catalog.lock.product_version,
        &catalog.lock.catalog_version,
    )?;
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    match command {
        "help" | "-h" | "--help" => print_help(),
        "version" | "--version" | "-V" => {
            println!(
                "xpad3 {} (catalog {})",
                env!("CARGO_PKG_VERSION"),
                catalog.lock.catalog_version
            );
        }
        "status" => command_status(&catalog, &paths, &args[1..])?,
        "list" => command_list(&catalog),
        "info" => command_info(&catalog, &paths, &args[1..])?,
        "doctor" => command_doctor(&catalog, &paths)?,
        "verify" => command_verify(&catalog, &paths, &args[1..])?,
        "root" => command_root(&catalog, &paths, &args[1..])?,
        "freeze" => command_freeze(&catalog, &paths, &args[1..])?,
        "unfreeze" => command_unfreeze(&catalog, &paths, &args[1..])?,
        "install" => command_install(&catalog, &paths, &args[1..])?,
        "repair" => command_repair(&catalog, &paths, &args[1..])?,
        "cleanup" => command_cleanup(&catalog, &paths)?,
        "logs" => command_logs(&catalog, &paths, &args[1..])?,
        "cache" => command_cache(&catalog, &paths, &args[1..])?,
        "update" => command_update(&catalog, &paths, &args[1..])?,
        "_update-verify-candidate" => update::verify_candidate_command(&catalog, &args[1..])?,
        "_update-export-cache" => update::export_candidate_cache_command(&catalog, &args[1..])?,
        other => return Err(msg(format!("unknown command: {other}; run `xpad3 help`"))),
    }
    Ok(())
}

fn parse_global_options(args: Vec<String>) -> Result<(Vec<String>, Option<PathBuf>)> {
    let mut clean = Vec::new();
    let mut cache = None;
    let mut index = 0;
    let mut passthrough = false;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            passthrough = true;
            clean.push(arg.clone());
        } else if !passthrough && arg == "--cache-dir" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| msg("--cache-dir requires a directory"))?;
            cache = Some(PathBuf::from(value));
        } else if !passthrough {
            if let Some(value) = arg.strip_prefix("--cache-dir=") {
                if value.is_empty() {
                    return Err(msg("--cache-dir requires a directory"));
                }
                cache = Some(PathBuf::from(value));
            } else {
                clean.push(arg.clone());
            }
        } else {
            clean.push(arg.clone());
        }
        index += 1;
    }
    Ok((clean, cache))
}

fn command_status(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() > 1 || args.first().is_some_and(|arg| arg != "--json") {
        return Err(msg("usage: xpad3 status [--json]"));
    }
    let status = device::snapshot(catalog, paths);
    if args.first().is_some_and(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!(
            "xpad3 {}  XPad3现代内核设备={}  精确Root-profile={}  SELinux={}",
            status.product_version,
            yes_no(status.product_supported),
            yes_no(status.supported),
            status.selinux
        );
        println!("boot-id: {}", status.boot_id);
        println!(
            "profile: fingerprint_incremental={} kernel={} kernel_build={}",
            status
                .fingerprint_incremental
                .map(|value| format!("/{value}"))
                .unwrap_or_else(|| "unparsed".to_string()),
            status.kernel_release,
            status.kernel_version
        );
        render_component(&status.temporary_root);
        for component in &status.components {
            render_component(component);
        }
        for warning in &status.transaction_warnings {
            println!("TRANSACTION: {warning}");
        }
        if let Some(action) = &status.action_required {
            println!("ACTION: {action}");
        }
    }
    Ok(())
}

fn command_list(catalog: &Catalog) {
    println!("ota              policy   freeze supported XPad3 system OTA package for user 0");
    println!("ksu              runtime  KernelSU 32547 / UAPI 2 / android12-5.10 / current boot");
    println!("ionstack-trigger internal profile-managed trigger; never installed standalone");
    println!("installer-backup policy   managed 0044 device-OEM fallback installer");
    for id in ["ksu-manager", "xpad-installer", "boominstaller"] {
        if let Ok(a) = catalog.artifact(id) {
            println!(
                "{:<16} {:<8} {}",
                a.id,
                format!("{:?}", a.kind).to_ascii_lowercase(),
                a.version
            );
        }
    }
    println!("full             bundle   default: ksu + matching Manager + installers");
}

fn command_info(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(msg("usage: xpad3 info COMPONENT"));
    }
    let id = &args[0];
    if id == "ota" {
        println!(
            "id: ota\nkind: policy\npackages: {}\nlifecycle: persistent until `xpad3 unfreeze ota`",
            ota::PACKAGES.join(", ")
        );
        render_component(&ota::status());
        return Ok(());
    }
    if id == "ksu" {
        println!(
            "id: ksu\nkind: runtime\nversion: 32547\nuapi: 2\nkmi: android12-5.10\nlate-load: --allow-shell\nlifecycle: current-boot"
        );
        render_component(&device::ksu_status(paths));
        return Ok(());
    }
    if id == "installer-backup" {
        println!(
            "id: installer-backup\nkind: policy\nidentity: znxrun / device OEM installer UID\nanchor: com.yoyicue.xpad2.installeranchor\nlifecycle: persistent package metadata"
        );
        render_component(&device::installer_backup_status(
            catalog.artifact("xpad-installer")?,
        ));
        return Ok(());
    }
    let artifact = catalog.artifact(id)?;
    println!("{}", serde_json::to_string_pretty(artifact)?);
    let state = match artifact.kind {
        model::ArtifactKind::Cli => device::cli_status(artifact),
        model::ArtifactKind::Apk => device::apk_status(artifact),
        _ => return Ok(()),
    };
    render_component(&state);
    Ok(())
}

fn command_doctor(catalog: &Catalog, paths: &Paths) -> Result<()> {
    let snapshot = device::snapshot(catalog, paths);
    println!(
        "[{}] XPad3 modern-kernel product profile / arm64 control plane",
        if snapshot.product_supported {
            "OK"
        } else {
            "FAIL"
        }
    );
    println!(
        "[{}] IonStack Root profile: TALIH-PD3S /338 + exact Android 12 5.10.198 kernel",
        if snapshot.supported { "OK" } else { "WARN" }
    );
    println!(
        "[{}] SELinux {}",
        if snapshot.selinux == "Enforcing" {
            "OK"
        } else {
            "WARN"
        },
        snapshot.selinux
    );
    println!("[INFO] 普通 APK 安装不会把 Root、simpleperf 授权或 KSU Manager 当作预检查条件");
    render_component(&snapshot.temporary_root);
    for component in &snapshot.components {
        render_component(component);
    }
    for warning in &snapshot.transaction_warnings {
        println!("[WARN] {warning}");
    }
    if paths.cache.join("catalog.json").exists() || paths.cache.join("catalog.sig").exists() {
        match catalog::verify_cache(paths, catalog) {
            Ok(ids) => println!("[OK] cache signature + {} blobs verified", ids.len()),
            Err(error) => println!("[FAIL] cache: {error}"),
        }
    } else {
        println!("[INFO] cache empty; locked embedded artifacts are available");
    }
    if !snapshot.product_supported {
        return Err(msg("device is not in the signed XPad3 product family"));
    }
    if !snapshot.supported {
        println!(
            "[INFO] Root/KSU unavailable on this exact profile; OTA policy, installers and Manager APK remain available"
        );
    }
    if let Some(component) = snapshot
        .components
        .iter()
        .find(|component| component.state == ComponentState::NeedsReboot)
    {
        return Err(Error::NeedsReboot(
            component
                .detail
                .clone()
                .unwrap_or_else(|| component.id.clone()),
        ));
    }
    Ok(())
}

fn command_verify(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(msg("usage: xpad3 verify [COMPONENT]"));
    }
    let snapshot = device::snapshot(catalog, paths);
    let selected: Vec<_> = if let Some(id) = args.first() {
        let state = device::component(&snapshot, id)
            .ok_or_else(|| msg(format!("unknown component: {id}")))?;
        vec![state]
    } else {
        std::iter::once(&snapshot.temporary_root)
            .chain(snapshot.components.iter())
            .collect()
    };
    let verifying_all = args.is_empty();
    let supported_runtime_active = snapshot
        .components
        .iter()
        .any(|component| component.id == "ksu" && component.state == ComponentState::Active);
    let mut failed = Vec::new();
    for state in selected {
        render_component(state);
        let healthy = match state.id.as_str() {
            "temporary-root" => {
                matches!(state.state, ComponentState::Absent | ComponentState::Active)
            }
            "ksu" => {
                state.state == ComponentState::Active
                    || (verifying_all
                        && supported_runtime_active
                        && state.state == ComponentState::Ready)
            }
            "ota" => state.state == ComponentState::Active,
            "boominstaller" => state.state == ComponentState::Active,
            "installer-backup" => state.state == ComponentState::Active,
            _ => state.state == ComponentState::Installed,
        };
        if !healthy {
            failed.push(state.id.clone());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(msg(format!("verification failed: {}", failed.join(", "))))
    }
}

fn command_root(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let command = if args.is_empty() {
        None
    } else if args.first().is_some_and(|arg| arg == "--") {
        Some(root::command_from_argv(&args[1..])?)
    } else {
        return Err(msg("usage: xpad3 root [-- COMMAND ARG...]"));
    };
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, "root")?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    device::root_profile_check(catalog)?;
    if device::ksu_module_loaded() {
        return Err(msg(
            "KernelSU is already active in this boot; use its su channel instead of starting another exploit session",
        ));
    }
    if device::ionstack_trigger_running(catalog)? {
        return Err(needs_reboot(
            "IonStack trigger is already running; ordinary reboot required before another Root attempt",
        ));
    }
    let trigger = device::current_root_profile(catalog)?
        .trigger_artifact
        .clone();
    let package_changed = install::install_locked_apk(catalog, paths, &trigger, &mut log)?;
    if package_changed {
        install::ensure_installer_backup(catalog.artifact("xpad-installer")?, &mut log)?;
    }
    let session = root::RootSession::acquire(catalog, paths, &mut log, true)?;
    let mut error = None;
    if let Some(command) = command {
        let output = session.exec(&command)?;
        log.command_result("root-command", output.status == 0, &output.text)?;
        if output.status != 0 {
            error = Some(format!("root command exited with {}", output.status));
        }
    }
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: "root".to_string(),
        success: error.is_none(),
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components: vec![
            "ota".to_string(),
            trigger,
            "xpad-installer".to_string(),
            "installer-backup".to_string(),
            "temporary-root".to_string(),
        ],
        error: error.clone(),
        needs_reboot: false,
    };
    log.write_receipt(paths, &receipt)?;
    println!(
        "临时 Root 已验证并保留在当前启动周期；SELinux 当前为 {}。执行 `/data/local/tmp/su`，完成后务必运行 `xpad3 cleanup` 或普通重启。",
        selinux()
    );
    if let Some(error) = error {
        return Err(msg(error));
    }
    Ok(())
}

fn command_freeze(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] != "ota" {
        return Err(msg("usage: xpad3 freeze ota"));
    }
    simple_transaction(paths, "freeze ota", |log| {
        device::product_check(catalog)?;
        let state = ota::freeze(log)?;
        render_component(&state);
        Ok(vec!["ota".to_string()])
    })
}

fn command_unfreeze(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] != "ota" {
        return Err(msg("usage: xpad3 unfreeze ota"));
    }
    simple_transaction(paths, "unfreeze ota", |log| {
        device::product_check(catalog)?;
        let state = ota::unfreeze(log)?;
        render_component(&state);
        Ok(vec!["ota".to_string()])
    })
}

fn command_install(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let Some(first) = args.first().map(String::as_str) else {
        return transaction::install_components(catalog, paths, args);
    };
    match first {
        "cli" => install_arbitrary_cli(catalog, paths, &args[1..]),
        "apk" => install_arbitrary_apk(catalog, paths, &args[1..]),
        _ => transaction::install_components(catalog, paths, args),
    }
}

fn install_arbitrary_cli(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(msg("usage: xpad3 install cli FILE [--name NAME]"));
    }
    let source = PathBuf::from(&args[0]);
    let name = match args.get(1).map(String::as_str) {
        None => None,
        Some("--name") if args.len() == 3 => Some(args[2].as_str()),
        _ => return Err(msg("usage: xpad3 install cli FILE [--name NAME]")),
    };
    simple_transaction(paths, "install cli", |log| {
        device::product_check(catalog)?;
        let target = install::install_arbitrary_cli(&source, name, log)?;
        println!("installed: {}", target.display());
        Ok(vec![target.display().to_string()])
    })
}

fn install_arbitrary_apk(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(msg("usage: xpad3 install apk FILE"));
    }
    let source = PathBuf::from(&args[0]);
    simple_transaction(paths, "install apk", |log| {
        device::product_check(catalog)?;
        install::install_locked_cli(catalog, paths, "xpad-installer", log)?;
        let identity =
            install::install_arbitrary_apk(&source, catalog.artifact("xpad-installer")?, log)?;
        println!(
            "installed: {} versionCode={}",
            identity.package, identity.version_code
        );
        Ok(vec![identity.package])
    })
}

fn command_repair(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] == "full" {
        return Err(msg("usage: xpad3 repair COMPONENT"));
    }
    if args[0] == "installer-backup" {
        return simple_transaction(paths, "repair installer-backup", |log| {
            device::product_check(catalog)?;
            install::install_locked_cli(catalog, paths, "xpad-installer", log)?;
            Ok(vec![
                "xpad-installer".to_string(),
                "installer-backup".to_string(),
            ])
        });
    }
    transaction::install_components(catalog, paths, args)
}

fn command_cleanup(catalog: &Catalog, paths: &Paths) -> Result<()> {
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, "cleanup")?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    let mut installer_cleanup_error: Option<Error> = None;
    if device::root_status().state == ComponentState::Active {
        let session = root::RootSession {
            owned: true,
            started_boot_id: started_boot.clone(),
        };
        session.close(&mut log)?;
    }
    if Path::new("/data/local/tmp/xpad-install").exists() {
        let verified = catalog
            .artifact("xpad-installer")
            .and_then(device::verify_locked_cli_path);
        match verified {
            Err(error) => {
                installer_cleanup_error = Some(msg(format!(
                    "refusing xpad-install cleanup with an unverified engine: {error}"
                )))
            }
            Ok(program) => match log.run_streaming("xpad-install cleanup", program, &["cleanup"]) {
                Ok(output) if output.status.success() => {}
                Ok(output) if output.status.code() == Some(75) => {
                    installer_cleanup_error = Some(crate::error::needs_reboot(
                        "xpad-install cleanup found a per-boot unsafe state",
                    ));
                }
                Ok(output) => {
                    installer_cleanup_error = Some(msg(format!(
                        "xpad-install cleanup failed (exit {:?}): {}",
                        output.status.code(),
                        output.text
                    )));
                }
                Err(error) => installer_cleanup_error = Some(error),
            },
        }
    }
    install::cleanup_work(paths)?;
    for path in [
        "/data/local/tmp/ionstack_reroot_device",
        "/data/local/tmp/ionstack_perf_target",
        "/data/local/tmp/ionstack_preload.so",
        "/data/local/tmp/cve43499_chainwalk_probe_arm32",
        "/data/local/tmp/temp_su.sock",
    ] {
        let _ = util::remove_if_exists(Path::new(path));
    }
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: "cleanup".to_string(),
        success: installer_cleanup_error.is_none(),
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components: vec![],
        error: installer_cleanup_error.as_ref().map(ToString::to_string),
        needs_reboot: installer_cleanup_error
            .as_ref()
            .is_some_and(Error::requires_reboot),
    };
    log.write_receipt(paths, &receipt)?;
    if let Some(error) = installer_cleanup_error {
        return Err(error);
    }
    println!("cleanup complete; artifact cache was preserved");
    Ok(())
}

fn command_logs(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 2 || args[0] != "export" {
        return Err(msg("usage: xpad3 logs export DIRECTORY"));
    }
    let output = logging::export_logs(catalog, paths, Path::new(&args[1]))?;
    println!("{}", output.display());
    Ok(())
}

fn command_cache(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(msg(
            "usage: xpad3 cache path|list|verify|import|prune|clear",
        ));
    };
    match command {
        "path" if args.len() == 1 => println!("{}", paths.cache.display()),
        "list" if args.len() == 1 => {
            if !paths.cache.join("catalog.json").exists() {
                println!("cache empty: {}", paths.cache.display());
            } else {
                for id in catalog::verify_cache(paths, catalog)? {
                    let a = catalog.artifact(&id)?;
                    println!("{} {} {}", a.id, a.version, a.sha256);
                }
            }
        }
        "verify" if args.len() == 1 => {
            let ids = catalog::verify_cache(paths, catalog)?;
            println!("verified signed catalog and {} cached blobs", ids.len());
        }
        "import" if args.len() == 2 => {
            let source = PathBuf::from(&args[1]);
            simple_transaction(paths, "cache import", |log| {
                let count = catalog::import_cache(&source, paths, catalog)?;
                log.event(
                    "cache",
                    "imported",
                    json!({"source": source, "blobs": count}),
                )?;
                println!("imported {count} blobs into {}", paths.cache.display());
                Ok(vec![])
            })?;
        }
        "prune" if args.len() == 1 => {
            simple_transaction(paths, "cache prune", |log| {
                let count = catalog::prune_cache(paths, catalog)?;
                log.event("cache", "pruned", json!({"removed": count}))?;
                println!(
                    "removed {count} obsolete cache files; kept current and one rollback release"
                );
                Ok(vec![])
            })?;
        }
        "clear" if args.len() == 1 => {
            simple_transaction(paths, "cache clear", |log| {
                let count = catalog::clear_cache(paths)?;
                log.event("cache", "cleared", json!({"removed": count}))?;
                println!("removed {count} cache files; embedded baseline remains available");
                Ok(vec![])
            })?;
        }
        _ => {
            return Err(msg(
                "usage: xpad3 cache path|list|verify|import DIRECTORY|prune|clear",
            ));
        }
    }
    Ok(())
}

fn command_update(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let request = update::parse_args(args)?;
    if request.check {
        return update::check(catalog, paths, &request);
    }
    // Keep every mutating update step inside this transaction: its OperationLock
    // is acquired before TransactionLog::start and before update::apply performs
    // downloads, cache swaps, binary replacement, rollback, or receipt writes.
    simple_transaction(paths, "self update", |log| {
        let changed = update::apply(catalog, paths, &request, log)?;
        Ok(if changed {
            vec!["xpad3".to_string()]
        } else {
            vec![]
        })
    })
}

fn simple_transaction<F>(paths: &Paths, operation: &str, action: F) -> Result<()>
where
    F: FnOnce(&mut TransactionLog) -> Result<Vec<String>>,
{
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, operation)?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    let result = action(&mut log);
    let (components, error, needs_reboot) = match &result {
        Ok(components) => (components.clone(), None, false),
        Err(error) => (vec![], Some(error.to_string()), error.requires_reboot()),
    };
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: operation.to_string(),
        success: result.is_ok(),
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components,
        error,
        needs_reboot,
    };
    log.write_receipt(paths, &receipt)?;
    result.map(|_| ())
}

fn render_component(component: &model::ComponentStatus) {
    println!(
        "{:<16} {:<13} {}",
        component.id,
        component.state,
        component.detail.as_deref().unwrap_or("")
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn print_help() {
    println!(
        "xpad3 {} - signed installer for profile-gated XPad3 modern-kernel devices\n\n\
Usage:\n  xpad3 status [--json]\n  xpad3 doctor\n  xpad3 list | info COMPONENT\n  xpad3 update [--check] [--version VERSION] [--offline DIRECTORY_OR_ZIP]\n  xpad3 root [-- COMMAND ARG...]\n  xpad3 freeze ota | unfreeze ota\n  xpad3 install [COMPONENT...]             # default: full (KSU)\n  xpad3 install cli FILE [--name NAME]\n  xpad3 install apk FILE\n  xpad3 verify [COMPONENT]\n  xpad3 repair COMPONENT\n  xpad3 cleanup\n  xpad3 logs export DIRECTORY\n  xpad3 cache path|list|verify|import DIRECTORY|prune|clear\n\n\
Built-ins: ota, ksu, ksu-manager, xpad-installer, installer-backup, boominstaller, full\n\
Global: --cache-dir DIRECTORY (or XPAD3_CACHE_DIR)\n\n\
Self-update: --reinstall repairs the same version; a downgrade also requires --allow-downgrade.\n\n\
Exit 75 means an ordinary reboot is required.",
        env!("CARGO_PKG_VERSION")
    );
}
