use crate::catalog::Catalog;
use crate::device;
use crate::error::{IoContext, Result, msg};
use crate::model::Receipt;
use crate::util::{
    Paths, atomic_write, boot_id, epoch_seconds, run, selinux, timestamp_filename, unique_id,
};
use serde_json::{Map, Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{OnceLock, mpsc};
use std::thread;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const DEBUGLOGGER_MAX_BOOT_DIRS: usize = 3;
const LAST_KMSG_MAX_BYTES: u64 = 16 * 1024 * 1024;
const MBLOG_HISTORY_MAX_BYTES: u64 = 2 * 1024 * 1024;

pub struct TransactionLog {
    pub id: String,
    pub dir: PathBuf,
    events: File,
    raw: File,
    active_path: PathBuf,
}

pub struct LoggedCommandOutput {
    pub status: ExitStatus,
    pub text: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ActiveTransaction {
    id: String,
    operation: String,
    boot_id: String,
    pid: u32,
    started_at: u64,
}

impl TransactionLog {
    pub fn start(paths: &Paths, operation: &str) -> Result<Self> {
        paths.ensure()?;
        recover_interrupted_transactions(paths)?;
        let id = format!("{}-{}", timestamp_filename(), unique_id());
        let dir = paths.logs.join(&id);
        fs::create_dir_all(&dir).at(&dir)?;
        fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).at(&dir)?;
        let events_path = dir.join("events.jsonl");
        let raw_path = dir.join("raw.log");
        let events = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&events_path)
            .at(&events_path)?;
        let raw = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&raw_path)
            .at(&raw_path)?;
        let mut log = Self {
            id,
            dir,
            events,
            raw,
            active_path: paths.state.join("active-transaction.json"),
        };
        let active = ActiveTransaction {
            id: log.id.clone(),
            operation: operation.to_string(),
            boot_id: boot_id(),
            pid: std::process::id(),
            started_at: epoch_seconds(),
        };
        atomic_write(
            &log.active_path,
            &serde_json::to_vec_pretty(&active)?,
            0o600,
        )?;
        log.event("transaction", "started", json!({"operation": operation}))?;
        Ok(log)
    }

    pub fn event(&mut self, event: &str, state: &str, fields: Value) -> Result<()> {
        let mut map = Map::new();
        map.insert("ts".to_string(), json!(epoch_seconds()));
        map.insert("event".to_string(), json!(event));
        map.insert("state".to_string(), json!(state));
        if let Value::Object(extra) = fields {
            map.extend(extra);
        }
        serde_json::to_writer(&mut self.events, &Value::Object(map))?;
        self.events
            .write_all(b"\n")
            .at(self.dir.join("events.jsonl"))?;
        self.events.flush().at(self.dir.join("events.jsonl"))?;
        self.events.sync_data().at(self.dir.join("events.jsonl"))?;
        Ok(())
    }

    pub fn line(&mut self, source: &str, line: &str) -> Result<()> {
        let redacted = redact(line);
        writeln!(self.raw, "[{source}] {redacted}").at(self.dir.join("raw.log"))?;
        self.raw.flush().at(self.dir.join("raw.log"))?;
        self.raw.sync_data().at(self.dir.join("raw.log"))?;
        println!("{redacted}");
        Ok(())
    }

    pub fn run_streaming(
        &mut self,
        name: &str,
        program: &str,
        args: &[&str],
    ) -> Result<LoggedCommandOutput> {
        self.event("command", "started", json!({"name": name}))?;
        let mut child = match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                self.event(
                    "command",
                    "failed",
                    json!({"name": name, "spawn_error": error.to_string()}),
                )?;
                return Err(msg(format!("failed to execute {program}: {error}")));
            }
        };
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| msg(format!("cannot capture stdout for {program}")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| msg(format!("cannot capture stderr for {program}")))?;
        let (sender, receiver) = mpsc::channel::<(&'static str, String)>();
        let stdout_thread = stream_reader(stdout, "stdout", sender.clone());
        let stderr_thread = stream_reader(stderr, "stderr", sender.clone());
        drop(sender);

        let mut combined = String::new();
        for (stream, line) in receiver {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(&line);
            self.line(&format!("{name}/{stream}"), &line)?;
        }
        let status = child
            .wait()
            .map_err(|error| msg(format!("failed waiting for {program}: {error}")))?;
        for (stream, handle) in [("stdout", stdout_thread), ("stderr", stderr_thread)] {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(msg(format!(
                        "failed reading {stream} from {program}: {error}"
                    )));
                }
                Err(_) => return Err(msg(format!("{stream} reader panicked for {program}"))),
            }
        }
        self.event(
            "command",
            if status.success() {
                "succeeded"
            } else {
                "failed"
            },
            json!({"name": name, "exit_code": status.code()}),
        )?;
        Ok(LoggedCommandOutput {
            status,
            text: combined,
        })
    }

    pub fn command_result(&mut self, name: &str, success: bool, output: &str) -> Result<()> {
        for line in output.lines() {
            self.line(name, line)?;
        }
        self.event(
            "command",
            if success { "succeeded" } else { "failed" },
            json!({"name": name}),
        )
    }

    pub fn prepare_ksu_trace(&mut self, runtime: &str, kmi: &str) -> Result<PathBuf> {
        let path = self.dir.join("ksu-late-load-stages.jsonl");
        atomic_write(&path, b"", 0o600)?;
        self.ksu_stage(
            &path,
            "trace-armed",
            json!({"runtime": runtime, "kmi": kmi}),
        )?;
        Ok(path)
    }

    pub fn ksu_stage(&mut self, path: &Path, stage: &str, fields: Value) -> Result<()> {
        let expected = self.dir.join("ksu-late-load-stages.jsonl");
        if path != expected {
            return Err(msg("invalid KSU stage trace path"));
        }
        let mut map = Map::new();
        map.insert("ts".to_string(), json!(epoch_seconds()));
        map.insert("boot_id".to_string(), json!(boot_id()));
        map.insert("pid".to_string(), json!(std::process::id()));
        map.insert("source".to_string(), json!("xpad3"));
        map.insert("stage".to_string(), json!(stage));
        if let Value::Object(extra) = fields {
            map.extend(extra);
        }
        let mut line = serde_json::to_vec(&Value::Object(map))?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .at(path)?;
        file.write_all(&line).at(path)?;
        file.flush().at(path)?;
        file.sync_data().at(path)
    }

    pub fn write_receipt(&mut self, paths: &Paths, receipt: &Receipt) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(receipt)?;
        atomic_write(&self.dir.join("receipt.json"), &bytes, 0o600)?;
        atomic_write(&paths.state.join("last-transaction.json"), &bytes, 0o600)?;
        if receipt.success {
            atomic_write(&paths.state.join("last-success.json"), &bytes, 0o600)?;
        }
        self.event(
            "transaction",
            if receipt.success {
                "succeeded"
            } else {
                "failed"
            },
            json!({"needs_reboot": receipt.needs_reboot, "error": receipt.error}),
        )?;
        self.raw.sync_data().at(self.dir.join("raw.log"))?;
        if let Ok(raw) = fs::read(&self.active_path)
            && let Ok(active) = serde_json::from_slice::<ActiveTransaction>(&raw)
            && active.id == self.id
        {
            fs::remove_file(&self.active_path).at(&self.active_path)?;
            if let Some(parent) = self.active_path.parent() {
                File::open(parent).at(parent)?.sync_all().at(parent)?;
            }
        }
        Ok(())
    }
}

fn stream_reader<R: Read + Send + 'static>(
    reader: R,
    stream: &'static str,
    sender: mpsc::Sender<(&'static str, String)>,
) -> thread::JoinHandle<std::io::Result<()>> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            let count = reader.read_until(b'\n', &mut bytes)?;
            if count == 0 {
                return Ok(());
            }
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            if sender
                .send((stream, String::from_utf8_lossy(&bytes).into_owned()))
                .is_err()
            {
                return Ok(());
            }
        }
    })
}

pub fn transaction_warnings(paths: &Paths) -> Vec<String> {
    let current_boot = boot_id();
    let mut warnings = Vec::new();
    let active_path = paths.state.join("active-transaction.json");
    if let Ok(raw) = fs::read(&active_path)
        && let Ok(active) = serde_json::from_slice::<ActiveTransaction>(&raw)
    {
        if active.boot_id == current_boot && Path::new(&format!("/proc/{}", active.pid)).exists() {
            warnings.push(format!(
                "transaction {} ({}) is currently active",
                active.id, active.operation
            ));
        } else {
            warnings.push(format!(
                "transaction {} ({}) was interrupted; boot {} -> {}",
                active.id, active.operation, active.boot_id, current_boot
            ));
        }
    }
    if let Ok(entries) = fs::read_dir(&paths.logs) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.join("receipt.json").exists() {
                let id = entry.file_name().to_string_lossy().to_string();
                if !warnings.iter().any(|warning| warning.contains(&id)) {
                    warnings.push(format!("transaction {id} has no final receipt (process terminated or device rebooted)"));
                }
            }
        }
    }
    warnings.sort();
    warnings
}

fn recover_interrupted_transactions(paths: &Paths) -> Result<()> {
    let current_boot = boot_id();
    let active_path = paths.state.join("active-transaction.json");
    let active = fs::read(&active_path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<ActiveTransaction>(&raw).ok());
    if let Some(active) = &active {
        let receipt_path = paths.logs.join(&active.id).join("receipt.json");
        if !receipt_path.exists() {
            let receipt = Receipt {
                transaction_id: active.id.clone(),
                operation: active.operation.clone(),
                success: false,
                started_boot_id: active.boot_id.clone(),
                ended_boot_id: current_boot.clone(),
                started_selinux: "unknown".to_string(),
                ended_selinux: selinux(),
                components: vec![],
                error: Some("transaction interrupted before final receipt; device reboot or process termination detected".to_string()),
                needs_reboot: active.boot_id == current_boot,
            };
            atomic_write(&receipt_path, &serde_json::to_vec_pretty(&receipt)?, 0o600)?;
        }
    }
    if active_path.exists() {
        fs::remove_file(&active_path).at(&active_path)?;
    }
    if let Ok(entries) = fs::read_dir(&paths.logs) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() || dir.join("receipt.json").exists() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let receipt = Receipt {
                transaction_id: id,
                operation: "unknown interrupted transaction".to_string(),
                success: false,
                started_boot_id: "unknown".to_string(),
                ended_boot_id: current_boot.clone(),
                started_selinux: "unknown".to_string(),
                ended_selinux: selinux(),
                components: vec![],
                error: Some(
                    "no final receipt was found; recovered on the next modifying operation"
                        .to_string(),
                ),
                needs_reboot: false,
            };
            atomic_write(
                &dir.join("receipt.json"),
                &serde_json::to_vec_pretty(&receipt)?,
                0o600,
            )?;
        }
    }
    Ok(())
}

pub fn redact(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let sensitive = [
        "serialno",
        "persist.sys.adb",
        "adb_keys",
        "adbkey",
        "private key",
        "private_key",
        "password=",
        "token=",
        "client_secret",
        "authorization: bearer",
        "bearer ",
        "pairing_code",
        "pairing code",
    ];
    if sensitive.iter().any(|needle| lower.contains(needle)) {
        "[REDACTED sensitive diagnostic line]".to_string()
    } else {
        let mut output = input.to_string();
        for identifier in device_identifiers() {
            output = output.replace(identifier, "[REDACTED_SERIAL]");
        }
        output
    }
}

fn device_identifiers() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES.get_or_init(|| {
        [
            "ro.serialno",
            "ro.boot.serialno",
            "ro.boot.genie.serialno",
            "ro.genie.serialno",
        ]
        .into_iter()
        .map(crate::util::getprop)
        .filter(|value| value.len() >= 6 && value != "unknown")
        .collect()
    })
}

pub fn export_logs(catalog: &Catalog, paths: &Paths, destination: &Path) -> Result<PathBuf> {
    paths.ensure()?;
    if !destination.is_dir() {
        return Err(msg(format!(
            "log export destination is not a directory: {}",
            destination.display()
        )));
    }
    let staging = paths.work.join(format!("log-export-{}", unique_id()));
    fs::create_dir_all(&staging).at(&staging)?;
    let result = (|| {
        atomic_write(
            &staging.join("assets.lock.json"),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets.lock.json")),
            0o600,
        )?;
        atomic_write(
            &staging.join("sources.lock.json"),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/sources.lock.json")),
            0o600,
        )?;
        let summary = json!({
            "product_version": env!("CARGO_PKG_VERSION"),
            "boot_id": boot_id(),
            "selinux": selinux(),
            "exported_at": epoch_seconds(),
            "transaction_warnings": transaction_warnings(paths)
        });
        atomic_write(
            &staging.join("summary.json"),
            &serde_json::to_vec_pretty(&summary)?,
            0o600,
        )?;

        capture(&staging.join("getprop.txt"), "/system/bin/getprop", &[])?;
        capture(&staging.join("uname.txt"), "/system/bin/uname", &["-a"])?;
        capture(
            &staging.join("logcat-current.txt"),
            "/system/bin/logcat",
            &["-b", "all", "-d"],
        )?;
        capture(
            &staging.join("logcat-previous-boot.txt"),
            "/system/bin/logcat",
            &["-L", "-b", "all", "-d"],
        )?;
        capture(
            &staging.join("logcat-kernel-current.txt"),
            "/system/bin/logcat",
            &["-b", "kernel", "-d"],
        )?;
        capture(
            &staging.join("logcat-kernel-previous-boot.txt"),
            "/system/bin/logcat",
            &["-L", "-b", "kernel", "-d"],
        )?;
        capture(
            &staging.join("last-kmsg-dropbox.txt"),
            "/system/bin/dumpsys",
            &["dropbox", "--print", "SYSTEM_LAST_KMSG"],
        )?;
        for (filename, tag) in [
            ("kernel-panic-dropbox.txt", "SYSTEM_KERNEL_PANIC"),
            ("recovery-log-dropbox.txt", "SYSTEM_RECOVERY_LOG"),
            ("restart-dropbox.txt", "SYSTEM_RESTART"),
        ] {
            capture(
                &staging.join(filename),
                "/system/bin/dumpsys",
                &["dropbox", "--print", tag],
            )?;
        }
        capture(
            &staging.join("system-server-crash-dropbox.txt"),
            "/system/bin/dumpsys",
            &["dropbox", "--print", "system_server_crash"],
        )?;
        capture(
            &staging.join("system-app-crash-dropbox.txt"),
            "/system/bin/dumpsys",
            &["dropbox", "--print", "system_app_crash"],
        )?;
        capture(
            &staging.join("process-exit-info.txt"),
            "/system/bin/dumpsys",
            &["activity", "exit-info"],
        )?;
        capture(
            &staging.join("activity-processes.txt"),
            "/system/bin/dumpsys",
            &["activity", "processes"],
        )?;
        capture(
            &staging.join("process-identities.txt"),
            "/system/bin/ps",
            &["-A", "-o", "USER,UID,PID,PPID,NAME"],
        )?;
        capture(&staging.join("dmesg.txt"), "/system/bin/dmesg", &[])?;
        capture(
            &staging.join("boot-reason.txt"),
            "/system/bin/sh",
            &[
                "-c",
                "for key in ro.boot.bootreason sys.boot.reason persist.sys.boot.reason ro.bootmode ro.boot.slot_suffix; do printf '%s=' \"$key\"; getprop \"$key\"; done; printf 'kernel_tainted='; cat /proc/sys/kernel/tainted 2>&1; printf 'cmdline='; cat /proc/cmdline 2>&1",
            ],
        )?;
        capture(
            &staging.join("bootstat.txt"),
            "/system/bin/dumpsys",
            &["bootstat"],
        )?;
        capture(
            &staging.join("proc-last-kmsg.txt"),
            "/system/bin/cat",
            &["/proc/last_kmsg"],
        )?;
        capture(
            &staging.join("pstore-inventory.txt"),
            "/system/bin/sh",
            &[
                "-c",
                "ls -la /sys/fs/pstore 2>&1; ls -la /proc/last_kmsg 2>&1",
            ],
        )?;
        capture(
            &staging.join("aee-mrdump-inventory.txt"),
            "/system/bin/sh",
            &[
                "-c",
                "for root in /data/aee_exp /data/vendor/aee_exp /data/mrdump /data/vendor/mrdump /data/misc/mrdump; do echo ===$root===; ls -la \"$root\" 2>&1; done",
            ],
        )?;
        capture(
            &staging.join("debuglogger-inventory.txt"),
            "/system/bin/sh",
            &[
                "-c",
                "for root in /sdcard/debuglogger/mobilelog /storage/emulated/0/debuglogger/mobilelog; do echo ===$root===; find \"$root\" -maxdepth 2 -type f 2>&1 | grep -E '/(last_kmsg|mblog_history)$'; done",
            ],
        )?;
        if Path::new("/data/local/tmp/xpad-install").is_file() {
            match catalog
                .artifact("xpad-installer")
                .and_then(device::verify_locked_cli_path)
            {
                Ok(program) => {
                    capture(
                        &staging.join("xpad-install-self-test.txt"),
                        program,
                        &["self-test"],
                    )?;
                    capture(
                        &staging.join("xpad-install-0044-status.txt"),
                        program,
                        &["znxrun", "status"],
                    )?;
                }
                Err(error) => {
                    atomic_write(
                        &staging.join("xpad-install-integrity.txt"),
                        format!("refused to execute /data/local/tmp/xpad-install: {error}\n")
                            .as_bytes(),
                        0o600,
                    )?;
                }
            }
        }
        capture(
            &staging.join("boom-autostart-status.txt"),
            "/system/bin/content",
            &[
                "call",
                "--uri",
                "content://com.yoyicue.boominstaller.shizuku",
                "--method",
                "getAutoStartStatus",
            ],
        )?;
        capture(
            &staging.join("ksu-package.txt"),
            "/system/bin/dumpsys",
            &["package", "me.weishu.kernelsu"],
        )?;
        capture(
            &staging.join("unrelated-package.txt"),
            "/system/bin/dumpsys",
            &["package", "com.sukisu.ultra"],
        )?;
        capture(
            &staging.join("boom-package.txt"),
            "/system/bin/dumpsys",
            &["package", "com.yoyicue.boominstaller"],
        )?;
        capture(
            &staging.join("ota-package.txt"),
            "/system/bin/dumpsys",
            &["package", "com.tal.pad.ota"],
        )?;
        capture(
            &staging.join("ota-init-package.txt"),
            "/system/bin/dumpsys",
            &["package", "com.tal.init.ota"],
        )?;

        let debuglogger_evidence = collect_debuglogger_evidence(&[
            PathBuf::from("/sdcard/debuglogger/mobilelog"),
            PathBuf::from("/storage/emulated/0/debuglogger/mobilelog"),
        ]);
        let debuglogger_manifest = if debuglogger_evidence.is_empty() {
            "No readable APLog last_kmsg or mblog_history evidence was found.\n".to_string()
        } else {
            let mut manifest = String::from("source\tbytes\tarchive_path\tmaximum_bytes\n");
            for evidence in &debuglogger_evidence {
                manifest.push_str(&format!(
                    "{}\t{}\t{}\t{}\n",
                    evidence.source.display(),
                    evidence.size,
                    evidence.archive_path,
                    evidence.maximum_bytes
                ));
            }
            manifest
        };
        atomic_write(
            &staging.join("debuglogger-evidence.txt"),
            debuglogger_manifest.as_bytes(),
            0o600,
        )?;

        let output = destination.join(format!("xpad3log-{}.zip", timestamp_filename()));
        let file = File::create(&output).at(&output)?;
        let mut zip = ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        add_tree(&mut zip, &staging, "diagnostics", options)?;
        if paths.logs.exists() {
            add_tree(&mut zip, &paths.logs, "transactions", options)?;
        }
        let installer_incidents = Path::new("/data/local/tmp/.xpad-installer/logs");
        if installer_incidents.exists() {
            add_tree(
                &mut zip,
                installer_incidents,
                "xpad-installer-incidents",
                options,
            )?;
        }
        let boom_installs = Path::new("/data/local/tmp/.boominstaller/logs");
        if boom_installs.exists() {
            add_redacted_text_tree(&mut zip, boom_installs, "boominstaller-installs", options)?;
        }
        if Path::new("/sys/fs/pstore").is_dir() {
            let _ = add_tree(&mut zip, Path::new("/sys/fs/pstore"), "pstore", options);
        }
        for evidence in &debuglogger_evidence {
            let _ = add_limited_redacted_file(&mut zip, evidence, options);
        }
        zip.finish()?;
        Ok(output)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

fn capture(path: &Path, program: &str, args: &[&str]) -> Result<()> {
    let text = match run(program, args) {
        Ok(output) => {
            let mut combined = String::new();
            combined.push_str(&String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                combined.push_str("\n[stderr]\n");
                combined.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            combined
        }
        Err(error) => format!("capture unavailable: {error}\n"),
    };
    let redacted = text.lines().map(redact).collect::<Vec<_>>().join("\n");
    atomic_write(path, redacted.as_bytes(), 0o600)
}

#[derive(Debug)]
struct DebugloggerEvidence {
    source: PathBuf,
    archive_path: String,
    size: u64,
    maximum_bytes: u64,
}

fn collect_debuglogger_evidence(roots: &[PathBuf]) -> Vec<DebugloggerEvidence> {
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        let mut boot_dirs = entries
            .flatten()
            .filter(|entry| {
                entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                    && entry.file_name().to_string_lossy().starts_with("APLog_")
            })
            .collect::<Vec<_>>();
        boot_dirs.sort_by_key(|entry| std::cmp::Reverse(entry.file_name()));
        let mut evidence = Vec::new();
        for boot_dir in boot_dirs.into_iter().take(DEBUGLOGGER_MAX_BOOT_DIRS) {
            let boot_name = sanitize_zip_component(&boot_dir.file_name().to_string_lossy());
            for (filename, maximum_bytes) in [
                ("last_kmsg", LAST_KMSG_MAX_BYTES),
                ("mblog_history", MBLOG_HISTORY_MAX_BYTES),
            ] {
                let source = boot_dir.path().join(filename);
                let Ok(metadata) = fs::symlink_metadata(&source) else {
                    continue;
                };
                if !metadata.is_file() {
                    continue;
                }
                let suffix = if metadata.len() > maximum_bytes {
                    ".tail"
                } else {
                    ""
                };
                evidence.push(DebugloggerEvidence {
                    archive_path: format!("debuglogger/{boot_name}/{filename}{suffix}"),
                    source,
                    size: metadata.len(),
                    maximum_bytes,
                });
            }
        }
        if !evidence.is_empty() {
            return evidence;
        }
    }
    Vec::new()
}

fn sanitize_zip_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn add_limited_redacted_file(
    zip: &mut ZipWriter<File>,
    evidence: &DebugloggerEvidence,
    options: SimpleFileOptions,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&evidence.source)
        .at(&evidence.source)?;
    let metadata = file.metadata().at(&evidence.source)?;
    if !metadata.is_file() {
        return Err(msg(format!(
            "DebugLogger evidence changed type: {}",
            evidence.source.display()
        )));
    }
    let offset = metadata.len().saturating_sub(evidence.maximum_bytes);
    if offset > 0 {
        file.seek(SeekFrom::Start(offset)).at(&evidence.source)?;
    }
    let mut data = Vec::new();
    file.take(evidence.maximum_bytes)
        .read_to_end(&mut data)
        .at(&evidence.source)?;
    let text = String::from_utf8_lossy(&data);
    let mut redacted = String::new();
    if offset > 0 {
        redacted.push_str(&format!(
            "[xpad3: retained the final {} of {} bytes]\n",
            evidence.maximum_bytes,
            metadata.len()
        ));
    }
    redacted.push_str(&text.lines().map(redact).collect::<Vec<_>>().join("\n"));
    zip.start_file(&evidence.archive_path, options)?;
    zip.write_all(redacted.as_bytes())
        .map_err(|error| msg(format!("write DebugLogger evidence to ZIP: {error}")))
}

fn add_tree(
    zip: &mut ZipWriter<File>,
    root: &Path,
    prefix: &str,
    options: SimpleFileOptions,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(root)
        .at(root)?
        .collect::<std::io::Result<Vec<_>>>()
        .at(root)?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        let kind = entry.file_type().at(&path)?;
        if kind.is_dir() {
            add_tree(zip, &path, &name, options)?;
        } else if kind.is_file() {
            zip.start_file(name, options)?;
            let mut file = File::open(&path).at(&path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data).at(&path)?;
            zip.write_all(&data)
                .map_err(|e| msg(format!("write diagnostic ZIP: {e}")))?;
        }
    }
    Ok(())
}

fn add_redacted_text_tree(
    zip: &mut ZipWriter<File>,
    root: &Path,
    prefix: &str,
    options: SimpleFileOptions,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(root)
        .at(root)?
        .collect::<std::io::Result<Vec<_>>>()
        .at(root)?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let name = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        let kind = entry.file_type().at(&path)?;
        if kind.is_dir() {
            add_redacted_text_tree(zip, &path, &name, options)?;
        } else if kind.is_file() {
            let data = fs::read(&path).at(&path)?;
            let text = String::from_utf8_lossy(&data);
            let redacted = text.lines().map(redact).collect::<Vec<_>>().join("\n");
            zip.start_file(name, options)?;
            zip.write_all(redacted.as_bytes())
                .map_err(|error| msg(format!("write redacted diagnostic ZIP: {error}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_redaction_covers_serials_and_credentials() {
        for line in [
            "[ro.boot.serialno]: [ABC123456]",
            "Authorization: Bearer secret",
            "token=secret",
            "-----BEGIN PRIVATE KEY-----",
            "adb pairing_code=123456",
        ] {
            assert!(
                redact(line).starts_with("[REDACTED"),
                "not redacted: {line}"
            );
        }
    }

    #[test]
    fn streaming_command_persists_stdout_stderr_and_exit_code() {
        let root = std::env::temp_dir().join(format!("xpad3-stream-test-{}", unique_id()));
        let paths = Paths {
            root: root.clone(),
            cache: root.join("cache"),
            cache_is_explicit: false,
            managed_blob_root: root.join("cache").join("blobs"),
            managed_cache_root: root.join("cache").join("releases"),
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
        };
        let mut log = TransactionLog::start(&paths, "stream-test").expect("start transaction");
        let output = log
            .run_streaming(
                "fixture",
                "/bin/sh",
                &[
                    "-c",
                    "printf 'phase-one\\n'; printf 'phase-two\\n' >&2; exit 75",
                ],
            )
            .expect("stream command");
        assert_eq!(output.status.code(), Some(75));
        assert!(output.text.contains("phase-one"));
        assert!(output.text.contains("phase-two"));
        let raw = fs::read_to_string(log.dir.join("raw.log")).expect("read durable raw log");
        assert!(raw.contains("phase-one"));
        assert!(raw.contains("phase-two"));
        drop(log);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ksu_stage_trace_is_valid_and_durable_jsonl() {
        let root = std::env::temp_dir().join(format!("xpad3-ksu-trace-test-{}", unique_id()));
        let paths = Paths {
            root: root.clone(),
            cache: root.join("cache"),
            cache_is_explicit: false,
            managed_blob_root: root.join("cache").join("blobs"),
            managed_cache_root: root.join("cache").join("releases"),
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
        };
        let mut log = TransactionLog::start(&paths, "ksu trace test").expect("start transaction");
        let trace = log
            .prepare_ksu_trace("ksu", "android12-5.10")
            .expect("prepare KSU trace");
        log.ksu_stage(&trace, "runtime-verified", json!({"version": "32551"}))
            .expect("append KSU stage");
        let lines = fs::read_to_string(trace).expect("read KSU trace");
        let records = lines
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("valid JSONL record"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["stage"], "trace-armed");
        assert_eq!(records[1]["stage"], "runtime-verified");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn debuglogger_collection_keeps_only_three_newest_boots() {
        let root = std::env::temp_dir().join(format!("xpad3-debuglogger-test-{}", unique_id()));
        for number in 1..=4 {
            let dir = root.join(format!("APLog_20260719_00000{number}"));
            fs::create_dir_all(&dir).expect("create APLog directory");
            fs::write(dir.join("last_kmsg"), format!("boot {number}\n")).expect("write last_kmsg");
            fs::write(dir.join("mblog_history"), format!("history {number}\n"))
                .expect("write mblog_history");
        }
        let evidence = collect_debuglogger_evidence(std::slice::from_ref(&root));
        assert_eq!(evidence.len(), 6);
        assert!(
            evidence
                .iter()
                .all(|item| !item.archive_path.contains("000001"))
        );
        assert!(
            evidence
                .iter()
                .any(|item| item.archive_path.contains("000004/last_kmsg"))
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_transaction_is_recovered_with_a_receipt() {
        let root = std::env::temp_dir().join(format!("xpad3-log-test-{}", unique_id()));
        let paths = Paths {
            root: root.clone(),
            cache: root.join("cache"),
            cache_is_explicit: false,
            managed_blob_root: root.join("cache").join("blobs"),
            managed_cache_root: root.join("cache").join("releases"),
            work: root.join("work"),
            state: root.join("state"),
            logs: root.join("logs"),
            lock: root.join("operation.lock"),
        };
        let interrupted =
            TransactionLog::start(&paths, "install full").expect("start interrupted transaction");
        let interrupted_id = interrupted.id.clone();
        drop(interrupted);
        assert!(!transaction_warnings(&paths).is_empty());

        let mut next =
            TransactionLog::start(&paths, "cleanup").expect("start recovery transaction");
        assert!(
            paths
                .logs
                .join(interrupted_id)
                .join("receipt.json")
                .is_file()
        );
        let receipt = Receipt {
            transaction_id: next.id.clone(),
            operation: "cleanup".to_string(),
            success: true,
            started_boot_id: boot_id(),
            ended_boot_id: boot_id(),
            started_selinux: selinux(),
            ended_selinux: selinux(),
            components: vec![],
            error: None,
            needs_reboot: false,
        };
        next.write_receipt(&paths, &receipt)
            .expect("finish recovery transaction");
        assert!(!paths.state.join("active-transaction.json").exists());
        let _ = fs::remove_dir_all(root);
    }
}
