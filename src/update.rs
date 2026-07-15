use crate::catalog::{self, Catalog};
use crate::device;
use crate::error::{IoContext, Result, msg};
use crate::logging::TransactionLog;
use crate::model::AssetsLock;
#[cfg(test)]
use crate::model::DeviceProfile;
use crate::util::{
    Paths, atomic_write, copy_atomic, getprop, kernel_release, safe_filename, sha256_bytes,
    sha256_file, unique_id, validate_elf_arm64,
};
use semver::Version;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zip::ZipArchive;

const UPDATE_SCHEMA: u32 = 1;
const UPDATE_KIND: &str = "xpad2-update";
const UPDATE_CHANNEL: &str = "stable";
const UPDATE_REPOSITORY: &str = "https://github.com/yoyicue/xpad2-cli";
const GITHUB_API_REPOSITORY: &str = "https://api.github.com/repos/yoyicue/xpad2-cli";
const MANIFEST_FILENAME: &str = "xpad2-update.json";
const SIGNATURE_FILENAME: &str = "xpad2-update.json.sig";
const MAX_MANIFEST_SIZE: usize = 256 * 1024;
const MAX_SIGNATURE_SIZE: usize = 64 * 1024;
const MAX_RELEASE_METADATA_SIZE: usize = 2 * 1024 * 1024;
const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;
const MAX_CACHE_ARCHIVE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_SIZE: u64 = 768 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 4096;
const DOWNLOAD_ATTEMPTS: u32 = 3;

#[derive(Clone, Debug)]
pub struct UpdateRequest {
    pub check: bool,
    pub json: bool,
    pub version: Option<String>,
    pub offline: Option<PathBuf>,
    pub manifest_url: Option<String>,
    pub reinstall: bool,
    pub allow_downgrade: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateManifest {
    schema: u32,
    kind: String,
    channel: String,
    repository: String,
    version: String,
    catalog_version: String,
    profile: UpdateProfile,
    binary: UpdateAsset,
    cache: UpdateAsset,
    catalog: CatalogIdentity,
    release_url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProfile {
    build_fingerprint: String,
    kernel_release_prefix: String,
    abi: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAsset {
    filename: String,
    url: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogIdentity {
    filename: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    url: String,
    size: u64,
    state: String,
    digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VersionState {
    Available,
    Current,
    Ahead,
}

impl VersionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Current => "current",
            Self::Ahead => "ahead",
        }
    }
}

struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn create(paths: &Paths) -> Result<Self> {
        paths.ensure()?;
        let path = paths.work.join(format!("self-update-{}", unique_id()));
        fs::create_dir(&path).at(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).at(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct VerifiedManifest {
    manifest: UpdateManifest,
    raw: Vec<u8>,
    signature: Vec<u8>,
    offline_root: Option<PathBuf>,
    github_release: Option<GitHubRelease>,
    source: String,
}

struct CacheSwap {
    target: PathBuf,
    previous: Option<PathBuf>,
}

impl CacheSwap {
    fn rollback(&self) -> Result<()> {
        if self.target.exists() {
            fs::remove_dir_all(&self.target).at(&self.target)?;
        }
        if let Some(previous) = &self.previous
            && previous.exists()
        {
            fs::rename(previous, &self.target).at(&self.target)?;
        }
        sync_parent(&self.target)
    }

    fn commit(&self) -> Result<()> {
        if let Some(previous) = &self.previous
            && previous.exists()
        {
            fs::remove_dir_all(previous).at(previous)?;
        }
        Ok(())
    }
}

struct BinarySwap {
    target: PathBuf,
    backup: PathBuf,
}

impl BinarySwap {
    fn rollback(&self) -> Result<()> {
        copy_atomic(&self.backup, &self.target, 0o700)?;
        sync_parent(&self.target)
    }
}

pub fn parse_args(args: &[String]) -> Result<UpdateRequest> {
    let mut request = UpdateRequest {
        check: false,
        json: false,
        version: None,
        offline: None,
        manifest_url: None,
        reinstall: false,
        allow_downgrade: false,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--check" => request.check = true,
            "--json" => request.json = true,
            "--reinstall" => request.reinstall = true,
            "--allow-downgrade" => request.allow_downgrade = true,
            "--version" => {
                index += 1;
                request.version = Some(
                    args.get(index)
                        .ok_or_else(|| msg("--version requires a semantic version"))?
                        .clone(),
                );
            }
            "--offline" => {
                index += 1;
                request.offline =
                    Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        msg("--offline requires a directory or update ZIP")
                    })?));
            }
            "--manifest-url" => {
                index += 1;
                request.manifest_url = Some(
                    args.get(index)
                        .ok_or_else(|| msg("--manifest-url requires an HTTPS URL"))?
                        .clone(),
                );
            }
            other if other.starts_with("--version=") => {
                request.version = Some(other["--version=".len()..].to_string());
            }
            other if other.starts_with("--offline=") => {
                request.offline = Some(PathBuf::from(&other["--offline=".len()..]));
            }
            other if other.starts_with("--manifest-url=") => {
                request.manifest_url = Some(other["--manifest-url=".len()..].to_string());
            }
            _ => return Err(msg(update_usage())),
        }
        index += 1;
    }

    if let Some(version) = &request.version {
        parse_canonical_version(version)?;
    }
    if request.offline.is_some() && request.manifest_url.is_some() {
        return Err(msg("--offline and --manifest-url are mutually exclusive"));
    }
    if request.json && !request.check {
        return Err(msg("--json is only valid with --check"));
    }
    if request.check && (request.reinstall || request.allow_downgrade) {
        return Err(msg(
            "--check cannot be combined with --reinstall or --allow-downgrade",
        ));
    }
    if request.allow_downgrade && request.version.is_none() && request.offline.is_none() {
        return Err(msg(
            "--allow-downgrade requires an explicit --version or --offline bundle",
        ));
    }
    Ok(request)
}

pub fn check(catalog: &Catalog, paths: &Paths, request: &UpdateRequest) -> Result<()> {
    device::profile_check(catalog)?;
    let workspace = Workspace::create(paths)?;
    let verified = acquire_manifest(request, &workspace)?;
    validate_target_profile(&verified.manifest, catalog)?;
    let current = parse_canonical_version(env!("CARGO_PKG_VERSION"))?;
    let target = parse_canonical_version(&verified.manifest.version)?;
    let state = version_state(&current, &target);

    if request.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "current_version": current.to_string(),
                "target_version": target.to_string(),
                "catalog_version": verified.manifest.catalog_version,
                "state": state.as_str(),
                "source": verified.source,
                "release_url": verified.manifest.release_url,
            }))?
        );
    } else {
        match state {
            VersionState::Available => println!(
                "可更新：xpad2 {} -> {}（catalog {}）\n{}",
                current, target, verified.manifest.catalog_version, verified.manifest.release_url
            ),
            VersionState::Current => println!(
                "已是当前稳定版：xpad2 {}（catalog {}）",
                current, verified.manifest.catalog_version
            ),
            VersionState::Ahead => {
                println!("当前版本 {} 高于所选发布 {}；不会自动降级", current, target)
            }
        }
    }
    Ok(())
}

pub fn apply(
    catalog: &Catalog,
    paths: &Paths,
    request: &UpdateRequest,
    log: &mut TransactionLog,
) -> Result<bool> {
    if paths.cache_is_explicit {
        return Err(msg(
            "self-update refuses --cache-dir/XPAD2_CACHE_DIR; use the managed versioned cache",
        ));
    }
    device::profile_check(catalog)?;
    let workspace = Workspace::create(paths)?;
    let verified = acquire_manifest(request, &workspace)?;
    validate_target_profile(&verified.manifest, catalog)?;
    let current = parse_canonical_version(env!("CARGO_PKG_VERSION"))?;
    let target = parse_canonical_version(&verified.manifest.version)?;
    let state = version_state(&current, &target);

    match state {
        VersionState::Current if !request.reinstall => {
            println!("xpad2 {current} 已是所选版本，无需更新");
            return Ok(false);
        }
        VersionState::Ahead if !request.allow_downgrade => {
            return Err(msg(format!(
                "refusing downgrade {} -> {}; repeat with an explicit version/bundle and --allow-downgrade",
                current, target
            )));
        }
        _ => {}
    }

    log.event(
        "self-update",
        "manifest-verified",
        json!({
            "source": verified.source,
            "current_version": current.to_string(),
            "target_version": target.to_string(),
            "catalog_version": verified.manifest.catalog_version,
            "reinstall": request.reinstall,
            "downgrade": state == VersionState::Ahead,
        }),
    )?;
    println!(
        "准备更新 xpad2 {} -> {}；下载、双重签名校验和候选自检通常需要 1–3 分钟…",
        current, target
    );

    let manifest_path = workspace.path.join(MANIFEST_FILENAME);
    let signature_path = workspace.path.join(SIGNATURE_FILENAME);
    atomic_write(&manifest_path, &verified.raw, 0o600)?;
    atomic_write(&signature_path, &verified.signature, 0o600)?;

    let candidate = acquire_asset(
        &verified.manifest.binary,
        verified.offline_root.as_deref(),
        verified.github_release.as_ref(),
        &workspace.path,
        0o700,
        "xpad2 ELF",
    )?;
    validate_elf_arm64(&candidate)?;
    let cache_archive = acquire_asset(
        &verified.manifest.cache,
        verified.offline_root.as_deref(),
        verified.github_release.as_ref(),
        &workspace.path,
        0o600,
        "离线 cache",
    )?;
    let unpacked = workspace.path.join("cache-unpacked");
    extract_zip_safely(&cache_archive, &unpacked, MAX_EXTRACTED_SIZE)?;
    let cache_source = locate_named_root(&unpacked, "xpad2-cache")?;
    let target_lock = verify_cache_against_manifest(&cache_source, &verified.manifest)?;
    verify_candidate(
        &candidate,
        &manifest_path,
        &signature_path,
        &cache_source,
        log,
    )?;

    let target_cache = paths.managed_cache_path(
        &verified.manifest.version,
        &verified.manifest.catalog_version,
    )?;
    let cache_swap = install_version_cache(&cache_source, &target_lock, &target_cache)?;
    let binary_swap = match install_candidate_binary(&candidate, &current, paths) {
        Ok(swap) => swap,
        Err(error) => {
            let _ = cache_swap.rollback();
            return Err(error);
        }
    };

    let postcheck = verify_candidate(
        &binary_swap.target,
        &manifest_path,
        &signature_path,
        &target_cache,
        log,
    );
    if let Err(error) = postcheck {
        let binary_rollback = binary_swap.rollback();
        let cache_rollback = cache_swap.rollback();
        log.event(
            "self-update",
            "rolled-back",
            json!({
                "target_version": target.to_string(),
                "candidate_error": error.to_string(),
                "binary_rollback": binary_rollback.as_ref().err().map(ToString::to_string),
                "cache_rollback": cache_rollback.as_ref().err().map(ToString::to_string),
            }),
        )?;
        binary_rollback?;
        cache_rollback?;
        return Err(msg(format!(
            "installed candidate failed self-check and was rolled back: {error}"
        )));
    }

    cache_swap.commit()?;
    prune_binary_backups(paths, 3)?;
    let record = json!({
        "from_version": current.to_string(),
        "to_version": target.to_string(),
        "catalog_version": verified.manifest.catalog_version,
        "binary_sha256": verified.manifest.binary.sha256,
        "cache_sha256": verified.manifest.cache.sha256,
        "manifest_sha256": sha256_bytes(&verified.raw),
        "source": verified.source,
        "rollback_binary": binary_swap.backup,
    });
    atomic_write(
        &paths.state.join("last-self-update.json"),
        &serde_json::to_vec_pretty(&record)?,
        0o600,
    )?;
    log.event("self-update", "installed", record)?;
    println!(
        "更新完成：xpad2 {}（catalog {}）；旧 ELF 已保留用于失败恢复",
        target, verified.manifest.catalog_version
    );
    Ok(true)
}

pub fn verify_candidate_command(catalog: &Catalog, args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err(msg("internal candidate verification usage error"));
    }
    let manifest_path = Path::new(&args[0]);
    let signature_path = Path::new(&args[1]);
    let cache = Path::new(&args[2]);
    let raw = read_limited(manifest_path, MAX_MANIFEST_SIZE)?;
    let signature = read_limited(signature_path, MAX_SIGNATURE_SIZE)?;
    catalog::verify_catalog_signature(&raw, &signature)?;
    let manifest: UpdateManifest = serde_json::from_slice(&raw)?;
    validate_manifest(&manifest)?;
    if manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.catalog_version != catalog.lock.catalog_version
        || manifest.profile.build_fingerprint != catalog.lock.profile.build_fingerprint
        || manifest.profile.kernel_release_prefix != catalog.lock.profile.kernel_release_prefix
        || manifest.profile.abi != catalog.lock.profile.abi
    {
        return Err(msg(
            "candidate embedded release identity does not match update manifest",
        ));
    }
    device::profile_check(catalog)?;
    let current_exe = std::env::current_exe()
        .map_err(|error| msg(format!("cannot resolve candidate executable: {error}")))?;
    verify_file_identity(&current_exe, &manifest.binary, "candidate ELF")?;
    validate_elf_arm64(&current_exe)?;
    verify_cache_against_manifest(cache, &manifest)?;
    let verified = catalog::verify_complete_external_cache(cache, catalog)?;
    println!(
        "XPAD2_UPDATE_CANDIDATE_OK version={} catalog={} blobs={}",
        manifest.version,
        manifest.catalog_version,
        verified.len()
    );
    Ok(())
}

pub fn update_usage() -> &'static str {
    "usage: xpad2 update [--check] [--json] [--version VERSION] [--offline DIRECTORY_OR_ZIP] [--reinstall] [--allow-downgrade] [--manifest-url HTTPS_URL]"
}

fn acquire_manifest(request: &UpdateRequest, workspace: &Workspace) -> Result<VerifiedManifest> {
    let (raw, signature, offline_root, github_release, source) =
        if let Some(path) = &request.offline {
            let root = prepare_offline_root(path, &workspace.path)?;
            let manifest_path = root.join(MANIFEST_FILENAME);
            let signature_path = root.join(SIGNATURE_FILENAME);
            (
                read_regular_limited(&manifest_path, MAX_MANIFEST_SIZE)?,
                read_regular_limited(&signature_path, MAX_SIGNATURE_SIZE)?,
                Some(root.clone()),
                None,
                format!("offline:{}", path.display()),
            )
        } else if let Some(url) = configured_manifest_url(request) {
            validate_https_url(&url, "manifest URL")?;
            let signature_url = format!("{url}.sig");
            let agent = http_agent();
            println!("检查签名更新清单…");
            (
                fetch_small(&agent, &url, MAX_MANIFEST_SIZE, "update manifest")?,
                fetch_small(
                    &agent,
                    &signature_url,
                    MAX_SIGNATURE_SIZE,
                    "update manifest signature",
                )?,
                None,
                None,
                url,
            )
        } else {
            let agent = http_agent();
            let api_url = github_release_api_url(request);
            println!("通过 GitHub Releases API 检查签名更新清单…");
            let metadata = fetch_small_with_accept(
                &agent,
                &api_url,
                MAX_RELEASE_METADATA_SIZE,
                "GitHub release metadata",
                "application/vnd.github+json",
            )?;
            let release: GitHubRelease = serde_json::from_slice(&metadata)?;
            validate_github_release(&release, request.version.as_deref())?;
            let manifest_asset = github_asset(&release, MANIFEST_FILENAME)?;
            let signature_asset = github_asset(&release, SIGNATURE_FILENAME)?;
            if manifest_asset.size == 0 || manifest_asset.size > MAX_MANIFEST_SIZE as u64 {
                return Err(msg("GitHub update manifest asset has an invalid size"));
            }
            if signature_asset.size == 0 || signature_asset.size > MAX_SIGNATURE_SIZE as u64 {
                return Err(msg("GitHub update signature asset has an invalid size"));
            }
            (
                fetch_small_with_accept(
                    &agent,
                    &manifest_asset.url,
                    MAX_MANIFEST_SIZE,
                    "update manifest",
                    "application/octet-stream",
                )?,
                fetch_small_with_accept(
                    &agent,
                    &signature_asset.url,
                    MAX_SIGNATURE_SIZE,
                    "update manifest signature",
                    "application/octet-stream",
                )?,
                None,
                Some(release),
                api_url,
            )
        };
    catalog::verify_catalog_signature(&raw, &signature)?;
    let manifest: UpdateManifest = serde_json::from_slice(&raw)?;
    validate_manifest(&manifest)?;
    if let Some(requested) = &request.version
        && manifest.version != *requested
    {
        return Err(msg(format!(
            "selected manifest version {} != requested {}",
            manifest.version, requested
        )));
    }
    if let Some(release) = &github_release {
        validate_github_release_manifest(release, &manifest)?;
    }
    Ok(VerifiedManifest {
        manifest,
        raw,
        signature,
        offline_root,
        github_release,
        source,
    })
}

fn configured_manifest_url(request: &UpdateRequest) -> Option<String> {
    if let Some(url) = &request.manifest_url {
        return Some(url.clone());
    }
    if request.version.is_none()
        && let Some(url) = std::env::var_os("XPAD2_UPDATE_MANIFEST_URL")
    {
        return Some(url.to_string_lossy().into_owned());
    }
    None
}

fn github_release_api_url(request: &UpdateRequest) -> String {
    if let Some(version) = &request.version {
        return format!("{GITHUB_API_REPOSITORY}/releases/tags/v{version}");
    }
    format!("{GITHUB_API_REPOSITORY}/releases/latest")
}

fn validate_github_release(release: &GitHubRelease, requested: Option<&str>) -> Result<()> {
    if release.draft || release.prerelease {
        return Err(msg("GitHub update release is draft or prerelease"));
    }
    let version = release
        .tag_name
        .strip_prefix('v')
        .ok_or_else(|| msg("GitHub update release tag is not v-prefixed semver"))?;
    let parsed = parse_canonical_version(version)?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return Err(msg(
            "GitHub stable release tag is not a stable semantic version",
        ));
    }
    if let Some(requested) = requested
        && version != requested
    {
        return Err(msg(format!(
            "GitHub release tag {} != requested v{}",
            release.tag_name, requested
        )));
    }
    let expected_page = format!("{UPDATE_REPOSITORY}/releases/tag/{}", release.tag_name);
    if release.html_url != expected_page {
        return Err(msg(
            "GitHub release page does not belong to the canonical repository",
        ));
    }
    Ok(())
}

fn github_asset<'a>(release: &'a GitHubRelease, name: &str) -> Result<&'a GitHubAsset> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| msg(format!("GitHub release asset missing: {name}")))?;
    if matches.next().is_some() {
        return Err(msg(format!(
            "GitHub release contains duplicate asset: {name}"
        )));
    }
    if asset.state != "uploaded" {
        return Err(msg(format!("GitHub release asset is not uploaded: {name}")));
    }
    validate_https_url(&asset.url, "GitHub asset API URL")?;
    let parsed = url::Url::parse(&asset.url)
        .map_err(|error| msg(format!("invalid GitHub asset API URL: {error}")))?;
    let expected_prefix = format!("{GITHUB_API_REPOSITORY}/releases/assets/");
    if parsed.host_str() != Some("api.github.com") || !asset.url.starts_with(&expected_prefix) {
        return Err(msg(format!("untrusted GitHub asset API URL for {name}")));
    }
    Ok(asset)
}

fn validate_github_release_manifest(
    release: &GitHubRelease,
    manifest: &UpdateManifest,
) -> Result<()> {
    if release.tag_name != format!("v{}", manifest.version)
        || release.html_url != manifest.release_url
    {
        return Err(msg(
            "GitHub release identity does not match signed update manifest",
        ));
    }
    for (locked, label) in [(&manifest.binary, "binary"), (&manifest.cache, "cache")] {
        let asset = github_asset(release, &locked.filename)?;
        if asset.size != locked.size {
            return Err(msg(format!(
                "GitHub {label} asset size does not match signed manifest"
            )));
        }
        if let Some(digest) = &asset.digest
            && digest != &format!("sha256:{}", locked.sha256)
        {
            return Err(msg(format!(
                "GitHub {label} asset digest does not match signed manifest"
            )));
        }
    }
    Ok(())
}

fn prepare_offline_root(source: &Path, workspace: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(source).at(source)?;
    let root = if metadata.file_type().is_symlink() {
        return Err(msg(format!(
            "offline update source must not be a symlink: {}",
            source.display()
        )));
    } else if metadata.is_dir() {
        source.to_path_buf()
    } else if metadata.is_file() {
        let extracted = workspace.join("offline-bundle");
        extract_zip_safely(source, &extracted, MAX_EXTRACTED_SIZE)?;
        locate_named_root(&extracted, "xpad2-update")?
    } else {
        return Err(msg(format!(
            "offline update source is neither a directory nor a ZIP: {}",
            source.display()
        )));
    };
    if root.join(MANIFEST_FILENAME).is_file() && root.join(SIGNATURE_FILENAME).is_file() {
        return Ok(root);
    }
    let nested = root.join("xpad2-update");
    if nested.join(MANIFEST_FILENAME).is_file() && nested.join(SIGNATURE_FILENAME).is_file() {
        return Ok(nested);
    }
    Err(msg(format!(
        "offline bundle is missing {MANIFEST_FILENAME} and {SIGNATURE_FILENAME}"
    )))
}

fn validate_manifest(manifest: &UpdateManifest) -> Result<()> {
    if manifest.schema != UPDATE_SCHEMA
        || manifest.kind != UPDATE_KIND
        || manifest.channel != UPDATE_CHANNEL
        || manifest.repository != UPDATE_REPOSITORY
    {
        return Err(msg(
            "unsupported or untrusted xpad2 update manifest identity",
        ));
    }
    let version = parse_canonical_version(&manifest.version)?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err(msg(
            "stable update manifest must use a release semantic version",
        ));
    }
    let expected_binary = format!("xpad2-v{}-android-arm64", manifest.version);
    let expected_cache = format!("xpad2-cache-v{}.zip", manifest.version);
    if manifest.binary.filename != expected_binary || manifest.cache.filename != expected_cache {
        return Err(msg("update asset filenames do not match manifest version"));
    }
    safe_filename(&manifest.binary.filename)?;
    safe_filename(&manifest.cache.filename)?;
    if manifest.catalog.filename != "catalog.json" {
        return Err(msg("update catalog filename must be catalog.json"));
    }
    validate_asset(&manifest.binary, MAX_BINARY_SIZE, "binary")?;
    validate_asset(&manifest.cache, MAX_CACHE_ARCHIVE_SIZE, "cache")?;
    if manifest.catalog.size == 0 || manifest.catalog.size > MAX_MANIFEST_SIZE as u64 {
        return Err(msg("update catalog size is outside the safe range"));
    }
    validate_sha256(&manifest.catalog.sha256, "catalog SHA-256")?;
    validate_https_url(&manifest.release_url, "release URL")?;
    if manifest.profile.build_fingerprint.is_empty()
        || manifest.profile.kernel_release_prefix.is_empty()
        || manifest.profile.abi != "arm64-v8a"
    {
        return Err(msg("invalid target device profile in update manifest"));
    }
    Ok(())
}

fn validate_asset(asset: &UpdateAsset, max_size: u64, name: &str) -> Result<()> {
    if asset.size == 0 || asset.size > max_size {
        return Err(msg(format!("{name} asset size is outside the safe range")));
    }
    validate_sha256(&asset.sha256, &format!("{name} SHA-256"))?;
    validate_https_url(&asset.url, &format!("{name} URL"))?;
    if !asset.url.ends_with(&format!("/{}", asset.filename)) {
        return Err(msg(format!(
            "{name} URL does not end with its locked filename"
        )));
    }
    Ok(())
}

fn validate_target_profile(manifest: &UpdateManifest, catalog: &Catalog) -> Result<()> {
    let profile = &catalog.lock.profile;
    if manifest.profile.build_fingerprint != profile.build_fingerprint
        || manifest.profile.kernel_release_prefix != profile.kernel_release_prefix
        || manifest.profile.abi != profile.abi
    {
        return Err(msg("update release targets a different device profile"));
    }
    let fingerprint = getprop("ro.build.fingerprint");
    let abi = getprop("ro.product.cpu.abi");
    let kernel = kernel_release();
    if fingerprint != manifest.profile.build_fingerprint
        || abi != manifest.profile.abi
        || !kernel.starts_with(&manifest.profile.kernel_release_prefix)
    {
        return Err(msg(
            "current device does not match the signed update profile",
        ));
    }
    Ok(())
}

fn parse_canonical_version(raw: &str) -> Result<Version> {
    let version = Version::parse(raw)
        .map_err(|error| msg(format!("invalid semantic version {raw:?}: {error}")))?;
    if version.to_string() != raw {
        return Err(msg(format!("non-canonical semantic version: {raw:?}")));
    }
    Ok(version)
}

fn version_state(current: &Version, target: &Version) -> VersionState {
    use std::cmp::Ordering;
    match current.cmp(target) {
        Ordering::Less => VersionState::Available,
        Ordering::Equal => VersionState::Current,
        Ordering::Greater => VersionState::Ahead,
    }
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(msg(format!("invalid lowercase {name}: {value:?}")));
    }
    Ok(())
}

fn validate_https_url(value: &str, name: &str) -> Result<()> {
    let parsed = url::Url::parse(value)
        .map_err(|error| msg(format!("invalid {name} {value:?}: {error}")))?;
    if value.len() > 4096
        || parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(msg(format!("invalid {name}: {value:?}")));
    }
    Ok(())
}

fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(&format!("xpad2/{}", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(120))
        .timeout_write(Duration::from_secs(120))
        .redirects(8)
        .build()
}

fn request(agent: &ureq::Agent, url: &str, accept: Option<&str>) -> ureq::Request {
    let mut request = agent.get(url);
    if let Some(accept) = accept {
        request = request.set("Accept", accept);
    }
    if url.starts_with("https://api.github.com/") {
        request = request.set("X-GitHub-Api-Version", "2022-11-28");
    }
    request
}

fn fetch_small(agent: &ureq::Agent, url: &str, max: usize, label: &str) -> Result<Vec<u8>> {
    fetch_small_with_optional_accept(agent, url, max, label, None)
}

fn fetch_small_with_accept(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: &str,
) -> Result<Vec<u8>> {
    fetch_small_with_optional_accept(agent, url, max, label, Some(accept))
}

fn fetch_small_with_optional_accept(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>> {
    let mut last_error = None;
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        match fetch_small_once(agent, url, max, label, accept) {
            Ok(bytes) => return Ok(bytes),
            Err(error) => {
                if attempt < DOWNLOAD_ATTEMPTS {
                    eprintln!(
                        "{label} 网络请求失败（{attempt}/{DOWNLOAD_ATTEMPTS}）：{error}；即将重试…"
                    );
                    std::thread::sleep(Duration::from_secs(attempt as u64));
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| msg(format!("{label} download failed"))))
}

fn fetch_small_once(
    agent: &ureq::Agent,
    url: &str,
    max: usize,
    label: &str,
    accept: Option<&str>,
) -> Result<Vec<u8>> {
    let response = request(agent, url, accept)
        .call()
        .map_err(|error| msg(format!("HTTPS {label} download failed: {error}")))?;
    if let Some(length) = response.header("Content-Length")
        && length
            .parse::<u64>()
            .ok()
            .is_some_and(|length| length > max as u64)
    {
        return Err(msg(format!("{label} exceeds the safe size limit")));
    }
    let mut reader = response.into_reader().take(max as u64 + 1);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| msg(format!("HTTPS {label} read failed: {error}")))?;
    if bytes.len() > max {
        return Err(msg(format!("{label} exceeds the safe size limit")));
    }
    Ok(bytes)
}

fn acquire_asset(
    asset: &UpdateAsset,
    offline_root: Option<&Path>,
    github_release: Option<&GitHubRelease>,
    workspace: &Path,
    mode: u32,
    label: &str,
) -> Result<PathBuf> {
    let target = workspace.join(&asset.filename);
    if let Some(root) = offline_root {
        let source = root.join(&asset.filename);
        verify_regular_file(&source)?;
        verify_file_identity(&source, asset, label)?;
        copy_atomic(&source, &target, mode)?;
    } else {
        println!(
            "下载 {label}：{}（{:.1} MiB）…",
            asset.filename,
            asset.size as f64 / 1024.0 / 1024.0
        );
        let (url, accept) = if let Some(release) = github_release {
            let transport = github_asset(release, &asset.filename)?;
            (transport.url.as_str(), Some("application/octet-stream"))
        } else {
            (asset.url.as_str(), None)
        };
        download_file(url, &target, asset, mode, label, accept)?;
    }
    verify_file_identity(&target, asset, label)?;
    Ok(target)
}

fn download_file(
    url: &str,
    target: &Path,
    asset: &UpdateAsset,
    mode: u32,
    label: &str,
    accept: Option<&str>,
) -> Result<()> {
    let agent = http_agent();
    let mut last_error = None;
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        match download_file_once(&agent, url, target, asset, mode, label, accept) {
            Ok(()) => return Ok(()),
            Err(error) => {
                if attempt < DOWNLOAD_ATTEMPTS {
                    eprintln!(
                        "{label} 下载失败（{attempt}/{DOWNLOAD_ATTEMPTS}）：{error}；即将重试…"
                    );
                    std::thread::sleep(Duration::from_secs(attempt as u64));
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| msg(format!("{label} download failed"))))
}

fn download_file_once(
    agent: &ureq::Agent,
    url: &str,
    target: &Path,
    asset: &UpdateAsset,
    mode: u32,
    label: &str,
    accept: Option<&str>,
) -> Result<()> {
    let response = request(agent, url, accept)
        .call()
        .map_err(|error| msg(format!("HTTPS {label} download failed: {error}")))?;
    if let Some(length) = response.header("Content-Length")
        && length
            .parse::<u64>()
            .ok()
            .is_some_and(|length| length != asset.size)
    {
        return Err(msg(format!(
            "{label} HTTP Content-Length does not match signed manifest"
        )));
    }
    let parent = target
        .parent()
        .ok_or_else(|| msg("download target has no parent directory"))?;
    fs::create_dir_all(parent).at(parent)?;
    let partial = parent.join(format!(".{}.{}.partial", asset.filename, unique_id()));
    let result = (|| {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&partial)
            .at(&partial)?;
        let mut reader = response.into_reader();
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut last_progress = Instant::now();
        let mut buffer = [0u8; 128 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| msg(format!("HTTPS {label} read failed: {error}")))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| msg(format!("{label} size overflow")))?;
            if total > asset.size {
                return Err(msg(format!("{label} exceeds signed size")));
            }
            output.write_all(&buffer[..count]).at(&partial)?;
            hasher.update(&buffer[..count]);
            if last_progress.elapsed() >= Duration::from_secs(15) {
                eprintln!(
                    "{label} 下载进度：{:.1}/{:.1} MiB（{:.0}%）",
                    total as f64 / 1024.0 / 1024.0,
                    asset.size as f64 / 1024.0 / 1024.0,
                    total as f64 * 100.0 / asset.size as f64
                );
                last_progress = Instant::now();
            }
        }
        output.sync_all().at(&partial)?;
        let digest = format!("{:x}", hasher.finalize());
        if total != asset.size || digest != asset.sha256 {
            return Err(msg(format!(
                "{label} identity mismatch: size {total}/{} sha256 {digest}/{}",
                asset.size, asset.sha256
            )));
        }
        fs::set_permissions(&partial, fs::Permissions::from_mode(mode)).at(&partial)?;
        fs::rename(&partial, target).at(target)?;
        println!(
            "{label} 下载完成：{:.1} MiB",
            total as f64 / 1024.0 / 1024.0
        );
        sync_parent(target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn verify_file_identity(path: &Path, asset: &UpdateAsset, label: &str) -> Result<()> {
    let metadata = fs::metadata(path).at(path)?;
    if !metadata.is_file() || metadata.len() != asset.size {
        return Err(msg(format!(
            "{label} size mismatch: expected {}, got {}",
            asset.size,
            metadata.len()
        )));
    }
    let actual = sha256_file(path)?;
    if actual != asset.sha256 {
        return Err(msg(format!(
            "{label} SHA-256 mismatch: expected {}, got {actual}",
            asset.sha256
        )));
    }
    Ok(())
}

fn verify_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).at(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(msg(format!("not a regular file: {}", path.display())));
    }
    Ok(())
}

fn verify_cache_against_manifest(cache: &Path, manifest: &UpdateManifest) -> Result<AssetsLock> {
    let catalog_path = cache.join("catalog.json");
    verify_regular_file(&catalog_path)?;
    let raw = read_limited(&catalog_path, MAX_MANIFEST_SIZE)?;
    if raw.len() as u64 != manifest.catalog.size || sha256_bytes(&raw) != manifest.catalog.sha256 {
        return Err(msg("cache catalog identity does not match update manifest"));
    }
    let lock = catalog::load_signed_external_catalog(cache)?;
    if lock.schema != 1
        || lock.product_version != manifest.version
        || lock.catalog_version != manifest.catalog_version
        || lock.profile.build_fingerprint != manifest.profile.build_fingerprint
        || lock.profile.kernel_release_prefix != manifest.profile.kernel_release_prefix
        || lock.profile.abi != manifest.profile.abi
    {
        return Err(msg(
            "signed cache catalog does not match update release identity",
        ));
    }
    let mut ids = BTreeSet::new();
    for artifact in &lock.artifacts {
        if !ids.insert(artifact.id.as_str()) {
            return Err(msg(format!(
                "duplicate artifact in update catalog: {}",
                artifact.id
            )));
        }
        if artifact.embedded {
            let blob = cache.join("blobs").join(&artifact.sha256);
            verify_regular_file(&blob)?;
            catalog::verify_blob(&blob, artifact)?;
        }
    }
    if ids.is_empty() {
        return Err(msg("update catalog contains no artifacts"));
    }
    Ok(lock)
}

fn verify_candidate(
    binary: &Path,
    manifest: &Path,
    signature: &Path,
    cache: &Path,
    log: &mut TransactionLog,
) -> Result<()> {
    let output = Command::new(binary)
        .arg("_update-verify-candidate")
        .arg(manifest)
        .arg(signature)
        .arg(cache)
        .env_remove("XPAD2_CACHE_DIR")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| msg(format!("failed to execute candidate self-check: {error}")))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(stderr.trim());
    }
    log.command_result("candidate-self-check", output.status.success(), &text)?;
    if !output.status.success() || !text.contains("XPAD2_UPDATE_CANDIDATE_OK") {
        return Err(msg(format!("candidate self-check failed: {text}")));
    }
    Ok(())
}

fn install_version_cache(source: &Path, lock: &AssetsLock, target: &Path) -> Result<CacheSwap> {
    let parent = target
        .parent()
        .ok_or_else(|| msg("managed cache target has no parent"))?;
    fs::create_dir_all(parent).at(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).at(parent)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| msg("managed cache target has an invalid name"))?;
    let staging = parent.join(format!(".{name}.{}.partial", unique_id()));
    let previous = parent.join(format!(".{name}.{}.previous", unique_id()));
    fs::create_dir(&staging).at(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).at(&staging)?;
    fs::create_dir(staging.join("blobs")).at(staging.join("blobs"))?;
    fs::set_permissions(staging.join("blobs"), fs::Permissions::from_mode(0o700))
        .at(staging.join("blobs"))?;
    let result = (|| {
        copy_atomic(
            &source.join("catalog.json"),
            &staging.join("catalog.json"),
            0o600,
        )?;
        copy_atomic(
            &source.join("catalog.sig"),
            &staging.join("catalog.sig"),
            0o600,
        )?;
        for artifact in lock.artifacts.iter().filter(|artifact| artifact.embedded) {
            copy_atomic(
                &source.join("blobs").join(&artifact.sha256),
                &staging.join("blobs").join(&artifact.sha256),
                0o600,
            )?;
        }
        if target.exists() {
            fs::rename(target, &previous).at(target)?;
        }
        if let Err(error) = fs::rename(&staging, target).at(target) {
            if previous.exists() {
                let _ = fs::rename(&previous, target);
            }
            return Err(error);
        }
        sync_parent(target)?;
        Ok(CacheSwap {
            target: target.to_path_buf(),
            previous: previous.exists().then_some(previous.clone()),
        })
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn install_candidate_binary(
    candidate: &Path,
    current: &Version,
    paths: &Paths,
) -> Result<BinarySwap> {
    let target = std::env::current_exe()
        .map_err(|error| msg(format!("cannot resolve current xpad2 executable: {error}")))?;
    verify_regular_file(&target)?;
    let current_sha = sha256_file(&target)?;
    let backup_dir = paths.state.join("update-backups");
    fs::create_dir_all(&backup_dir).at(&backup_dir)?;
    fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).at(&backup_dir)?;
    let backup = backup_dir.join(format!("xpad2-v{}-{}", current, &current_sha[..12]));
    if !backup.exists() {
        copy_atomic(&target, &backup, 0o700)?;
    }
    if sha256_file(&backup)? != current_sha {
        return Err(msg("self-update rollback backup identity mismatch"));
    }
    copy_atomic(candidate, &target, 0o700)?;
    sync_parent(&target)?;
    if sha256_file(&target)? != sha256_file(candidate)? {
        let _ = copy_atomic(&backup, &target, 0o700);
        return Err(msg(
            "installed xpad2 ELF failed post-write SHA-256 verification",
        ));
    }
    Ok(BinarySwap { target, backup })
}

fn prune_binary_backups(paths: &Paths, keep: usize) -> Result<()> {
    let dir = paths.state.join("update-backups");
    if !dir.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(&dir)
        .at(&dir)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
                && entry.file_name().to_string_lossy().starts_with("xpad2-v")
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
    });
    let remove_count = entries.len().saturating_sub(keep);
    for entry in entries.into_iter().take(remove_count) {
        fs::remove_file(entry.path()).at(entry.path())?;
    }
    Ok(())
}

fn extract_zip_safely(source: &Path, destination: &Path, max_total: u64) -> Result<()> {
    verify_regular_file(source)?;
    if destination.exists() {
        fs::remove_dir_all(destination).at(destination)?;
    }
    fs::create_dir_all(destination).at(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).at(destination)?;
    let file = File::open(source).at(source)?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(msg("update ZIP contains too many entries"));
    }
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| msg("update ZIP contains an unsafe path"))?
            .to_path_buf();
        if relative.as_os_str().is_empty() {
            continue;
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o040000 && kind != 0o100000 {
                return Err(msg("update ZIP contains a non-regular filesystem entry"));
            }
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| msg("update ZIP expanded size overflow"))?;
        if total > max_total {
            return Err(msg("update ZIP exceeds the safe expanded size limit"));
        }
        let output = destination.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&output).at(&output)?;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).at(&output)?;
            continue;
        }
        let parent = output
            .parent()
            .ok_or_else(|| msg("update ZIP entry has no parent"))?;
        fs::create_dir_all(parent).at(parent)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&output)
            .at(&output)?;
        let copied = std::io::copy(&mut entry, &mut file).at(&output)?;
        if copied != entry.size() {
            return Err(msg("update ZIP entry size changed during extraction"));
        }
        file.sync_all().at(&output)?;
    }
    Ok(())
}

fn locate_named_root(parent: &Path, expected: &str) -> Result<PathBuf> {
    if parent.file_name().is_some_and(|name| name == expected) {
        return Ok(parent.to_path_buf());
    }
    let direct = parent.join(expected);
    if direct.is_dir() {
        return Ok(direct);
    }
    Err(msg(format!(
        "archive does not contain the expected {expected}/ root"
    )))
}

fn read_regular_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    verify_regular_file(path)?;
    read_limited(path, max)
}

fn read_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).at(path)?;
    if metadata.len() > max as u64 {
        return Err(msg(format!(
            "{} exceeds the safe size limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .at(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .at(path)?;
    if bytes.len() > max {
        return Err(msg(format!(
            "{} exceeds the safe size limit",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent).at(parent)?.sync_all().at(parent)?;
    }
    Ok(())
}

#[cfg(test)]
fn profile_from_catalog(profile: &DeviceProfile) -> UpdateProfile {
    UpdateProfile {
        build_fingerprint: profile.build_fingerprint.clone(),
        kernel_release_prefix: profile.kernel_release_prefix.clone(),
        abi: profile.abi.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("xpad2-update-{label}-{}", unique_id()))
    }

    fn manifest() -> UpdateManifest {
        UpdateManifest {
            schema: 1,
            kind: UPDATE_KIND.to_string(),
            channel: UPDATE_CHANNEL.to_string(),
            repository: UPDATE_REPOSITORY.to_string(),
            version: "0.2.0".to_string(),
            catalog_version: "2026-07-15.9".to_string(),
            profile: UpdateProfile {
                build_fingerprint: "vendor/device:13/build/260:user/release-keys".to_string(),
                kernel_release_prefix: "4.19.191".to_string(),
                abi: "arm64-v8a".to_string(),
            },
            binary: UpdateAsset {
                filename: "xpad2-v0.2.0-android-arm64".to_string(),
                url: "https://github.com/yoyicue/xpad2-cli/releases/download/v0.2.0/xpad2-v0.2.0-android-arm64".to_string(),
                size: 1,
                sha256: "a".repeat(64),
            },
            cache: UpdateAsset {
                filename: "xpad2-cache-v0.2.0.zip".to_string(),
                url: "https://github.com/yoyicue/xpad2-cli/releases/download/v0.2.0/xpad2-cache-v0.2.0.zip".to_string(),
                size: 1,
                sha256: "b".repeat(64),
            },
            catalog: CatalogIdentity {
                filename: "catalog.json".to_string(),
                size: 1,
                sha256: "c".repeat(64),
            },
            release_url: "https://github.com/yoyicue/xpad2-cli/releases/tag/v0.2.0".to_string(),
        }
    }

    fn github_release() -> GitHubRelease {
        let asset = |name: &str, size: u64, digest: Option<String>, id: u64| GitHubAsset {
            name: name.to_string(),
            url: format!("https://api.github.com/repos/yoyicue/xpad2-cli/releases/assets/{id}"),
            size,
            state: "uploaded".to_string(),
            digest,
        };
        GitHubRelease {
            tag_name: "v0.2.0".to_string(),
            html_url: "https://github.com/yoyicue/xpad2-cli/releases/tag/v0.2.0".to_string(),
            draft: false,
            prerelease: false,
            assets: vec![
                asset(MANIFEST_FILENAME, 1024, None, 1),
                asset(SIGNATURE_FILENAME, 512, None, 2),
                asset(
                    "xpad2-v0.2.0-android-arm64",
                    1,
                    Some(format!("sha256:{}", "a".repeat(64))),
                    3,
                ),
                asset(
                    "xpad2-cache-v0.2.0.zip",
                    1,
                    Some(format!("sha256:{}", "b".repeat(64))),
                    4,
                ),
            ],
        }
    }

    #[test]
    fn strict_manifest_accepts_the_release_shape() {
        validate_manifest(&manifest()).unwrap();
    }

    #[test]
    fn manifest_rejects_unsafe_or_mismatched_assets() {
        let mut value = manifest();
        value.binary.filename = "../xpad2".to_string();
        assert!(validate_manifest(&value).is_err());
        let mut value = manifest();
        value.cache.url = "http://example.invalid/cache.zip".to_string();
        assert!(validate_manifest(&value).is_err());
        let mut value = manifest();
        value.binary.sha256 = "A".repeat(64);
        assert!(validate_manifest(&value).is_err());
    }

    #[test]
    fn version_policy_distinguishes_update_current_and_downgrade() {
        let current = Version::parse("0.2.0").unwrap();
        assert_eq!(
            version_state(&current, &Version::parse("0.2.1").unwrap()),
            VersionState::Available
        );
        assert_eq!(version_state(&current, &current), VersionState::Current);
        assert_eq!(
            version_state(&current, &Version::parse("0.1.9").unwrap()),
            VersionState::Ahead
        );
    }

    #[test]
    fn update_arguments_require_explicit_downgrade_authority() {
        let args = vec!["--allow-downgrade".to_string()];
        assert!(parse_args(&args).is_err());
        let args = vec![
            "--version".to_string(),
            "0.1.9".to_string(),
            "--allow-downgrade".to_string(),
        ];
        assert!(parse_args(&args).is_ok());
    }

    #[test]
    fn github_api_transport_is_bound_to_the_signed_release() {
        let release = github_release();
        validate_github_release(&release, Some("0.2.0")).unwrap();
        validate_github_release_manifest(&release, &manifest()).unwrap();

        let mut wrong_host = github_release();
        wrong_host.assets[0].url =
            "https://example.invalid/repos/yoyicue/xpad2-cli/releases/assets/1".to_string();
        assert!(github_asset(&wrong_host, MANIFEST_FILENAME).is_err());

        let mut wrong_digest = github_release();
        wrong_digest.assets[2].digest = Some(format!("sha256:{}", "f".repeat(64)));
        assert!(validate_github_release_manifest(&wrong_digest, &manifest()).is_err());
    }

    #[test]
    fn catalog_profile_conversion_is_lossless() {
        let source = DeviceProfile {
            build_fingerprint: "fp".to_string(),
            kernel_release_prefix: "4.19".to_string(),
            abi: "arm64-v8a".to_string(),
        };
        let converted = profile_from_catalog(&source);
        assert_eq!(converted.build_fingerprint, source.build_fingerprint);
        assert_eq!(
            converted.kernel_release_prefix,
            source.kernel_release_prefix
        );
        assert_eq!(converted.abi, source.abi);
    }

    #[test]
    fn rollback_primitives_restore_the_previous_binary_and_cache() {
        let root = test_dir("rollback");
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("xpad2");
        let backup = root.join("xpad2.backup");
        atomic_write(&binary, b"new", 0o700).unwrap();
        atomic_write(&backup, b"old", 0o700).unwrap();
        BinarySwap {
            target: binary.clone(),
            backup,
        }
        .rollback()
        .unwrap();
        assert_eq!(fs::read(&binary).unwrap(), b"old");

        let cache = root.join("cache");
        let previous = root.join("cache.previous");
        fs::create_dir(&cache).unwrap();
        fs::create_dir(&previous).unwrap();
        fs::write(cache.join("marker"), b"new").unwrap();
        fs::write(previous.join("marker"), b"old").unwrap();
        CacheSwap {
            target: cache.clone(),
            previous: Some(previous),
        }
        .rollback()
        .unwrap();
        assert_eq!(fs::read(cache.join("marker")).unwrap(), b"old");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zip_extraction_rejects_parent_traversal() {
        let root = test_dir("zip-slip");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("malicious.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = ZipWriter::new(file);
        archive
            .start_file("../escaped", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
        let output = root.join("output");
        assert!(extract_zip_safely(&archive_path, &output, 1024).is_err());
        assert!(!root.join("escaped").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
