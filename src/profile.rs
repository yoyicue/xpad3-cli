use crate::error::{Result, msg};
#[cfg(test)]
use crate::model::IonStackDiscoveryProfile;
use crate::model::{AssetsLock, DeviceProfile, IonStackProfile};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IonStackArtifacts<'a> {
    pub profile_id: &'a str,
    pub runner: &'a str,
    pub perf_target: &'a str,
    pub preload: &'a str,
    pub chainwalk_probe: &'a str,
    pub trigger: &'a str,
    pub ksu_kmi: &'a str,
}

#[derive(Clone, Copy)]
pub struct FingerprintPolicy<'a> {
    exact_anchor: &'a str,
    prefix: &'a str,
    suffix: &'a str,
    incremental_min: u32,
    incremental_max: u32,
}

impl DeviceProfile {
    pub fn fingerprint_policy(&self) -> FingerprintPolicy<'_> {
        FingerprintPolicy {
            exact_anchor: &self.build_fingerprint,
            prefix: &self.build_fingerprint_prefix,
            suffix: &self.build_fingerprint_suffix,
            incremental_min: self.fingerprint_incremental_min,
            incremental_max: self.fingerprint_incremental_max,
        }
    }
}

impl AssetsLock {
    pub fn validate_ionstack_profiles(&self) -> Result<()> {
        if self.ionstack_profiles.is_empty() {
            return Err(msg("signed catalog has no enabled XPad3 runtime profile"));
        }

        let mut ids = BTreeSet::new();
        let mut runtime_identities = BTreeSet::new();
        for profile in &self.ionstack_profiles {
            if profile.id.is_empty()
                || profile.build_fingerprint.is_empty()
                || profile.kernel_release_prefix.is_empty()
                || profile.kernel_version.is_empty()
                || profile.abi != "arm64-v8a"
                || profile.runner_artifact.is_empty()
                || profile.perf_target_artifact.is_empty()
                || profile.preload_artifact.is_empty()
                || profile.chainwalk_probe_artifact.is_empty()
                || profile.trigger_artifact.is_empty()
                || profile.ksu_kmi.is_empty()
            {
                return Err(msg(
                    "IonStack profile has an empty identity or artifact mapping",
                ));
            }
            if !ids.insert(profile.id.as_str()) {
                return Err(msg(format!(
                    "duplicate IonStack profile id: {}",
                    profile.id
                )));
            }
            if !runtime_identities.insert((
                profile.build_fingerprint.as_str(),
                profile.kernel_release_prefix.as_str(),
                profile.kernel_version.as_str(),
                profile.abi.as_str(),
            )) {
                return Err(msg(format!(
                    "duplicate IonStack runtime identity: {}",
                    profile.id
                )));
            }
        }

        let mut discovery_ids = BTreeSet::new();
        for discovery in &self.ionstack_discovery_profiles {
            if !ids.contains(discovery.profile_id.as_str()) {
                return Err(msg(format!(
                    "IonStack discovery references unknown profile {}",
                    discovery.profile_id
                )));
            }
            if !discovery_ids.insert(discovery.profile_id.as_str()) {
                return Err(msg(format!(
                    "duplicate IonStack discovery profile: {}",
                    discovery.profile_id
                )));
            }
            let mut offsets = BTreeSet::new();
            for (name, value) in &discovery.offsets {
                let offset = parse_anchor_offset(value).ok_or_else(|| {
                    msg(format!(
                        "invalid IonStack discovery offset {}:{}={value:?}",
                        discovery.profile_id, name
                    ))
                })?;
                if name.is_empty() || !offsets.insert(offset) {
                    return Err(msg(format!(
                        "IonStack discovery profile {} has an empty or duplicate anchor",
                        discovery.profile_id
                    )));
                }
            }
            if offsets.len() < 2 {
                return Err(msg(format!(
                    "IonStack discovery profile {} needs at least two independent anchors",
                    discovery.profile_id
                )));
            }
        }
        Ok(())
    }

    pub fn selected_ionstack_profile(
        &self,
        fingerprint: &str,
        kernel_release: &str,
        kernel_version: &str,
        abi: &str,
    ) -> Option<&IonStackProfile> {
        self.ionstack_profiles.iter().find(|profile| {
            profile.build_fingerprint == fingerprint
                && kernel_release.starts_with(&profile.kernel_release_prefix)
                && profile.kernel_version == kernel_version
                && profile.abi == abi
        })
    }

    pub fn ionstack_profile(&self, profile_id: &str) -> Option<&IonStackProfile> {
        self.ionstack_profiles
            .iter()
            .find(|profile| profile.id == profile_id)
    }

    pub fn ionstack_artifacts_for_profile(
        &self,
        profile_id: &str,
    ) -> Option<IonStackArtifacts<'_>> {
        let profile = self.ionstack_profile(profile_id)?;
        Some(IonStackArtifacts {
            profile_id: &profile.id,
            runner: &profile.runner_artifact,
            perf_target: &profile.perf_target_artifact,
            preload: &profile.preload_artifact,
            chainwalk_probe: &profile.chainwalk_probe_artifact,
            trigger: &profile.trigger_artifact,
            ksu_kmi: &profile.ksu_kmi,
        })
    }

    pub fn ionstack_artifacts(
        &self,
        fingerprint: &str,
        kernel_release: &str,
        kernel_version: &str,
        abi: &str,
    ) -> Option<IonStackArtifacts<'_>> {
        let profile =
            self.selected_ionstack_profile(fingerprint, kernel_release, kernel_version, abi)?;
        self.ionstack_artifacts_for_profile(&profile.id)
    }

    #[cfg(test)]
    pub fn matches_technical_runtime(
        &self,
        fingerprint: &str,
        kernel_release: &str,
        abi: &str,
    ) -> bool {
        self.ionstack_profiles.iter().any(|profile| {
            profile.build_fingerprint == fingerprint
                && kernel_release.starts_with(&profile.kernel_release_prefix)
                && profile.abi == abi
        })
    }

    pub fn matches_product_device(&self, fingerprint: &str, abi: &str) -> bool {
        self.ionstack_profiles
            .iter()
            .any(|profile| profile.build_fingerprint == fingerprint && profile.abi == abi)
    }

    #[cfg(test)]
    pub fn matches_runtime(
        &self,
        fingerprint: &str,
        kernel_release: &str,
        kernel_version: &str,
        abi: &str,
    ) -> bool {
        self.matches_technical_runtime(fingerprint, kernel_release, abi)
            && self
                .ionstack_artifacts(fingerprint, kernel_release, kernel_version, abi)
                .is_some()
    }
}

pub fn parse_anchor_offset(value: &str) -> Option<u64> {
    let digits = value.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

impl FingerprintPolicy<'_> {
    pub fn validate(self) -> Result<()> {
        if self.exact_anchor.is_empty() {
            return Err(msg("device profile has an empty fingerprint anchor"));
        }
        if self.is_legacy_exact() {
            return Ok(());
        }
        if self.prefix.is_empty()
            || self.suffix.is_empty()
            || self.incremental_min > self.incremental_max
        {
            return Err(msg("device profile has an incomplete fingerprint range"));
        }
        let expected_anchor = format!("{}{}{}", self.prefix, self.incremental_max, self.suffix);
        if self.exact_anchor != expected_anchor {
            return Err(msg(format!(
                "fingerprint compatibility anchor must equal the range upper bound: expected {expected_anchor}, got {}",
                self.exact_anchor
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn matches(self, fingerprint: &str) -> bool {
        if self.is_legacy_exact() {
            return fingerprint == self.exact_anchor;
        }
        self.incremental(fingerprint).is_some_and(|incremental| {
            incremental >= self.incremental_min && incremental <= self.incremental_max
        })
    }

    pub fn incremental(self, fingerprint: &str) -> Option<u32> {
        if self.is_legacy_exact() {
            return None;
        }
        let numeric = fingerprint
            .strip_prefix(self.prefix)?
            .strip_suffix(self.suffix)?;
        if numeric.is_empty()
            || !numeric.bytes().all(|byte| byte.is_ascii_digit())
            || (numeric.len() > 1 && numeric.starts_with('0'))
        {
            return None;
        }
        numeric.bytes().try_fold(0u32, |value, byte| {
            value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
        })
    }

    fn is_legacy_exact(self) -> bool {
        self.prefix.is_empty()
            && self.suffix.is_empty()
            && self.incremental_min == 0
            && self.incremental_max == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "alps/vnd_ls12_mt8797_wifi_64/ls12_mt8797_wifi_64:13/TP1A.220624.014/";
    const SUFFIX: &str = ":user/release-keys";

    fn ranged_profile() -> DeviceProfile {
        DeviceProfile {
            build_fingerprint: format!("{PREFIX}260{SUFFIX}"),
            build_fingerprint_prefix: PREFIX.to_string(),
            build_fingerprint_suffix: SUFFIX.to_string(),
            fingerprint_incremental_min: 19,
            fingerprint_incremental_max: 260,
            kernel_release_prefix: "5.10.test".to_string(),
            kernel_version: "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026".to_string(),
            abi: "arm64-v8a".to_string(),
        }
    }

    fn ranged_lock() -> AssetsLock {
        AssetsLock {
            schema: 1,
            product_version: "test".to_string(),
            catalog_version: "test".to_string(),
            profile: ranged_profile(),
            ionstack_profiles: vec![
                ionstack_profile(
                    "modern-a",
                    "#1 SMP PREEMPT Tue Aug 13 02:06:24 CST 2024",
                    "a",
                ),
                ionstack_profile(
                    "modern-b",
                    "#1 SMP PREEMPT Mon Dec 16 23:29:13 CST 2024",
                    "b",
                ),
                ionstack_profile(
                    "modern-c",
                    "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
                    "260",
                ),
            ],
            ionstack_discovery_profiles: vec![
                discovery_profile("modern-a", "0x00be6de8"),
                discovery_profile("modern-b", "0x00be7210"),
                discovery_profile("modern-c", "0x00be4c48"),
            ],
            artifacts: Vec::new(),
        }
    }

    fn discovery_profile(id: &str, distinct: &str) -> IonStackDiscoveryProfile {
        IonStackDiscoveryProfile {
            profile_id: id.to_string(),
            offsets: [
                ("distinct".to_string(), distinct.to_string()),
                ("shared".to_string(), "0x020fb2b8".to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    fn ionstack_profile(id: &str, kernel_version: &str, suffix: &str) -> IonStackProfile {
        IonStackProfile {
            id: id.to_string(),
            build_fingerprint: format!("{PREFIX}260{SUFFIX}"),
            kernel_release_prefix: "5.10.test".to_string(),
            kernel_version: kernel_version.to_string(),
            abi: "arm64-v8a".to_string(),
            runner_artifact: format!("runner-{suffix}"),
            perf_target_artifact: "perf".to_string(),
            preload_artifact: format!("preload-{suffix}"),
            chainwalk_probe_artifact: "probe".to_string(),
            trigger_artifact: "trigger".to_string(),
            ksu_kmi: "test-kmi".to_string(),
        }
    }

    #[test]
    fn accepts_every_canonical_incremental_from_19_through_260() {
        let profile = ranged_profile();
        let policy = profile.fingerprint_policy();
        policy.validate().unwrap();
        assert!(!policy.matches(&format!("{PREFIX}18{SUFFIX}")));
        for incremental in 19..=260 {
            let fingerprint = format!("{PREFIX}{incremental}{SUFFIX}");
            assert!(policy.matches(&fingerprint), "rejected {incremental}");
            assert_eq!(policy.incremental(&fingerprint), Some(incremental));
        }
        assert!(!policy.matches(&format!("{PREFIX}261{SUFFIX}")));
    }

    #[test]
    fn runtime_profile_gate_is_exact_even_when_manifest_anchor_has_a_range() {
        let lock = ranged_lock();
        assert!(lock.matches_product_device(&format!("{PREFIX}260{SUFFIX}"), "arm64-v8a"));
        assert!(!lock.matches_product_device(&format!("{PREFIX}19{SUFFIX}"), "arm64-v8a"));
        let timestamp = format!("{PREFIX}1703659196{SUFFIX}");
        assert!(!lock.matches_technical_runtime(&timestamp, "5.10.test+", "arm64-v8a"));
        assert!(!lock.matches_product_device(&timestamp, "armeabi-v7a"));
        assert!(!lock.matches_product_device(&format!("{PREFIX}01703659196{SUFFIX}"), "arm64-v8a"));
        assert!(!lock.matches_product_device(
            "alps/vnd_other/device:13/TP1A.220624.014/260:user/release-keys",
            "arm64-v8a"
        ));
    }

    #[test]
    fn rejects_noncanonical_or_different_fingerprints() {
        let profile = ranged_profile();
        let policy = profile.fingerprint_policy();
        for fingerprint in [
            format!("{PREFIX}019{SUFFIX}"),
            format!("{PREFIX}+19{SUFFIX}"),
            format!("{PREFIX}{SUFFIX}"),
            format!("{PREFIX}19x{SUFFIX}"),
            format!("{PREFIX}42949672960{SUFFIX}"),
            format!("{PREFIX}19:user/debug-keys"),
            "alps/vnd_other/ls12_mt8797_wifi_64:13/TP1A.220624.014/19:user/release-keys"
                .to_string(),
        ] {
            assert!(!policy.matches(&fingerprint), "accepted {fingerprint}");
        }
    }

    #[test]
    fn range_requires_an_upper_bound_compatibility_anchor() {
        let mut profile = ranged_profile();
        profile.build_fingerprint = format!("{PREFIX}19{SUFFIX}");
        assert!(profile.fingerprint_policy().validate().is_err());
        profile.build_fingerprint = format!("{PREFIX}260{SUFFIX}");
        profile.build_fingerprint_suffix.clear();
        assert!(profile.fingerprint_policy().validate().is_err());
    }

    #[test]
    fn legacy_profile_remains_exact_only() {
        let profile = DeviceProfile {
            build_fingerprint: "legacy/exact".to_string(),
            build_fingerprint_prefix: String::new(),
            build_fingerprint_suffix: String::new(),
            fingerprint_incremental_min: 0,
            fingerprint_incremental_max: 0,
            kernel_release_prefix: "4.19".to_string(),
            kernel_version: String::new(),
            abi: "arm64-v8a".to_string(),
        };
        let policy = profile.fingerprint_policy();
        policy.validate().unwrap();
        assert!(policy.matches("legacy/exact"));
        assert!(!policy.matches("legacy/other"));
    }

    #[test]
    fn fingerprint_range_never_weakens_kernel_or_abi_identity() {
        let profile = ranged_lock();
        let fingerprint = format!("{PREFIX}260{SUFFIX}");
        assert!(profile.matches_runtime(
            &fingerprint,
            "5.10.test+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "5.10.test+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "5.10.198",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "arm64-v8a"
        ));
        assert!(!profile.matches_runtime(
            &fingerprint,
            "5.10.test+",
            "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
            "armeabi-v7a"
        ));
        assert!(!profile.matches_runtime(
            &format!("{PREFIX}1703659196{SUFFIX}"),
            "5.10.test+",
            "#1 SMP PREEMPT Wed Dec 27 15:45:11 CST 2023",
            "arm64-v8a"
        ));
    }

    #[test]
    fn exact_kernel_build_selects_each_release_artifact_set() {
        let lock = ranged_lock();
        lock.validate_ionstack_profiles().unwrap();
        for (kernel, id, runner, preload) in [
            (
                "#1 SMP PREEMPT Tue Aug 13 02:06:24 CST 2024",
                "modern-a",
                "runner-a",
                "preload-a",
            ),
            (
                "#1 SMP PREEMPT Mon Dec 16 23:29:13 CST 2024",
                "modern-b",
                "runner-b",
                "preload-b",
            ),
            (
                "#1 SMP PREEMPT Mon Jun 29 04:08:29 CST 2026",
                "modern-c",
                "runner-260",
                "preload-260",
            ),
        ] {
            let fingerprint = format!("{PREFIX}260{SUFFIX}");
            let selected = lock
                .ionstack_artifacts(&fingerprint, "5.10.test+", kernel, "arm64-v8a")
                .unwrap();
            assert_eq!(selected.profile_id, id);
            assert_eq!(selected.runner, runner);
            assert_eq!(selected.preload, preload);
            assert_eq!(selected.perf_target, "perf");
            assert_eq!(selected.chainwalk_probe, "probe");
        }
    }

    #[test]
    fn unknown_kernel_build_enters_discovery_without_becoming_exact() {
        let lock = ranged_lock();
        let fingerprint = format!("{PREFIX}260{SUFFIX}");
        assert!(!lock.matches_runtime(
            &fingerprint,
            "5.10.test+",
            "#1 SMP PREEMPT unknown",
            "arm64-v8a"
        ));
        assert!(lock.matches_technical_runtime(&fingerprint, "5.10.test+", "arm64-v8a"));
        assert!(
            lock.ionstack_artifacts(
                &fingerprint,
                "5.10.test+",
                "#1 SMP PREEMPT unknown",
                "arm64-v8a"
            )
            .is_none()
        );
        assert_eq!(lock.ionstack_discovery_profiles.len(), 3);
    }

    #[test]
    fn duplicate_kernel_profiles_are_rejected() {
        let mut lock = ranged_lock();
        lock.ionstack_profiles[1].kernel_version = lock.ionstack_profiles[0].kernel_version.clone();
        assert!(lock.validate_ionstack_profiles().is_err());
    }

    #[test]
    fn release_catalog_remains_readable_by_the_v0_4_14_shape() {
        #[derive(serde::Deserialize)]
        struct LegacyProfile {
            build_fingerprint: String,
            kernel_release_prefix: String,
            abi: String,
        }
        #[derive(serde::Deserialize)]
        struct LegacyAssetsLock {
            schema: u32,
            product_version: String,
            catalog_version: String,
            profile: LegacyProfile,
            artifacts: Vec<crate::model::Artifact>,
        }

        let legacy: LegacyAssetsLock = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/assets.lock.json"
        )))
        .unwrap();
        assert_eq!(legacy.schema, 1);
        assert_eq!(legacy.product_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(legacy.catalog_version, "2026-07-19.7");
        assert!(legacy.profile.build_fingerprint.contains("TALIH-PD3S"));
        assert_eq!(
            legacy.profile.kernel_release_prefix,
            "5.10.198-android12-9-00019-g6efebf1322d6-ab11471183"
        );
        assert_eq!(legacy.profile.abi, "arm64-v8a");
        assert!(!legacy.artifacts.is_empty());
    }
}
