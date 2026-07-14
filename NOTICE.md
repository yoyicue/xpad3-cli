# Notices

`xpad2` control-plane code is distributed under GPL-3.0-or-later.

The release embeds independent, hash-locked executables and APKs as data and extracts them as
separate processes/files at runtime. Their exact binary and source identities are recorded in
`assets.lock.json` and `sources.lock.json`.

- `xpad2-ionstack-poc`: GPL-3.0-or-later aggregate with Apache-2.0-derived exploit portions;
  its upstream LICENSE and NOTICE are included in release packages.
- KernelSU late-load kernel/userspace artifacts: GPL-2.0-only and applicable upstream notices.
- KernelSU Manager: GPL-3.0-only.
- `xpad-installer`: its upstream LICENSE is included in release packages.
- BoomInstaller: its upstream LICENSE and third-party notices remain with that project and the
  signed APK; the project LICENSE is included in release packages.
- Rust dependencies retain their own licenses as recorded by `Cargo.lock` and crates.io metadata.

No production signing private key, encrypted password, recovery private key, GitHub credential,
ADB key, or pairing credential is included in this repository or any diagnostic package.
