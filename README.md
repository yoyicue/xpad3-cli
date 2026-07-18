# xpad3-cli

`xpad3-cli` 是面向 XPad2A 之后现代内核产品线的、离线且 profile 锁定的 Root/安装控制面。它与 `xpad2-cli` 分开演进：前者承载 Android 12 / 5.x 内核设备，后者继续承载 XPad2 的 4.19 旧内核发布线。

名字表示产品族，不表示所有 5.x 固件天然兼容。每台设备必须同时命中签名目录中的完整 runtime profile，CLI 才会执行 IonStack 或 KernelSU late-load。

## v0.1.0 支持范围

| Profile | 设备 | 指纹 | 内核 | 状态 |
| --- | --- | --- | --- | --- |
| `xpad3s-338` | `TALIH-PD3S` | 精确 `/338` | `5.10.198-android12-9-00019-g6efebf1322d6-ab11471183`，精确 `uname -v` | Root 与 KSU late-load 真机验证 |
| PD2A / PD3P / PD3U | 预留 | 未锁定 | 未锁定 | 安全拒绝 |

首版不会放行 PD3S `/371`，也不会用“同属 5.x”替代精确地址表验证。新增型号应增加独立 profile、IonStack 制品、触发器和 KSU KMI，而不是扩大现有指纹范围。

## 已锁定链路

- PD3S app-domain compat32 trigger：`com.ionstack.trigger` v1。
- PD3S IonStack runner、perf target、preload 和 chainwalk probe。
- KernelSU 32551 / UAPI 2 / `android12-5.10` late-load，调用时带 `--allow-shell`。
- 官方 KernelSU Manager、`xpad-install`、0044 installer backup 和 BoomInstaller。
- 所有制品在 `assets.lock.json` 中锁定大小和 SHA-256，并嵌入 arm64 CLI。

## 常用命令

```sh
adb push xpad3 /data/local/tmp/xpad3
adb shell chmod 700 /data/local/tmp/xpad3

adb shell /data/local/tmp/xpad3 version
adb shell /data/local/tmp/xpad3 status
adb shell /data/local/tmp/xpad3 doctor
adb shell /data/local/tmp/xpad3 list
```

完整安装默认选择 KernelSU：

```sh
adb shell /data/local/tmp/xpad3 install
# 等价于：ksu + xpad-installer + installer-backup + ksu-manager + boominstaller
```

仅保留临时 Root：

```sh
adb shell /data/local/tmp/xpad3 root
adb shell /data/local/tmp/xpad3 root -- id
adb shell /data/local/tmp/xpad3 cleanup
```

`root` 会保留临时 `su`；`install ksu/full` 会在 KSU 验证后主动关闭临时 Root，并恢复 SELinux Enforcing。退出码 `75` 表示必须普通重启后再继续。

## 关键安全行为

1. 写原语之前匹配指纹、kernel release、完整 `uname -v` 和 ABI。
2. profile 同时选择对应 IonStack 制品、trigger APK 和 KernelSU KMI，避免跨型号错配。
3. 如果 KSU 已在当前 boot 中健康加载，安装事务接管它，不再启动 exploit，也不更新仍可能驻留的 trigger。
4. 如果 trigger 仍在运行但 KSU 未加载，拒绝叠加尝试并返回退出码 75。
5. APK 安装前核验包名、版本、证书、ABI、大小和哈希；不通过卸载来“修复”签名冲突。
6. OTA freeze、boot ID、SELinux、Root 和 KSU 状态在事务末尾独立复核。

## 构建

相邻目录需要存在锁定上游工程和制品：

- `../xpad2-ionstack-poc`，commit `3a0d27f`；
- `../xpad2-ksu-lateload`，commit `c7bcd62`；
- `../xpad2-reroot-android`、`../xpad-installer`、`../BoomInstaller`。

```sh
./tools/build_android.sh
```

输出为 `target/aarch64-linux-android/release/xpad3`。构建脚本会先运行全部 Rust 测试，再从相邻工程读取制品，并在嵌入前逐一核验锁定大小和 SHA-256。

## 新型号接入规则

新增型号至少要获得四元身份：fingerprint、kernel release、完整 `uname -v`、ABI；还要独立验证 IonStack 地址表/写链路、trigger 身份、KSU KMI 和 late-load 结果。然后在 `ionstack_profiles` 中添加独立条目并锁定制品。即使 KASLR 基址或部分 offset 恰好相同，也不能跳过完整 profile 验证。

设计细节见 [DESIGN.md](DESIGN.md)，设备端操作见 [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md)。
