# xpad3-cli 设计

## 1. 产品边界

`xpad2-cli` 对应 4.19 旧内核 XPad2；`xpad3-cli` 对应 XPad2A 之后的 5.x 现代内核产品线。拆分的原因不是命令名称，而是两个时代的利用链、触发域、KSU KMI、内核布局和发布风险不同。

“现代内核产品线”是代码和发布的归属边界，不是兼容性判断。5.4、5.10，乃至两个相同 5.10 release 的厂商 build，都可能具有不同符号布局、结构体布局、SELinux offset、触发约束或 KSU 模块组合。

## 2. Profile 是唯一写入授权

每个 runtime profile 锁定：

| 字段 | 作用 |
| --- | --- |
| `build_fingerprint` | 型号与固件身份，精确匹配 |
| `kernel_release_prefix` | 内核发行/KMI 线 |
| `kernel_version` | 完整 `uname -v` 编译身份 |
| `abi` | CLI 和内核链的 ABI 边界 |
| 四个 IonStack artifact | runner、perf target、preload、probe |
| `trigger_artifact` | 对应 app-domain 触发器及签名身份 |
| `ksu_kmi` | `ksud late-load` 选择的内嵌模块 |

运行时必须同时匹配四元身份，随后从同一 profile 取出利用制品、trigger 和 KMI。这样可以避免“设备门匹配 A、制品却按 kernel version 选到 B”的交叉选择错误。

`assets.lock.json.profile` 继续作为 schema-1 updater 的兼容锚点；真正的 runtime 选择使用 `ionstack_profiles`。首版只有 `xpad3s-338`。PD2A、PD3P、PD3U 不使用占位身份，也不会继承 PD3S offset。

## 3. Root 状态机

```text
exact profile
  -> freeze OTA
  -> reject stale root/trigger state
  -> install and verify profile trigger
  -> stage profile IonStack artifacts
  -> run bounded holder attempts
  -> independently verify su -c id
  -> optional command or KSU late-load
  -> remove temporary su and chain files
  -> restore and verify SELinux Enforcing
```

PD3S 需要 debuggable app-domain compat32 trigger。利用成功后，该进程可能仍驻留以维持链路，所以不能把 trigger APK 当成普通的随时可更新组件：

- KSU 已加载：复用 KSU，跳过 trigger 安装和 exploit；
- KSU 未加载且 trigger 在运行：返回 `NeedsReboot`；
- 只有无冲突状态才允许安装锁定 trigger 并进入 Root。

Runner 受 20 分钟总 deadline 和 6 轮 holder 机会限制。失败后的低价值同 boot 重试转换为普通重启要求。

## 4. KernelSU late-load

首版锁定 KernelSU 32551、UAPI 2、flags/features `0x5`，KMI 为 `android12-5.10`。调用为：

```text
ksud late-load --kmi android12-5.10 --allow-shell
```

`--allow-shell` 是 PD3S 这条现代内核移植的明确约束。CLI 不仅检查 `/sys/module/kernelsu`，还用锁定的 `ksud debug info` 核验版本、UAPI、flags/features、LKM 与 late-load 状态。已有未知 KernelSU-family 模块时，不进行在线切换。

未来 profile 可以声明不同 KMI；KMI 和利用制品一样，来自选中的 runtime profile，而不是由“5.x”推断。

## 5. 安装事务

默认 `install` 展开为：

```text
ksu -> xpad-installer -> installer-backup -> ksu-manager -> boominstaller
```

Manager 在 late-load 前安装，使模块注册时可以核验官方应用身份。所有 APK 先离线解析包名、versionCode、签名证书、ABI、大小和哈希；已安装包签名不一致时拒绝卸载或擦除数据。

PackageManager 每次提交后可能重写 `packages.list`。因此事务在所有 APK 变化完成后，再执行一次幂等的 0044 installer-backup 修复和验证。

事务记录开始/结束 boot ID、SELinux、组件、错误与 reboot 要求。只要本事务拥有临时 Root，就必须在结束时关闭它；关闭失败升级为 `NeedsReboot`。

## 6. 制品与供应链

`assets.lock.json` 是执行制品锁：文件名、类型、版本、大小、SHA-256、模式、APK 身份和是否嵌入。构建脚本从相邻上游工程读取文件，验证后才写入 Rust `include_bytes!` 表。

`sources.lock.json` 是来源锁：IonStack、KSU port、Manager、安装器和 BoomInstaller 的仓库与 commit。PD3S 首版关键来源是：

- `xpad2-ionstack-poc` `3a0d27f`；
- `xpad2-ksu-lateload` `c7bcd62`。

目录名仍带 `xpad2` 是历史仓库名，不代表 CLI 使用 4.19 XPad2 profile。

## 7. 新 profile 接入门槛

新增 PD2A/PD3P/PD3U 或新 PD3S build 时：

1. 收集完整 fingerprint、kernel release、`uname -v`、ABI。
2. 建立独立 PoC profile，验证读路径、KASLR、写原语、Root 与安全收尾。
3. 构建并锁定对应 trigger APK；验证进程域和驻留行为。
4. 构建对应 KSU KMI，验证 late-load、Manager 身份、SELinux Enforcing 和重启恢复。
5. 增加独立 `ionstack_profiles` 条目与制品，不修改已有 profile 的身份范围。
6. 运行 Rust 测试、clippy、arm64 build，并做先只读后有状态的真机验证。

Offset 恰好一致可以减少移植工作，但不能替代这些门槛；它是 profile 验证的证据，不是跨型号授权规则。
