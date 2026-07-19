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

PD3S 需要 debuggable app-domain compat32 trigger。v0.1.8 使用独立的 `com.ionstack.trigger.v2` 身份，因此不必卸载旧 v1 包；但任一代 trigger 进程正在运行时都不能叠加利用：

- KSU 已加载：复用 KSU，跳过 trigger 安装和 exploit；
- KSU 未加载且 trigger 在运行：返回 `NeedsReboot`；
- 只有无冲突状态才允许安装锁定 trigger 并进入 Root。

Runner 受 20 分钟总 deadline 和 6 轮 holder 机会限制。capture 命中后会验证唯一 waiter task，恢复并回读 `pi_blocked_on` 与 slab 元数据，再由 UID 0 信号释放停放的 probe；`NeedsReboot` 只保留给无法证明安全退出的兜底路径。失败后的低价值同 boot 重试仍转换为普通重启要求。

## 4. KernelSU late-load

首版锁定 KernelSU 32547、UAPI 2、flags/features `0x5`，KMI 为 `android12-5.10`。驱动版本显式固定到官方同签名 Manager 制品的 32547；不得让 fork 的移植提交数量把驱动版本自动推进。调用为：

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
runner 的退出码 75，以及旧 runner 输出中的安全停放/留存 stale-waiter 标记，都会升级为 `NeedsReboot`；这保证日志、最终回执和进程退出码一致，禁止在同一 boot 叠加利用。
一旦 capture 输出 hit 标记，runner 会把该 worker 视为正在持有内核恢复责任：probe 的 parked/timeout、runner 的常规 capture deadline 和终止信号都不能提前杀死它。只有 worker 输出包含恢复结果的终态标记或自行退出后，事务才继续收尾。

## 6. 制品与供应链

`assets.lock.json` 是执行制品锁：文件名、类型、版本、大小、SHA-256、模式、APK 身份和是否嵌入。构建脚本从相邻上游工程读取文件，验证后才写入 Rust `include_bytes!` 表。

v0.1.8 将公共安装平面锁定到 xpad-installer v0.2.13 与 BoomInstaller r23。Boom 的
Root broker 保持真实 UID 0，经学而思 OEM Provider 提交 APK；随机 Provider 可读副本、
私有 staging 和内嵌 CLI 均在事务结束后删除。ADB-shell 路径继续使用受管 0044，31317
仍只修复 0044。

v0.1.9 将公共安装平面升级到 xpad-installer v0.2.14 与 BoomInstaller r24。APK 与 DEX
暂存改为逐事务唯一文件名并在成功或失败后清理，历史只读残留不再让下一次安装提前以
staging I/O 错误退出；PD3S Root profile、trigger、IonStack 与 KSU 制品保持不变。

`sources.lock.json` 是来源锁：IonStack、KSU port、Manager、安装器和 BoomInstaller 的仓库与 commit。PD3S 首版关键来源是：

- `xpad2-ionstack-poc` `c5e6aca`；
- `xpad2-ksu-lateload` `d25f9cc`。

目录名仍带 `xpad2` 是历史仓库名，不代表 CLI 使用 4.19 XPad2 profile。

## 7. KSU 重启诊断

KSU late-load 是最可能直接跨越进程死亡乃至整机重启的阶段，普通 stdout 无法作为
可靠证据。CLI 因此在每个安装事务内预建 0600 的
`ksu-late-load-stages.jsonl`，在进入临时 Root 调度前写入并 `fsync`；锁定的
`ksud` 继承该文件描述符，并在 daemonize、KMI/模块准备、Manager 检查、
`init_module` 前后和各 userspace 初始化阶段追加 JSONL，每条都单独同步。
CLI 会先检查锁定 loader 是否包含该协议；旧 loader 仍保留 CLI 外层阶段记录，但不会
收到未知参数。发布版只有在新 ksud 已重建并更新制品锁后才宣称具备内部阶段边界。

`init-module-enter` 与 `init-module-returned` 是核心边界。内核 panic 时调用不会返回，
重启后的最后一条耐久记录能够把故障定位到模块初始化；如果调用已返回，则可以继续
区分 SELinux、脚本或 Manager 重启阶段。trace 参数默认关闭，只接受 xpad3 事务目录
内、shell 所有、0600、单硬链接的预建普通文件，诊断失败不会扩大 ksud 的写文件能力。

状态命令会识别 active transaction 的 boot ID 变化；日志导出把事务告警写入摘要，
并汇总当前/上一 boot logcat、DropBox、pstore、`/proc/last_kmsg`、AEE/MRDUMP
清单及 MTK DebugLogger 最近三个 APLog 的 `last_kmsg`/`mblog_history`。AEE 正文
可能受 app domain 权限限制，因此这里明确采用多渠道而不是假设 shell 可读取单一路径。

## 8. 新 profile 接入门槛

新增 PD2A/PD3P/PD3U 或新 PD3S build 时：

1. 收集完整 fingerprint、kernel release、`uname -v`、ABI。
2. 建立独立 PoC profile，验证读路径、KASLR、写原语、Root 与安全收尾。
3. 构建并锁定对应 trigger APK；验证进程域和驻留行为。
4. 构建对应 KSU KMI，验证 late-load、Manager 身份、SELinux Enforcing 和重启恢复。
5. 增加独立 `ionstack_profiles` 条目与制品，不修改已有 profile 的身份范围。
6. 运行 Rust 测试、clippy、arm64 build，并做先只读后有状态的真机验证。

Offset 恰好一致可以减少移植工作，但不能替代这些门槛；它是 profile 验证的证据，不是跨型号授权规则。
