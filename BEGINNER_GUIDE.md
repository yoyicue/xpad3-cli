# xpad3-cli 设备端使用指南

v0.1.9 只支持已经验证的 `TALIH-PD3S` `/338`。看到同为 Android 13 或 5.x 内核，不代表可以绕过 profile 检查。

## 1. 先检查，不改设备

```sh
adb devices
adb push xpad3 /data/local/tmp/xpad3
adb shell chmod 700 /data/local/tmp/xpad3
adb shell /data/local/tmp/xpad3 version
adb shell /data/local/tmp/xpad3 status
adb shell /data/local/tmp/xpad3 doctor
```

正常设备应显示：

- XPad3 现代内核设备：`yes`；
- 精确 Root profile：`yes`；
- profile 为 PD3S `/338` 和精确 5.10.198 build；
- SELinux 为 `Enforcing`。

`ionstack-trigger` 显示 `outdated` 并不等于必须立刻更新。如果当前 boot 已加载 KSU，CLI 会跳过 exploit 和 trigger 更新，避免杀死仍驻留的触发进程。

## 2. 完整安装

```sh
adb shell /data/local/tmp/xpad3 install
```

流程会依次处理 OTA freeze、官方 Manager、trigger、临时 Root、KernelSU late-load、安装器和 BoomInstaller。若 KSU 已健康加载，则复用当前 runtime，不会再次利用漏洞。

完成后检查：

```sh
adb shell /data/local/tmp/xpad3 status
adb shell /data/local/tmp/xpad3 info ksu
adb shell /data/local/tmp/xpad3 verify ksu
```

Manager 与驱动应同时显示 `32547`。若仍显示 Manager `32525` / 驱动 `32551`，说明
设备仍运行旧组合：先普通重启清除非持久的 late-load 驱动，再用本版本执行完整安装；
不要在同一 boot 内尝试把 32551 在线替换为 32547。

## 3. 仅使用临时 Root

```sh
adb shell /data/local/tmp/xpad3 root -- id
adb shell /data/local/tmp/su -c id
```

用完立即清理：

```sh
adb shell /data/local/tmp/xpad3 cleanup
```

或者执行一次普通重启。不要在同一 boot 里强停或更新 `com.ionstack.trigger` / `com.ionstack.trigger.v2` 后继续叠加 Root 尝试。v0.1.9 使用独立 v2 包，旧 v1 包无需卸载。

v0.1.9 可以容忍中断事务遗留的、无守护进程的 root 所有
`/data/local/tmp/su`：CLI 会报告无法以 shell 身份删除它，Root 链在捕获
credential 后再以 root 身份原子替换。这个警告本身不需要循环重启。

看到 `CAPTURE_RECOVERY_WAIT` 表示写原语已经命中，runner 正在完成结果确认和
fops/内核元数据恢复；此时不要按 Ctrl-C、关闭 ADB 窗口或杀进程。v0.1.9 会越过
普通的 90 秒 capture 超时，找到唯一 waiter task，恢复并回读验证其内核字段，然后
安全释放 probe。只有这一步无法验证时才会返回 75 要求重启。

## 4. 退出码 75

退出码 75 表示当前 boot 的状态不适合安全重试，例如：

- trigger 已驻留但 KSU 没有成功加载；
- app-domain probe 已停放，但 runner 无法验证 waiter 修复与安全释放；
- 已加载的 KernelSU-family 模块不是锁定版本；
- boot ID 在事务中变化；
- 临时 Root 或 SELinux 无法安全收尾。

此时执行普通重启，再从 `status` 和 `doctor` 开始。不要循环运行 exploit。

## 5. Root/KSU 重启后收集日志

无论是在临时 Root 阶段还是 KSU late-load 阶段突然黑屏重启，都遵守同一条原则：
**等系统完全开机后先导出日志，不要先运行 `root`、`install`、`cleanup` 或重新利用。**
新操作会开始下一笔事务，增加判断难度。导出本身只使用 ADB shell，不要求 Root。

如果设备上的 `xpad3` 还是旧版，可以只覆盖 CLI 文件；这不会重跑利用链：

```sh
adb push xpad3 /data/local/tmp/xpad3
adb shell chmod 700 /data/local/tmp/xpad3
```

然后立即收集：

```sh
adb wait-for-device
adb shell mkdir -p /sdcard/xpad3-logs
adb shell /data/local/tmp/xpad3 status
adb shell /data/local/tmp/xpad3 logs export /sdcard/xpad3-logs
adb pull /sdcard/xpad3-logs
```

`status` 出现 `transaction ... was interrupted` 是预期证据，不要因此先执行修复。
找到刚生成、时间最新的 `xpad3log-*.zip`。

### 5.1 临时 Root 阶段重启

如果屏幕在 holder 等待、IonStack 输出或“临时 Root”期间重启，重点发送 ZIP 中：

- `diagnostics/summary.json`：记录中断事务和前后 boot ID；
- `transactions/<事务号>/events.jsonl`：查看最后一条 `root-holder`、`root-runner` 或
  `root` 事件；
- `transactions/<事务号>/raw.log`：runner 的逐行耐久输出，最后几行通常最有价值；
- `diagnostics/boot-reason.txt`、上一 boot logcat、DropBox、pstore/last_kmsg。

`root-holder` 的 `attempt` 表示重启前进行到第几轮 holder；没有最终
`root=active`/`verification=su -c id` 事件，就不能把旧 success 文件当成成功。

### 5.2 KSU late-load 阶段重启

ZIP 会保留中断事务中的 `ksu-late-load-stages.jsonl`，按最后阶段判断：

- 最后是 `init-module-enter`，且没有 `init-module-returned`：重启发生在内核模块初始化调用内；
- 已有 `init-module-returned=success`，但没有 `complete`：继续检查 SELinux、脚本、
  userspace 安装或 Manager 重启阶段；
- 已有 `runtime-verified`：KSU 本身已通过锁定身份验证，重启点在更后的事务步骤；
- 出现 `loader-trace-unavailable`：使用的是不支持内部阶段记录的旧 ksud，只能结合
  CLI 外层事件和系统日志判断。

不要在同一 boot 内重复 late-load，也不要在线卸载或替换已经驻留的 KSU 模块。

导出还会同时尝试当前/上一 boot 的 logcat、DropBox kernel/restart 记录、pstore、
`/proc/last_kmsg`、AEE/MRDUMP 目录清单，以及 MTK DebugLogger 最近三个
`APLog_*` 中的 `last_kmsg` 和 `mblog_history`。AEE 数据目录通常不允许 shell
直接读取，所以清单显示 `Permission denied` 并不代表没有异常记录；DebugLogger 的
`last_kmsg` 是重要的非 Root 兜底渠道。

日志会做常见序列号和凭据脱敏，并限制 DebugLogger 单文件大小。导出后仍应人工
检查，再发送给他人。最少应提供完整 ZIP，而不是只截取 Manager 报错截图。
