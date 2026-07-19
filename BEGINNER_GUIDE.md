# xpad3-cli 设备端使用指南

v0.1.4 只支持已经验证的 `TALIH-PD3S` `/338`。看到同为 Android 13 或 5.x 内核，不代表可以绕过 profile 检查。

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

或者执行一次普通重启。不要在同一 boot 里强停或更新 `com.ionstack.trigger` 后继续叠加 Root 尝试。

v0.1.4 可以容忍中断事务遗留的、无守护进程的 root 所有
`/data/local/tmp/su`：CLI 会报告无法以 shell 身份删除它，Root 链在捕获
credential 后再以 root 身份原子替换。这个警告本身不需要循环重启。

## 4. 退出码 75

退出码 75 表示当前 boot 的状态不适合安全重试，例如：

- trigger 已驻留但 KSU 没有成功加载；
- 已加载的 KernelSU-family 模块不是锁定版本；
- boot ID 在事务中变化；
- 临时 Root 或 SELinux 无法安全收尾。

此时执行普通重启，再从 `status` 和 `doctor` 开始。不要循环运行 exploit。

## 5. 导出日志

如果 KSU late-load 过程中设备意外重启，等系统完全开机后不要先重跑 Root，直接导出：

```sh
adb shell mkdir -p /sdcard/xpad3-logs
adb shell /data/local/tmp/xpad3 logs export /sdcard/xpad3-logs
adb pull /sdcard/xpad3-logs
```

ZIP 会保留中断事务及 `ksu-late-load-stages.jsonl`。最后一条阶段如果是
`init-module-enter`、但没有 `init-module-returned`，说明重启发生在内核模块初始化
调用内；若已经返回，则继续看后续 userspace 阶段。

导出还会同时尝试当前/上一 boot 的 logcat、DropBox kernel/restart 记录、pstore、
`/proc/last_kmsg`、AEE/MRDUMP 目录清单，以及 MTK DebugLogger 最近三个
`APLog_*` 中的 `last_kmsg` 和 `mblog_history`。AEE 数据目录通常不允许 shell
直接读取，所以清单显示 `Permission denied` 并不代表没有异常记录；DebugLogger 的
`last_kmsg` 是重要的非 Root 兜底渠道。

日志会做常见序列号和凭据脱敏，并限制 DebugLogger 单文件大小。导出后仍应人工
检查，再发送给他人。
