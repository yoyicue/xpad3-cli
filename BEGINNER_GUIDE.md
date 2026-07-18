# xpad3-cli 设备端使用指南

v0.1.2 只支持已经验证的 `TALIH-PD3S` `/338`。看到同为 Android 13 或 5.x 内核，不代表可以绕过 profile 检查。

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

## 4. 退出码 75

退出码 75 表示当前 boot 的状态不适合安全重试，例如：

- trigger 已驻留但 KSU 没有成功加载；
- 已加载的 KernelSU-family 模块不是锁定版本；
- boot ID 在事务中变化；
- 临时 Root 或 SELinux 无法安全收尾。

此时执行普通重启，再从 `status` 和 `doctor` 开始。不要循环运行 exploit。

## 5. 导出日志

```sh
adb shell mkdir -p /sdcard/xpad3-logs
adb shell /data/local/tmp/xpad3 logs export /sdcard/xpad3-logs
adb pull /sdcard/xpad3-logs
```

日志会做常见序列号和凭据脱敏。导出后仍应人工检查，再发送给他人。
