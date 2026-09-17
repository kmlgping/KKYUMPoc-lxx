# KKYUM.sys 漏洞驱动分析

> 本文为个人学习研究笔记，仅用于游戏安全研究与反外挂防御建设。样本为漏洞驱动（BYOVD），请勿将其用于任何非法用途。

## 0x00 样本信息

| 属性 | 值 |
|---|---|
| 文件名 | KKYUM.sys |
| 架构 | x64 内核驱动 |
| 镜像基址 | 0x140000000 |
| 镜像大小 | 0x9000（很小，只有 58 个函数） |
| MD5 | `8516410b49bb79c08c19a37c516dad72` |
| SHA256 | `72bd55f4459c992b9caa1a33cb6862f1f3085ca35839c58dee8b75db22ca605f` |
| 分析环境 | IDA Pro + Hex-Rays（IDB: KKYUM.sys.i64） |

一句话定性：**这是一个典型的 BYOVD（Bring Your Own Vulnerable Driver）漏洞驱动**。它本身没有签名校验、没有访问控制，加载后任何普通用户态程序只要打开 `\\.\KKYUM` 设备，就能指挥内核干脏活：读写任意进程内存、伪造键盘鼠标输入、隐藏窗口、对抗截屏取证。

---

## 0x01 全局概览

驱动加载后做的事非常直白：

- 创建设备 `\Device\KKYUM`，符号链接 `\DosDevices\KKYUM`
- IRP_MJ_CREATE / IRP_MJ_CLOSE 走一个"什么都不做"的分发例程（放行所有打开请求）
- IRP_MJ_DEVICE_CONTROL 指向核心分发器 `DispatchIoctl_1400015C0`（1813 字节，13 个 IOCTL）
- 卸载函数只删符号链接和设备对象，**不清理任何钩子/引用**

DriverEntry 伪代码（IDA 反编译）：

```c
__int64 __fastcall DriverEntry_140001180(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  IoCreateDevice(DriverObject, 0, &DeviceName, 0x22u, 0x100u, 0, &DeviceObject);
  IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);   // \DosDevices\KKYUM
  IoSetDeviceInterfaceState(RegistryPath, 1u);
  DriverObject->MajorFunction[0]  = DispathRoutine_140001160;   // IRP_MJ_CREATE 放行
  DriverObject->MajorFunction[14] = DispatchIoctl_1400015C0;    // IRP_MJ_DEVICE_CONTROL
  DriverObject->MajorFunction[2]  = DispathRoutine_140001160;   // IRP_MJ_CLOSE
  DriverObject->DriverUnload = DriverUnload_140001D50;
  DeviceObject->Flags |= 0x10u;      // DO_BUFFERED_IO
  DeviceObject->Flags &= ~0x80u;     // 清掉 DO_DIRECT_IO
  return 0;
}
```

注意两个细节：

1. **DO_BUFFERED_IO 置位、DO_DIRECT_IO 清除** —— 所有非 MDL 的 IOCTL 都走 SystemBuffer。
2. 设备类型 `0x22`（FILE_DEVICE_UNKNOWN）+ 无安全描述符 = 任何用户都能打开。

---

## 0x02 通信协议：可选项的 XOR 加密

驱动维护一对全局变量：

- `byte_140005100`：密钥内容（最多 256 字节）
- `Key_140005200`：密钥长度

规则很简单：

1. `0x222640` 用于设置密钥（1~256 字节），**这一包本身是明文**（此刻密钥还没建立）。
2. 之后每个 IOCTL handler 开头都有一个同款循环，把 SystemBuffer 按下式"解密"：

```c
// 加解密同一个函数，对称 XOR
for (i = 0; i < len; ++i)
    buf[i] ^= key[i % keyLen];
```

3. **密钥未设置（长度=0）时驱动直接跳过解密 => 全程明文通信**。所以从逆向角度看这层"加密"形同虚设，它唯一的用途是躲避基于 IOCTL 内容明文特征的网络/ETW 检测。
4. 两个例外值得注意：
   - `0x222658` / `0x22265C`（批量读写内存）的输入**永远明文**，驱动不解密；
   - `0x222654` / `0x222650`（查 PID/模块基址）的**应答会被重新加密一遍**，R3 侧需要再做一次同样的 XOR 才能读到结果。

---

## 0x03 IOCTL 全表

| IOCTL | 功能 | 输入格式 | 加密 | 备注 |
|---|---|---|---|---|
| `0x222640` | 设置 XOR 密钥 | 密钥字节 1~256B | 明文 | 通信的"握手" |
| `0x222644` | 安装键鼠注入基础设施 | 无 | - | 偷 kbdclass/mouclass 的 ClassService 回调 |
| `0x22264C` | 模拟键盘按键 | 12B `KEYBOARD_INPUT_DATA` | 密文 | 直接喂 kbdclass |
| `0x222648` | 模拟鼠标事件 | 24B `MOUSE_INPUT_DATA` | 密文 | 直接喂 mouclass |
| `0x222624` | DWM 防截屏开关 | 16B `{HWND, Flags}` | 密文 | 调未导出函数 GreProtectSpriteContent |
| `0x222620` | 隐藏窗口 | 16B `{HWND}` | 密文 | PWND 双向链摘除 |
| `0x22261C` | 窗口挂回 | 16B `{HWND_A, HWND_B}` | 密文 | 摘除的逆操作 |
| `0x222654` | 按进程名查 PID | 520B `{WCHAR name[256]; u64 pid}` | 密文 | **应答也是密文** |
| `0x222650` | 按模块名查基址 | 528B `{u64 pid; WCHAR name[256]; u64 base}` | 密文 | **应答也是密文**，支持 Wow64 |
| `0x222658` | 批量写目标进程内存 | 8B 头 + N×24B 条目 | **明文** | MmCopyVirtualMemory 循环 |
| `0x22265C` | 批量读目标进程内存 | 8B 头 + N×24B 条目 | **明文** | 同上，方向相反 |
| `0x222662` | MDL 大块写 | 32B 头（密文）+ MDL 数据（密文） | 密文 | METHOD_OUT_DIRECT |
| `0x222666` | MDL 大块读 | 32B 头（密文）+ MDL 缓冲 | 密文 | 应答密文 |

---

## 0x04 逐个拆解

### 4.1 任意内存读写（核心能力）

批量读写共用一个模式：先 `PsLookupProcessByProcessId` 拿到目标 EPROCESS，再用 `IoGetCurrentProcess()` 拿自己的，然后循环调 `MmCopyVirtualMemory`：

```c
// IOCTL 0x22265C 读：目标进程 -> 当前进程
MmCopyVirtualMemory(
    TargetProcess,      Entries[k].SourceAddress,   // 从哪读
    CurrentProcess,     Entries[k].DestinationAddress,
    Entries[k].Size,
    0,                  // PreviousMode = KernelMode（绕过用户态地址检查策略）
    &ReturnSize);
```

请求体结构（读/写条目字段方向相反）：

```c
struct KK_RW_HEADER {        // 8 字节
    uint32_t ProcessId;      // +0x00 目标进程
    uint32_t Count;          // +0x04 条目数
};
struct KK_READ_ENTRY {       // 24 字节（0x22265C）
    uint64_t SourceAddress;      // 目标进程内的源地址
    uint64_t DestinationAddress; // 本进程内的落点
    uint64_t Size;
};
struct KK_WRITE_ENTRY {      // 24 字节（0x222658）
    uint64_t TargetAddress;      // 目标进程内的目的地址
    uint64_t SourceAddress;      // 本进程内的数据地址
    uint64_t Size;
};
```

几个安全细节（都是漏洞点）：

- **没有对目标地址做任何校验**，Size 完全由攻击者控制；
- 用 EPROCESS 直接引用 + `PreviousMode=KernelMode`，完全绕开句柄权限体系，`ObRegisterCallbacks` 这类句柄级防护**根本看不到它**；
- `0x222662/0x222666` 的 MDL 版本还会把 32 字节头部存进全局 `xmmword_140005480/490`，MDL 数据经 `sub_140001DE4`（就是那个 XOR 循环）解密/加密后写入目标进程，适合大块镜像搬运。

### 4.2 键鼠注入：偷换 kbdclass/mouclass 的输入源

`0x222644` 触发 `InitPhysicalDeviceInformations_1400020A4`：

1. `ObReferenceObjectByName(L"\\Driver\\WMIxWDM")` —— 借一个 WDM 驱动对象当"入口跳板"；
2. 在其设备栈上按名字定位 `\Driver\kbdclass` / `\Driver\mouclass`；
3. 对键盘侧（`Init_kbdclass_140002244`）：先探测 `\Driver\i8042prt`（PS/2）或 `\Driver\kbdhid`（USB）哪个存在，拿到物理端口设备，然后沿 `AttachedDevice` 链找到挂在它上面的 kbdclass 设备。

最野的一段来了——定位 ClassService 回调的方式是**在 DeviceExtension 里逐字节滑动暴力扫描**：

```c
// Init_kbdclass_140002550 摘录
for ( j = 0; j < 4096; ++j )
{
    if ( !MmIsAddressValid(DeviceExtension) ) break;
    v11 = *DeviceExtension;
    if ( *DeviceExtension == i )                    // 指向 kbdclass 设备对象 -> ClassDeviceObject
        KeyboardDevice_1400054C0 = i;
    else if ( v11 > DriverStart &&                  // 指向 kbdclass 驱动镜像内部
              v11 < DriverStart + DriverSize )      // -> 那就是隐藏的 ClassService 回调
        KeyboardClassServiceCallback_1400054C8 = v11;
    DeviceExtension = (PVOID *)((char *)DeviceExtension + 1);  // 一次挪 1 字节
}
```

拿到回调地址之后，`0x22264C`/`0x222648` 就能"直录直放"：

```c
// KeyboardClassServiceCallback_140002138
KbdInData = ExAllocatePool(NonPagedPool, 0x7C);          // 键盘池 0x7C
*KbdInData = *Arg_KbdInData;                             // 拷入 12B KEYBOARD_INPUT_DATA
ClassService(KeyboardDevice, KbdInData, KbdInData+1, &consumed);  // 直接调真回调
```

效果：伪造的输入与真实键盘记录在内核层面**完全无法区分**（同一个池、同一个回调、同一条路径），R3 层的 `SendInput` 钩子、低级键盘钩子全部失效。这就是"硬件级外挂"的软件实现思路。

### 4.3 DWM 防截屏：签名扫描挖未导出函数

`0x222624` 的前置初始化 `Init_ProtectWindow_140001000` 是个教科书级的 win32k 攻击链：

1. 找到 `winlogon.exe` 的 PID，`KeStackAttachProcess` 附进去（GUI 子系统内核对象只在有窗口站的任务上下文里有效）；
2. `GetKernelModule_140001234` 拿 `win32kbase.sys` 基址，`RtlFindExportedRoutineByName` 解出导出函数 `ValidateHwnd`；
3. 再拿 `win32kfull.sys`，在其 `.text` 节里跑通配符签名扫描：

```
E8 ? ? ? ? 8B ? 85 C0 75 0E
```

这是某个 `call GreProtectSpriteContent` 调用点的特征（call + 测试返回值 + 条件跳转）。扫到后解出 E8 相对调用目标：

```c
GreProtectSpriteContent_140005208 = &v4[v4[1] + 5];   // E8 的 rel32 解析
```

4. 真正调用时硬编码 `r8d=1`：

```c
// GreProtectSpriteContent_140001F68 wrapper
result = RealGreProtectSpriteContent(0, HWND, 1, Flags);
```

效果：对指定 HWND 开启 DWM 精灵内容保护，之后截图/录屏/OBS/远程桌面抓到的都是黑块。这是外挂窗口的"防审计"手段，让取证截图失效。

### 4.4 窗口隐藏：PWND 双向链摘除

`0x222620` → `ProtectWindow_140001F04`：

```c
Wnd = ValidateHwnd(hwnd);
if (Wnd == Wnd->previous->next && Wnd == Wnd->next->previous) {
    Wnd->previous->next = Wnd->next;    // 标准双向链 unlink
    Wnd->next->previous = Wnd->previous;
    // 注意：自身 +0x58/+0x60 不清零，保留旧邻居以便挂回
}
```

效果与 `ShowWindow(SW_HIDE)` 的区别：**不产生任何窗口消息**，R3 的消息钩子全程无感知；`EnumWindows`/`GetWindow`/Z 序遍历全部看不到该窗口，但窗口对象仍存活。

`0x22261C` → `ProtectWindow_140001E1C` 是逆操作：把已摘除的 A 插到 B 后面（`A->next = B->next; B->next = A; A->prev = B`），并强校验 A 必须已脱离原链防止打环。有意思的瑕疵：它**没有回写 B 原后继的 spwndPrev 指向 A**，所以反向遍历会跳过 A —— 驱动作者自己都没把链表维护对称。

### 4.5 侦察函数

- `GetProcessId_1400014D0`：`ZwQuerySystemInformation(SystemProcessInformation)` 两段式（先探长度再分配 NonPagedPool）全量枚举，逐项 `RtlCompareUnicodeString` 匹配进程名，返回 PID（找不到返回 -1）。
- `GetProcessModuleBase_140001360`：`PsLookupProcessByProcessId` → `KeStackAttachProcess` → 遍历 `PEB->Ldr.InLoadOrderModuleList` 匹配模块名返回 DllBase；32 位目标进程走 `PsGetProcessWow64Process` 拿 PEB32 后按 32 位偏移遍历。用途是定位 ntdll/kernelbase 等模块后，配合内存写改代码段。

---

## 0x05 攻击链拼图

把这些能力拼起来，就是一条完整的内核级外挂工作流：

```
[踩点]  0x222654 查游戏 PID
        └─> 0x222650 查游戏模块基址
             └─> 0x22265C/0x222666 读内存定位特征码

[搞事]  0x222658/0x222662 写内存：patch 游戏逻辑/瘫反作弊模块
        └─> 0x222644 + 0x22264C/0x222648 伪造键鼠输入（内核直喂，钩子无效）

[隐身]  0x222620 隐藏外挂窗口（无消息、遍历不可见）
        └─> 0x222624 DWM 防截屏（取证截图全黑）

[掩护]  0x222640 设置 XOR 密钥，让 IOCTL 流量避开明文特征检测
```

全程不需要 SeDebugPrivilege，不需要打开目标进程句柄，一切在内核完成。

---

## 0x06 检测与防御思路

### R3 / EDR 可落地的检测点

1. **设备访问**：监控对 `\Device\KKYUM`（符号链接 `\DosDevices\KKYUM`）的 CreateFile + DeviceIoControl，`0x222640`（设密钥）和 `0x222644`（装键鼠基础设施）是强特征，可以直接拦截/告警。
2. **驱动加载**：BYOVD 的根子是"漏洞驱动能被普通进程加载"。维护漏洞驱动黑名单（参考微软的 Microsoft vulnerable driver blocklist），内核侧对驱动加载事件做哈希比对。
3. **键鼠注入特征**：
   - `ObReferenceObjectByName` 对 `\Driver\kbdclass`/`\Driver\mouclass`/`\Driver\WMIxWDM` 的非常规引用（ETW 内核回调可见）；
   - kbdclass!ClassService 被调用时，调用栈中出现非键盘驱动的返回地址；
   - 输入数据池分配来源异常。
4. **内存读写**：`MmCopyVirtualMemory` 的调用方为白名单外驱动即告警；对高价值进程，内核侧定期校验代码段完整性（应对 0x222658/0x222662 的 patch）。
5. **窗口隐匿**：窗口对象存活但不在父窗口兄弟链上——从内核遍历 PWND 可校验一致性。
6. **防截屏**：win32kfull.sys 的 `.text` 出现第三方模块的签名扫描行为（该驱动 attach winlogon + 读 win32k 模块头本身就是强信号）；游戏窗口出现 DWM sprite 锁定属性。

### 驱动自身的缺陷清单（逆向视角）

- 无任何访问控制（无安全描述符、无进程白名单）；
- XOR "加密"密钥由客户端任意指定，等于没有；
- DeviceExtension 暴力扫描 4096 次的行为在 MmIsAddressValid 缺页或并发时可能引发稳定性问题；
- 窗口挂回操作不维护反向指针，链表不对称；
- 卸载时不回收键鼠基础设施（无恢复路径）；
- `GetProcessModuleBase_140001360` 在 Wow64 分支返回值直接用了外层 `status`（`PsLookupProcessByProcessId` 的返回值），逻辑上是凑合能跑但并不严谨。

---

## 0x07 结语

KKYUM.sys 是一个功能完整、代码粗糙的 BYOVD 样本：XOR 通信层只是薄薄一层面纱，真正有价值的是它把"内核外挂"所需的四类原语——**任意读写、输入伪造、窗口隐匿、截屏对抗**——全部封装成了十几个 IOCTL。对防御方而言，最重要的结论是：**这类威胁的检测主战场必须前移到内核**（驱动加载管控 + 内核回调监控），等 R3 层看到伪装成"真实键盘记录"的输入或消失的窗口时，一切都已经发生了。

（完）

---

*IOC 摘要：设备名 `\\.\KKYUM`；签名特征 `E8 ?? ?? ?? ?? 8B ?? 85 C0 75 0E`（win32kfull .text 扫描）；字符串 `\Driver\WMIxWDM`、`\Driver\kbdclass`、`\Driver\mouclass`、`ValidateHwnd`、`win32kbase.sys`、`win32kfull.sys`；SHA256 见 0x00。*
