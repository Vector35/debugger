# 任务:给 x2winstub 加 `ReadMemoryRequest` 处理,修复 attach 后 Binja 反汇编/hex view 全部显示 "????" 的问题

## 背景

BN 这边(`X2WinRpcAdapter::ReadMemory`)一直是空桩子,直接 `return DataBuffer();`。attach 上之后,
Binja 会切换到实时内存视图,这个视图的每个字节都要靠 `ReadMemory` 现读,读不到就显示成 "??"。这就是
你观察到的"连上之后原来解析好的二进制都变成 ????"的根因——不是解析结果坏了,只是实时内存视图一个
字节都读不上来。

已经在 Mac 这边把 BN core 端补上了(`protocol/x2win.proto` 和
`core/adapters/x2winrpcadapter.cpp` 已经改完、编译过了),跟 `Attach`/`Go`/`SetBreakpointRequest`
是同一套 `CallSync`(发 Request、按 `request_id` 等 Response)的模式,新增了两个消息:

```protobuf
// Envelope 的 oneof 里新增:
ReadMemoryRequest read_memory_request = 109;
ReadMemoryResponse read_memory_response = 309;

// 新增的消息定义:
// Reads raw bytes from the target's address space (equivalent of ReadProcessMemory). Unlike
// Go/Launch/Attach, this is a plain synchronous request/response -- there is no separate async
// event involved. A partial or failed read (e.g. address not mapped) is reported as
// success=false with an empty `data`, not a short `data` buffer -- callers should not try to
// use a truncated result.
message ReadMemoryRequest {uint64 address = 1; uint64 size = 2;}
message ReadMemoryResponse {bool success = 1; bytes data = 2;}
```

把这份 `.proto` 同步到你本地(跟之前 `Go`/`SetBreakpoint` 那几次一样,对一下 `git diff`,确认字段号
`109`/`309` 没有跟你本地已有的其他改动冲突),重新生成一下 `x2win.pb.h`/`x2win.pb.cc`。

## 这次要做的事

在 `HandleClient` 里(跟 `kGoRequest`/`kSetBreakpointRequest` 挨着的 `switch (request.body_case())`
那个地方)加一个新 `case`:

```cpp
case x2win::Envelope::kReadMemoryRequest: {
    const auto& req = request.read_memory_request();
    auto* resp = response.mutable_read_memory_response();

    std::vector<uint8_t> buffer(req.size());
    SIZE_T bytesRead = 0;
    bool ok = ReadProcessMemory(pi.hProcess, (LPCVOID)req.address(), buffer.data(), req.size(), &bytesRead)
        && bytesRead == req.size();

    if(ok){
        // 见下面"断点隐藏"那一段——这里读到的原始字节里,如果覆盖了我们自己下的软件断点地址,
        // 要把 0xCC 换回原字节,不能直接把 patch 过的内存原样发回去。
        RestoreBreakpointBytesInBuffer(buffer.data(), req.address(), req.size());
        resp->set_success(true);
        resp->set_data(buffer.data(), buffer.size());
    }else{
        resp->set_success(false);
    }
    break;
}
```

这里跟 `kSetBreakpointRequest` 用的应该是同一个 `pi.hProcess`(你之前给 `SetBreakpoint`/
`VirtualProtectEx`/`WriteProcessMemory` 传的那个句柄)——如果 `SetBreakpointRequest` 现在的写法里
访问 `hProcess` 用的是别的变量名/别的存取方式(比如存在某个全局 `g_processHandle` 里,或者包在某个
连接/会话结构体里),照抄那个已有的方式就行,不用引入新的存储方式。

**不需要**像 `GoRequest` 那样搞跨线程唤醒(`g_resumeSignal` 那一套)——`ReadProcessMemory` 没有
`WaitForDebugEvent`/`ContinueDebugEvent` 那种"必须在调试循环线程里调用"的限制,可以直接在
`HandleClient` 线程里同步调用、同步回复,跟 `kGetTargetArchRequest`、`kSetBreakpointRequest` 一样简
单直接。

### 断点隐藏(重要,容易漏)

如果当前已经有软件断点下在被读的地址范围内(不管是靠 `g_breakpointArmed`/`g_breakpointAddress` 那
种单断点变量,还是你现在可能已经升级成的一个断点表),内存里那个位置实际存的是我们自己 patch 上去
的 `0xCC`,不是目标程序真正的指令字节。如果原样把这段内存发给 Binja,反汇编出来那条指令会显示成
`int3`,而不是原来那条指令——这是所有调试器实现软件断点都要处理的经典坑。

写一个小helper,在把 `ReadProcessMemory` 读到的 buffer 发出去之前,检查请求的 `[address, address+size)`
范围里有没有落在任何一个已下断点的地址上,有的话把 buffer 里对应偏移的那个字节换成断点表里存的
`original byte`:

```cpp
void RestoreBreakpointBytesInBuffer(uint8_t* buffer, uint64_t address, uint64_t size){
    if(g_breakpointArmed && g_breakpointAddress >= address && g_breakpointAddress < address + size){
        buffer[g_breakpointAddress - address] = g_breakpointOriginalByte;
    }
    // 如果现在维护的是断点表(多个断点)而不是单个 g_breakpointAddress/g_breakpointArmed,
    // 这里改成遍历断点表,逻辑一样:命中就把该偏移换回 original byte。
}
```

具体用的是单断点变量还是断点表,以你现在 `debug_loop.cpp`/`main.cpp` 里实际的断点状态结构为准,不
用为了这个任务专门重构成表(除非现在已经是表了)。

### 大小上限

不用加请求大小的上限检查或者分块读取——`req.size()` 由 BN 那边控制,Binja 的内存视图本来就是按小块
(通常几百字节到几 KB)分批请求的,不会一次要一个夸张的大小,这次不用为了防御性而加这些代码。

## 这次不用管的部分(明确超出范围)

- **`WriteMemory`**:还是空的,这次只做读,不做写。
- **多线程并发读**:多个 `ReadMemoryRequest` 并发到达時如果 `HandleClient` 本来就是每个连接一个
  线程/每个请求同步处理,`ReadProcessMemory` 本身是线程安全的,不用加额外的锁;如果你现在的
  `HandleClient` 架构对同一个连接是单线程顺序处理请求的,那这里天然不会有并发问题,不用画蛇添足。
- **模块基址/`GetModuleList`**:这是下一步的任务,不在这次范围内。

## 验证方法

写测试客户端(复用之前验证 `Go`/`SetBreakpointRequest` 那个):

1. 连接 → `LaunchRequest` 或 `AttachRequest` 起个目标(比如还是 `helloworld.exe`)→ 收到
   `TargetStoppedEvent{reason: STOP_REASON_INITIAL_BREAKPOINT}`
2. 发一个 `ReadMemoryRequest{address: <入口点或任意已知地址>, size: 16}`,应该收到
   `ReadMemoryResponse{success: true, data: <16字节>}`,把这 16 字节跟"这台机器上直接用其他工具
   (比如 `x64dbg`/`WinDbg`)看到的同一地址内容"或者跟磁盘上 PE 文件对应位置的原始字节对一下,确认
   读出来的东西是对的。
3. 发一个明显没映射的地址(比如 `0x1`),应该收到 `ReadMemoryResponse{success: false}`,`data` 为
   空,而不是进程崩了或者卡死。
4. 用 `SetBreakpointRequest` 在某个地址下个断点,然后马上对同一个地址发 `ReadMemoryRequest`,确认
   读回来的第一个字节是原始指令字节,**不是** `0xCC`——这是最容易漏掉、也最值得单独确认一遍的一步。
5. 把测试客户端完整的收发日志、`x2winstub.exe` 的完整 stderr 日志发回来对一下。
