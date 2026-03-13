# Steam API Tracer

一个基于 [Microsoft Detours](https://github.com/microsoft/Detours) 的 Steam API 追踪与 IPC 数据捕获工具。通过将自身伪装为 `steam_api64.dll` 代理 DLL，拦截游戏进程与 Steam 客户端之间的所有 API 调用及 IPC（进程间通信）数据包，并将其记录到日志文件中，方便开发者调试和分析 Steam 接口行为。

---

## 文件说明

| 文件 | 说明 |
|------|------|
| `steam_api_proxy.cpp` | 代理 DLL 主体，使用 Detours 钩住 `GetProcAddress`，拦截并记录 `SteamAPI_Init`、`SteamInternal_CreateInterface`、`SteamAPI_RegisterCallback` 等约 20 个关键 Steam API 函数，同时将其余函数转发给原始 DLL。 |
| `ipc_dump.cpp` | IPC 数据捕获模块，钩住 Steam 内部的回调分发函数（支持新旧两种 SDK 路径），将每条回调/调用结果的完整载荷以文本和二进制两种格式保存到文件。 |
| `ipc_dump.h` | `ipc_dump.cpp` 的头文件，声明对外接口。 |
| `generate_exports.py` | 从原始 `steam_api64_o.dll` 提取导出表，自动生成 `.def` 链接定义文件和 MASM x64 转发桩（`forwarded_exports.asm`）。 |
| `parse_ipc_dump.py` | 离线分析工具，解析 `ipc_payloads.bin` 二进制捕获文件，支持文本、JSON、统计及单包提取等多种输出模式。 |
| `build_detours.bat` | 编译 Microsoft Detours 库，生成 `Detours\lib.X64\detours.lib`。 |
| `build_msvc.bat` | 使用 MSVC 工具链一键构建整个代理 DLL。 |
| `Detours/` | Microsoft Detours 子模块。 |

---

## 工作原理

```
游戏进程
    │
    ▼
steam_api64.dll（本代理）
    ├─► steam_api_proxy.cpp  ── 拦截并记录 API 调用
    ├─► forwarded_exports.asm ── 其余函数直接转发
    └─► ipc_dump.cpp         ── 拦截并记录 IPC 回调载荷
            │
            ▼
    ipc_trace.log（可读文本）
    ipc_payloads.bin（二进制存档）
            │
            ▼
    parse_ipc_dump.py（离线分析）
```

运行时生成的文件：

- `steam_api_trace.log` — Steam API 调用日志（文本格式，超过 50 MB 自动截断）
- `ipc_trace.log` — IPC 回调/调用结果日志（文本格式）
- `ipc_payloads.bin` — IPC 载荷二进制存档（含 CRC32 校验）

---

## 构建

### 前提条件

- Windows 操作系统
- Visual Studio（含 MSVC 编译器、`ml64.exe`、`nmake`）
- Python 3（用于运行生成脚本）

### 步骤

**1. 初始化子模块（首次克隆后执行）**

```bat
git submodule update --init --recursive
```

**2. 编译 Detours 库（仅需执行一次）**

```bat
build_detours.bat
```

**3. 准备原始 DLL**

将游戏目录中的 `steam_api64.dll` 复制到本项目目录并重命名为 `steam_api64_o.dll`。

```bat
copy "C:\path\to\game\steam_api64.dll" steam_api64_o.dll
```

**4. 构建代理 DLL**

```bat
build_msvc.bat
```

构建脚本会依次执行以下步骤：

1. 调用 `generate_exports.py` 生成导出定义文件和转发桩汇编代码
2. 用 `ml64` 汇编 `forwarded_exports.asm`
3. 用 `cl` 编译 `steam_api_proxy.cpp` 和 `ipc_dump.cpp`
4. 用 `link` 链接生成最终的 `steam_api64.dll`

---

## 使用方法

**1. 部署代理 DLL**

将构建输出的 `steam_api64.dll` 替换到目标游戏目录中（原始 DLL 保留为 `steam_api64_o.dll`，放在同一目录下）。

**2. 运行游戏**

正常启动游戏，代理 DLL 会自动开始拦截并记录所有 Steam API 调用和 IPC 数据。

**3. 查看日志**

```bat
notepad steam_api_trace.log
notepad ipc_trace.log
```

---

## 解析 IPC 数据包

使用 `parse_ipc_dump.py` 分析捕获的二进制文件：

```bash
# 默认文本输出
python parse_ipc_dump.py ipc_payloads.bin

# 输出为 JSON 格式
python parse_ipc_dump.py ipc_payloads.bin --json

# 仅显示统计信息
python parse_ipc_dump.py ipc_payloads.bin --stats

# 只查看回调（C）或调用结果（R）
python parse_ipc_dump.py ipc_payloads.bin --filter C
python parse_ipc_dump.py ipc_payloads.bin --filter R

# 过滤特定回调 ID（例如 UserStatsReceived_t = 1101）
python parse_ipc_dump.py ipc_payloads.bin --callback 1101

# 将每条载荷提取为独立文件
python parse_ipc_dump.py ipc_payloads.bin --extract-dir ./payloads
```

---

## 注意事项

- 本项目仅支持 **64 位 Windows** 平台。
- 目前只针对 `steam_api64.dll`，暂不支持 32 位的 `steam_api.dll`。
- 本工具仅供学习、调试和研究使用，请勿用于违反 Steam 服务条款的用途。
