<div align="center">

# vmpunpack

**面向 x64 PE 恶意样本的通用 VMProtect / 加壳脱壳工具。**

[![CI](https://github.com/milk-analyzer/vmpunpack/actions/workflows/ci.yml/badge.svg)](https://github.com/milk-analyzer/vmpunpack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](#运行环境)

[English](README.md) · [Русский](README.ru.md) · **简体中文**

</div>

---

一条命令即可把加壳的 x64 PE 变成可加载、可分析的映像。

vmpunpack 在打过补丁的 [sogen](https://github.com/momo5502/sogen) 模拟器中运行样本——它能绕过那些让
VMProtect 在 any.run、CAPE 和真实机器上直接退出的反虚拟机与反调试检测——把壳代码驱动到**原始入口点
（OEP）**，在该处转储内存，重建可供 IDA/Ghidra 加载的 PE，并提取失陷指标（IOC）。

> **它只脱壳，不做反虚拟化。** 被 VMProtect 虚拟化的函数仍然是虚拟机字节码。你得到的是一个虚拟机原封
> 不动、但可以正常分析的映像，而不是 VMP 处理之前的原始汇编。

## 安装

```bat
git clone https://github.com/milk-analyzer/vmpunpack.git
cd vmpunpack
setup.cmd
```

`setup.cmd` 会下载本仓库不再分发的两个第三方组件，约 500 MB，只需一次：

- **模拟根环境**，来自 [sogen.dev](https://sogen.dev/root.zip)：模拟器启动时所依托的 Windows 用户态快照；
- **打过补丁的模拟器**，来自 [milk-analyzer/sogen](https://github.com/milk-analyzer/sogen/releases/tag/vmpunpack-1.0.1)，
  并以 SHA-256 固定校验。原版 sogen 无法使用——脱壳钩子位于模拟器中，而不在这份 Python 代码里——该构建
  采用 GPL-2.0，因此其源码已发布在同一 fork 的
  [`vmpunpack` 分支](https://github.com/milk-analyzer/sogen/tree/vmpunpack)。

随时可用 `setup.cmd --check` 校验已有安装，用 `--analyzer-url <zip>` 替换为你自己的构建。详见
[THIRD_PARTY.md](THIRD_PARTY.md)。

### 无网络的机器

`setup.cmd` 需要联网，因此对于隔离的分析虚拟机，请先在联网机器上安装，再把结果搬过去：

```bat
setup.cmd                              :: 在联网的机器上
setup.cmd --export bundle.zip          :: 约 150 MB，并打印 SHA-256
:: 把 bundle.zip 和一份仓库副本拷到虚拟机，然后：
setup.cmd --import bundle.zip --sha256 <打印出来的哈希>
```

`--import` 不会下载任何东西。直接在离线虚拟机上克隆仓库没有用：`sogen/` 与 `emu_root/` 并不在仓库里，
这正是 `setup.cmd` 存在的理由。

该归档是你自己下载的模拟根环境连同模拟器，为你自己的转移而重新打包。把它再转交他人不是我们的权利，
其中的 Microsoft 系统文件也不是你的权利。详见 [THIRD_PARTY.md](THIRD_PARTY.md)。

### 运行环境

Windows x64、Python 3.8+。除此之外别无依赖：本工具只使用标准库，以便在受限的分析虚拟机上直接运行。

## 使用

```bat
RUN_ME.cmd C:\samples\thing.exe
```

结果会输出到样本旁边的 `<sample>_unpacked\` 目录。

> **一次只处理一个样本。** `C:\dumps` 是硬编码在模拟器内的固定暂存路径，本机上的每次运行都共用它。
> 每次运行会持有 `C:\dumps\.lock` 锁，锁被持有期间第二个运行拒绝启动；崩溃遗留的锁会在超时之后被自动
> 接管。此外，最终发布的产物还会单独与产生它的那次运行绑定校验。

### 命令行参数

| 参数 | 含义 |
|---|---|
| `-o OUTDIR` | 输出目录（默认 `<sample>_unpacked`）；在转储通过校验后清除上次运行的产物，因此不能设为 `C:\dumps` |
| `--run-payload` | 越过 OEP 继续执行并记录行为，而不是在该处停下 |
| `--nodelay` | 消除用于对抗沙箱的 `NtDelayExecution` 休眠 |
| `--tsc 0x8000` | 每次调用按给定步长推进 rdtsc，压缩基于 rdtsc 的延时循环 |
| `--oep 0xRVA` | 手动指定 OEP 的 RVA，覆盖启发式判断 |
| `--late N` | 在 OEP 之后的第 N 个基本块再转储 `unpacked_late.bin` 与 `heap.bin`（运行时解密的配置）；需要配合 `--run-payload`，否则 OEP 之后根本不会执行任何基本块 |
| `--timeout SEC` | 运行时间上限，默认 300 |
| `--sogen DIR` / `--emuroot DIR` | 引擎路径，适用于把它们放在工作副本之外的情况 |

### 输出

| 文件 | 内容 |
|---|---|
| `<name>.unpacked.exe` | 重建后的 PE，入口点已设为真实的 OEP |
| `unpacked.bin` / `.meta` | 原始内存映像，以及基址、SizeOfImage、入口点和 OEP |
| `iocs.txt` | 域名、URL 与 IP，按每个转储分节列出 |
| `unpacked_late.bin`、`heap.bin` | 仅在使用 `--late` 时生成 |

重建出的 PE 是**用于分析**的映像：它的导入表中保存的是模拟器地址，因此在不做 Scylla 式 IAT 重建的情况
下，不保证能在别处运行。

IOC 提取会把每个转储分别按单字节文本和两种对齐方式的 UTF-16 各读一遍，因此宽字符串中的 URL 和 IP 同样
能被找到。主机名会与一份带锚定的已知噪声域名列表比对；像 `windows-defender-update[.]top` 这种只是看着
像微软的 C2 会被如实报告，而不会被过滤掉。

## 工作原理

1. **`unicorn` 后端配合 `--no-inst-precision`。** sogen 默认为每条指令挂钩；放开 TCG 的 JIT 之后，壳代
   码连同解压过程大约两分钟即可跑完，而不是永远跑不完。
2. **OEP 识别。** 在样本的原始代码段上挂执行钩子——即不包含壳入口点、RVA 最小的可执行段。首次命中该段
   即为 OEP，该地址取自样本自身的 PE 头。这是一个没有旁证的启发式判断，因此 vmpunpack 会校验结果：报告
   OEP 落在哪个段，若该段不可执行、或 OEP 与壳入口点相同则发出警告，并拒绝发布 OEP 所在页为空的映像。
   带警告的结果应视为可疑，而不是脱壳成功。
3. **序号导入补洞。** 扫描导入表中的 `#ORD` 条目；如果模拟根环境里的 DLL 对该序号留有空的导出槽位，就
   把它指向一个 `ret` 桩，使客户机加载器能够解析。否则新样本会以 `STATUS_ORDINAL_NOT_FOUND`
   （`C0000138`）失败。

## 样本看到的环境

模拟根环境是 **GitHub Actions Windows 运行器**的快照，因此从内部看，客户机就是一台 Hyper-V 虚拟机，而且
毫不掩饰：`SYSTEM` 注册表配置单元里有数百条 `Hyper-V`、`VMBus` 与 `Azure` 记录，`USERNAME` 为
`runneradmin`，`COMPUTERNAME` 是形如 `runnervm…` 的字符串，且每次上游重建都会变化。vmpunpack 会把样本
放到下载文件通常会落到的位置，而不是单独的目录，但这并不能伪装环境本身。

这对具备反分析能力的样本很关键。如果某个样本立即退出、干净收场却没有转储，或者行为与在沙箱中不同，请先
假设它识别出了虚拟机，而不是先怀疑 vmpunpack 出错。`--nodelay` 与 `--tsc` 能绕过基于时间的检测，但绕不过
基于环境的检测。

如果你需要一个不像 CI 的环境，请用 sogen 的
[`grab-registry.bat`](https://github.com/momo5502/sogen/blob/main/src/tools/grab-registry.bat) 从你自己
掌控的机器上生成模拟根环境，并用 `--emuroot` 指向它。这会同时替换用户名、计算机名和硬件痕迹——这也正是它
比单纯改名更有效的原因。

## 局限

- 它不是反虚拟化工具。
- 整程序虚拟化、多阶段加载器以及 TLS 回调技巧，可能需要 `--oep`、`--late`、更大的 `--timeout`，或者手工
  处理。
- **实时 C2 通常只在运行期存在**（例如通过 DoH 解析），不会出现在转储里。`--run-payload` 只能尽力而为：
  模拟器没有真实网络。
- 仅支持 x64。32 位目标会被直接拒绝，而不是错误解析。
- 如果壳在跳转到 OEP 之前抹掉了自己的头部页，就无法重建可加载的 PE；此时仍会写出原始的 `unpacked.bin`
  和 `.meta`，供手工重建使用。

## 项目

[参与贡献](CONTRIBUTING.md) · [安全策略](SECURITY.md) · [更新日志](CHANGELOG.md) ·
[第三方许可](THIRD_PARTY.md)

测试既不需要引擎也不需要样本——所有测试数据都是在内存中构造的合成 PE：

```bat
py -3 tests\run_tests.py
py -3 tests\run_tests2.py
powershell -ExecutionPolicy Bypass -File tests\launcher.ps1
```

本仓库中的驱动程序与启动脚本采用 MIT 许可。它所下载的模拟器和模拟根环境各自适用其自身的许可，详见
[THIRD_PARTY.md](THIRD_PARTY.md)。
