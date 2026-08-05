# spark-source

对 `Spark1.5.2F.exe` 的可复现静态还原工作区。

本仓库只记录二进制结构、受保护入口、导入面、资源索引、分析脚本和已确认的 C 级源码模型，不讨论程序面向的具体业务。

## 当前结论

输入文件是 **32 位原生 Windows PE GUI 程序**，不是 .NET 程序。原始 `.text`、`.rdata`、`.data` 在磁盘中的原始大小均为 0；入口先跳入高熵保护区，再构造三字段帧并进入统一调度器。静态扫描确认至少 14 个包装节点直接进入同一调度器。

仓库中的源码是基于 PE 头和已确认机器码重建的分析模型，不冒充完整原始工程。原始函数名、变量名、注释、项目结构及受保护函数体无法仅凭当前磁盘镜像无损恢复。

## 目录

- `docs/analysis-report.md`：第一阶段静态分析报告；
- `docs/recovery-status.md`：已有成果和当前缺口；
- `docs/HANDOFF_LATEST_20260805.md`：最新交接与下一阶段验收条件；
- `data/`：已有 PE、导入表、资源与反汇编证据；
- `evidence/dispatcher-xrefs.json`：统一调度器直接跳转索引；
- `src-recovered/`：早期入口伪代码和结构定义；
- `src/recovered/`：通过 CMake 编译验证的 C 级源码模型；
- `tools/`：无第三方依赖的分析、资源提取和跳转扫描脚本。

## 输入校验

```text
SHA256  8ba74270a14218bd0713a31bd4601d69824b742770c641c346b199239362e2d8
MD5     162831ceba8ffb3ed573f0306455d559
```

## 复现静态结果

```powershell
python tools\analyze_pe.py .\Spark1.5.2F.exe --out .\analysis-output
python tools\locate_virtualized_stubs.py .\Spark1.5.2F.exe --dispatcher 0x58b0b0d -o .\dispatcher-xrefs.json
```

## 构建源码模型

源码模型用于持续标注、交叉验证和后续函数级恢复，不会生成原程序：

```powershell
cmake -S . -B build
cmake --build build --config Release
```
