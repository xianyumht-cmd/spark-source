# spark-source

对 `Spark1.5.2F.exe` 的可复现静态还原工作区。

本仓库只记录二进制结构、受保护入口、导入面、资源索引、分析脚本和已确认的 C 级源码模型，不讨论程序面向的具体业务。

## 当前结论

输入文件是 **32 位原生 Windows PE GUI 程序**，不是 .NET 程序。原始 `.text`、`.rdata`、`.data` 在磁盘中的原始大小均为 0；入口先跳入高熵保护区，再构造三字段帧并进入虚拟机调度层。

第二阶段静态扫描已经识别：

- 514 个按字节异或 `0x11` 保存的动态 API 名称；
- 17 个资源条目；
- 101 个固定结构的虚拟机入口桩；
- 6 个公共调度器；
- 12 个虚拟目标族；
- 89 个携带非零数据槽的入口。

仓库中的源码是基于 PE 头和已确认机器码重建的分析模型，不冒充完整原始工程。原始函数名、变量名、注释、项目结构及受保护函数体无法仅凭当前磁盘镜像无损恢复。

## 目录

- `docs/analysis-report.md`：第一阶段静态分析报告；
- `docs/STATIC_RECOVERY_STAGE_2.md`：第二阶段静态恢复、验收结果和动态采集入口；
- `docs/recovery-status.md`：已有成果和当前缺口；
- `docs/HANDOFF_LATEST_20260805.md`：交接与下一阶段验收条件；
- `data/`、`analysis/`：PE、导入、资源、虚拟机入口统计与反汇编证据；
- `evidence/dispatcher-xrefs.json`：首个统一调度器的直接跳转索引；
- `src-recovered/`：早期入口伪代码和结构定义；
- `src/recovered/`：通过 CMake 编译验证的 C 级源码模型；
- `tools/analyze_pe.py`：无第三方依赖的 PE、资源和动态导入分析器；
- `tools/scan_vm_stubs.py`：101 个结构化虚拟机入口扫描器；
- `tools/windows/`：禁网 Windows 沙盒内存采集与运行时 PE 重建工具。

## 输入校验

```text
SHA256  8ba74270a14218bd0713a31bd4601d69824b742770c641c346b199239362e2d8
MD5     162831ceba8ffb3ed573f0306455d559
```

## 复现静态结果

```powershell
python tools\analyze_pe.py .\Spark1.5.2F.exe --out .\analysis-output --extract-resources
python tools\scan_vm_stubs.py .\Spark1.5.2F.exe --out .\vm-output
```

## 构建源码模型

源码模型用于持续标注、交叉验证和后续函数级恢复，不会生成原程序：

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## 采集运行时解包映像

在 Windows 10/11 上启用“Windows 沙盒”，把 `Spark1.5.2F.exe` 放到仓库根目录，然后双击：

```text
Launch-Unpack-Collector.cmd
```

启动器会禁用沙盒网络和常见设备重定向，只允许写入 `unpack-output/`。运行时映像是继续定位真实入口、修复导入表并生成函数级伪代码的必要输入。
