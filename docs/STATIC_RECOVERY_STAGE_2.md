# 静态恢复第二阶段记录

生成日期：2026-08-05

## 本阶段新增成果

在不执行目标文件的前提下，新增完成：

1. 从保护区恢复按字节异或 `0x11` 的动态导入名称表，共 514 个具名 API；
2. 建立无第三方依赖的 PE/资源/导入分析器 `tools/analyze_pe.py`；
3. 从高熵执行区识别 101 个固定格式的虚拟机入口桩；
4. 将 101 个入口归并为 6 个公共调度器、12 个虚拟目标族；
5. 确认 89 个入口携带非零数据槽，可作为后续跟踪解密数据的断点索引；
6. 编写 Windows 沙盒内存采集器，用于等待原 `.text` 区被填充后立即转储模块；
7. 编写运行时节拆分与 PE 重建逻辑。

## 可复现命令

```bash
python tools/analyze_pe.py Spark1.5.2F.exe --out analysis-output --extract-resources
python tools/scan_vm_stubs.py Spark1.5.2F.exe --out vm-output
```

已在当前沙箱重复执行并得到：

```text
dynamic_import_count = 514
resource_count       = 17
vm_stub_count        = 101
vm_dispatchers       = 6
vm_target_families   = 12
nonzero_slots        = 89
```

## 当前源码恢复边界

磁盘映像中的原 `.text`、`.rdata`、`.data` 节没有原始字节。现阶段已经恢复的是加载结构、资源、依赖名称、虚拟机入口元数据和可重复分析工具，而不是原作者逐行工程源码。

要生成第一版可读伪代码，下一步必须取得运行时填充后的内存映像。仓库提供 `Launch-Unpack-Collector.cmd`，它会在禁网的 Windows 沙盒中运行采集器，生成：

- `memory-image.bin`
- `memory-map.json`
- `sections/*.bin`
- `rebuilt-memory-image.exe`
- `collector.json`

## 验证状态

- `tools/analyze_pe.py`：已通过 Python 语法检查和样本复跑；
- `tools/scan_vm_stubs.py`：已通过 Python 语法检查和样本复跑；
- `tools/rebuild_icons.py`：已通过 Python 语法检查；
- Windows 沙盒采集器：已完成静态审查，但当前 Linux 沙箱没有 Windows 运行环境，尚未进行真实执行验收。
