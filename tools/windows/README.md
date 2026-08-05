# 隔离内存采集工具

此目录用于补齐静态分析无法获得的运行时内存映像。

## 使用条件

- Windows 10/11 专业版、企业版或教育版；
- 已启用“Windows 沙盒”；
- 将待分析文件放到仓库根目录，文件名保持为 `Spark1.5.2F.exe`；
- 双击仓库根目录的 `Launch-Unpack-Collector.cmd`。

启动器会生成临时 `.wsb` 配置，并执行以下隔离措施：

- 禁用 Windows 沙盒网络；
- 禁用剪贴板、打印机、音频输入和摄像头映射；
- 仓库目录以只读方式映射到沙盒；
- 仅 `unpack-output` 目录允许写入；
- 原文件先复制到沙盒临时目录再运行；
- 检测到原始 `.text` 区被填充且稳定后立即导出内存并终止进程。

成功后会生成：

- `unpack-output/memory-image.bin`：完整模块内存映像；
- `unpack-output/memory-map.json`：内存页读取情况；
- `unpack-output/sections/*.bin`：按 PE 节拆分的数据；
- `unpack-output/rebuilt-memory-image.exe`：以运行时节数据重建的 PE，入口点仍保留原保护入口，仅供继续反编译；
- `unpack-output/collector.json`：采集参数和判断结果。

不要在日常使用的宿主系统上通过 `-AllowHostExecution` 直接运行。该开关仅为一次性离线虚拟机保留。
