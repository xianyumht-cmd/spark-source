# HANDOFF — Spark1.5.2F 源码还原

更新时间：2026-08-05

## 当前阶段

阶段二“静态结构扩展、可编译索引模型与动态采集工具”完成。

## 输入

- 文件：`Spark1.5.2F.exe`
- SHA-256：`8ba74270a14218bd0713a31bd4601d69824b742770c641c346b199239362e2d8`
- MD5：`162831ceba8ffb3ed573f0306455d559`
- 后续分析必须先校验哈希，避免混入不同版本。

## 已完成

- PE32/i386/GUI 格式确认及 .NET 排除；
- 节区、熵、原始偏移和虚拟地址建档；
- 入口 `0x03883820 -> 0x0595D9C0` 与首个三字段 VM 帧恢复；
- 确认原 `.text/.rdata/.data` 在磁盘中的 `RawSize` 均为 0；
- 16 组磁盘静态导入记录；
- 从保护数据区恢复 514 个按字节异或 `0x11` 保存的动态 API 名称及编码位置；
- 17 项资源索引、Manifest、版本资源和图标重建工具；
- 扫描出 101 个固定结构的 VM 入口桩；
- 101 个入口归入 6 个公共调度器和 12 个虚拟目标族，其中 89 个入口携带非零数据槽；
- `src/recovered/vm_index.c`：101 个入口的可编译 C 数据模型；
- `src/recovered/dynamic_import_index.c`：514 个动态名称的可编译 C 数据模型；
- `tools/analyze_pe.py`、`tools/scan_vm_stubs.py`、`tools/rebuild_icons.py`；
- 禁网 Windows 沙盒采集器及运行时节拆分、PE 重建工具；
- 本次新增 Python 工具已通过语法检查和样本复跑；两个新增 C 索引模型已分别通过 `-std=c11 -Wall -Wextra -Werror` 编译检查。

## 已验证结果

```text
dynamic_import_count = 514
resource_count       = 17
vm_stub_count        = 101
vm_dispatchers       = 6
vm_target_families   = 12
nonzero_slots        = 89
```

## 关键边界

当前仓库中的 C 文件是从机器码和数据结构确认后重建的分析模型，不是原作者完整工程。当前磁盘映像没有原始常规代码节数据，无法仅靠静态文件无损恢复原始函数名、变量名、注释、工程结构和全部函数体。

## 下一阶段：采集运行时映像

在 Windows 10/11 启用“Windows 沙盒”，把哈希匹配的 `Spark1.5.2F.exe` 放到仓库根目录并双击：

```text
Launch-Unpack-Collector.cmd
```

启动器默认：

- 禁用沙盒网络；
- 禁用剪贴板、打印机、音频输入和视频输入重定向；
- 仓库目录只读映射；
- 仅 `unpack-output/` 允许写入；
- 监测原 `.text` 区被填充并稳定后导出模块内存、拆分节并终止进程。

预期产物：

- `unpack-output/memory-image.bin`
- `unpack-output/memory-map.json`
- `unpack-output/sections/*.bin`
- `unpack-output/rebuilt-memory-image.exe`
- `unpack-output/collector.json`

当前 Linux 沙箱没有 Windows 运行环境，因此采集器已做静态审查，但尚未完成真实 Windows 执行验收。

## 获得转储后的工作

1. 校验 `.text/.rdata/.data` 已有非零运行时数据；
2. 定位真实 OEP；
3. 重建完整 IAT；
4. 对内存代码重新建立函数边界和 CFG；
5. 按“机器码确认 / 反编译器推断 / 人工命名”分层写入 `src/decompiled/`；
6. 逐步形成可读、可编译的函数级源码重建。

## 禁止事项

- 不把保护层线性反汇编垃圾当成函数；
- 不根据导入名称推断程序用途；
- 不声称已恢复原始变量名、注释或完整工程；
- 不在日常使用的 Windows 宿主系统上直接执行样本。
