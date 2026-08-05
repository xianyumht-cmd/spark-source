# 可编译源码模型验收

验收日期：2026-08-05

## 验收对象

- `CMakeLists.txt`
- `src/recovered/pe_layout.c`
- `src/recovered/vm_entry.c`
- `src/recovered/import_surface.c`
- `src/recovered/dispatcher_model.c`
- 对应头文件

## 执行命令

```bash
cmake -S . -B build
cmake --build build --parallel
```

## 结果

四个 C 源文件均成功编译，静态库成功生成：

```text
[100%] Built target spark_recovered_model
```

本次沙箱构建产物：

```text
libspark_recovered_model.a
SHA256 c62ad2aa0a46357c67d623097848696d38dd79bd092f265e45650e3da8041f02
```

该构建结果证明仓库中的“源码模型”在语法和工程结构上可编译。它只表达已由静态证据确认的 PE 布局、入口栈帧、静态导入面和调度器结构，不将尚未解出的虚拟指令语义伪装成原始源码。
