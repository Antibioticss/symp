# symp

[English](README.md) | [中文](README.zh-CN.md)

基于Mach-O内符号的补丁工具，轻松地修改符号函数

**已支持：**

 - 符号表 `LC_SYMTAB`
 - 导出表 `LC_DYLD_INFO/LC_DYLD_EXPORTS_TRIE`
 - 导入表 `S_SYMBOL_STUBS`
 - `ObjC`元数据

## 安装

### 下载二进制

Releases: https://github.com/Antibioticss/symp/releases

可以下载`pkg`安装包，默认安装到`/usr/local/bin`目录

### 从源码编译

克隆仓库并使用`cmake`编译

```sh
git clone https://github.com/Antibioticss/symp.git
cd symp
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .
```

安装到`/usr/local/bin`

```sh
sudo cmake --install .
```

## 使用

```sh
symp [options] -- <symbol> <file>
```

### 快速上手

往虚拟地址（反汇编器中看到的）对应的文件偏移写入十六进制数据

```sh
symp -x 909090 -- 0x10002a704 file
```

让一个OC函数返回1

```sh
symp -p ret1 -- '-[MyClass isSmart]' file
```

用新的二进制（纯指令）覆盖一个原有的函数

```sh
symp -b new.bin -- '_old_func' file
```

### 符号类型

目前支持支持三种类型的`symbol`

| 类型         | 说明                                               | 示例               |
| ------------ | -------------------------------------------------- | ------------------ |
| 十六进制偏移 | 为在内存中的偏移量，以`0x`或者`0X`开头会被自动识别 | `0x100007e68`      |
| `ObjC`符号名 | 不会demangle类名，以`+`/`-`开头，用`[]`框起来      | `-[MyClass hello]` |
| 一般的符号名 | 不满足上面两条的符号都会当作此类型                 | `_printf`          |

### 参数

| 参数 | 说明 | 示例 |
| ------------ | ---- | ---- |
| `-p`/`--patch` | 使用内置的补丁，可选`nop`, `ret`, `ret0`, `ret1`, `ret2` | `-p ret1` |
| `-b`/`--binary` | 使用一个二进制文件作为补丁 | `-b data.bin` |
| `-x`/`--hex` | 使用十六进制数据作为补丁（不要求大小写，可以有空格） | `-x "C0 03 5F D6"` |
|`-a`/`--arch`|指定`FAT`文件中的某个架构，目前仅支持`x86_64`和`arm64`|`-a arm64`|
| `-q`/`--quiet`  | 不要输出匹配数量统计（用于指令集成） | `-q` |

`-p/b/x`这三个参数只能有其中一个，当都没有提供时，会输出该符号在整个文件中的偏移量

`-a`可以有多个，当未提供`-a`参数时，默认会查找文件中的所有架构

## 与 xsp 集成

`symp` 可以和 `xsp` 一起使用，实现强大的基于符号的16进制补丁修改

```bash
# 基本原理: 查找符号地址并用来搜索补丁
xsp --offset $(symp -q 'symbol_name' binary_file) -f binary_file hex1 hex2

# 例子: 把某个函数中的 NOP 替换为断点
xsp --offset $(symp -q '_vulnerable_function' /usr/bin/target) -f /usr/bin/target "90 90 90 90" "CC CC CC CC"

# 例子: 修改一个 Objective-C 函数
xsp --offset $(symp -q '-[MyClass sensitiveMethod]' MyApp) -f MyApp "original_bytes" "patched_bytes"
```

## LICENSE

[MIT LICENSE](LICENSE)

