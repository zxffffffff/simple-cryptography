# start-cpp-vcpkg-template

![workflow](https://github.com/zxffffffff/start-cpp-vcpkg-template/actions/workflows/build-windows.yml/badge.svg?event=push)
![workflow](https://github.com/zxffffffff/start-cpp-vcpkg-template/actions/workflows/build-macos.yml/badge.svg?event=push)
![workflow](https://github.com/zxffffffff/start-cpp-vcpkg-template/actions/workflows/build-ubuntu.yml/badge.svg?event=push)

更多信息: [start-cpp-vcpkg](https://github.com/zxffffffff/start-cpp-vcpkg)

## 温馨提示

- 可以使用环境变量 VCPKG_ROOT、VCPKG_DOWNLOADS 指定安装、下载目录，也可以每个项目自带一个 vcpkg 子模块
- 下载时网络不是很稳定，经常失败需要反复手动下载，建议仅开源项目和小型项目使用
- 叫得出名字的库基本都支持，如果 vcpkg search 没有那就真没有了

## 一个 C++ 跨平台脚手架项目，使用 vcpkg + cmake 搭建

- `gflags`: Google 命令行标志库。
- `glog`: Google 日志库。
- `nlohmann-json`: 现代的 JSON 解析/生成器，语法糖非常方便。
- `tinyxml`: 轻量的 XML 解析库。
- `fmt`: 格式化库，实现 C++20 std::format，完美取代 iostreams 和 printf。
- `gtest`: Google 测试框架。

## 快速开始

- 运行 `build-xxx` 在线安装第三方库，需要能够访问外网 (github)
- 网络异常导致的错误，可以尝试重新运行脚本(下载较多，可能需要反复重试)
- 跨平台项目建议使用 静态库 (Linux默认静态编译，动态链接系统库)
- 跨平台项目建议使用 UTF-8 编码格式，这样仅需设置 Windows 编译环境 (Windows 中文系统默认使用 GBK 编码)
- 跨平台项目建议使用 `.gitattributes` 确保提交时转换为 `LF`

### CMake CXX_STANDARD 版本参考

| Added in version  | C++ Standard    |
| ----------------- | --------------- |
| 3.1               | C++ 98, 11, 14  |
| 3.8               | C++ 17          |
| 3.12              | C++ 20          |
| 3.20              | C++ 23          |
| 3.25              | C++ 26          |

### Windows MSVC 参考

| CMake version         | MSVC version    |
| --------------------- | --------------- |
| Visual Studio 17 2022 | v143            |
| Visual Studio 16 2019 | v142            |
| Visual Studio 15 2017 | v141            |
| Visual Studio 14 2015 | v140            |
| Visual Studio 12 2013 | 不保证二进制兼容性 |

### Apple C++ 版本参考

| C++ Feature        | Minimum deployment target                     |
| ------------------ | --------------------------------------------- |
| C++ 17 Filesystem  | macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0 |

### Linux Glibc 版本参考

| Glibc | Ubuntu             | CentOS         | Debian          |
| ----- | ------------------ | -------------- | --------------- |
| 2.35  | 22.04 (GCC 11.2.0) |                |                 |
| 2.34  |                    | 9 (GCC 11.2.1) |                 |
| 2.31  | 20.04 (GCC 9.3.0)  |                | 11 (GCC 10.2.1) |
| 2.28  |                    | 8 (GCC 8.3.1)  | 10 (GCC 8.3.0)  |
| 2.27  | 18.04 (GCC 7.3.0)  |                |                 |
| 2.24  |                    |                | 9 (GCC 6.3.0)   |
| 2.23  | 16.04 (GCC 5.4.0)  |                |                 |
| 2.19  | 14.04 (GCC 4.8.2)  |                | 8 (GCC 4.9.2)   |
| 2.17  |                    | 7 (GCC 4.8.5)  |                 |
| 2.15  | 12.04 (GCC 4.6.3)  |                |                 |
| 2.13  |                    |                | 7 (GCC 4.7.2)   |
| 2.12  |                    | 6 (GCC 4.4.7)  |                 |

## 注意事项

### vcpkg 指定编译器(降级)

- 除了使用 `cmake -G` 之外，还需要在 `vcpkg/triplets/xxx.cmake` 指定编译器，否则默认使用已安装的最新版本
- 手动修改 triplets 配置，例如设置 MSVC 版本 `set(VCPKG_PLATFORM_TOOLSET v140)`

### vcpkg 指定版本号(降级)

- 必须使用 `git clone` 或 `submodule` 引入 vcpkg，`subtree` 会报错找不到 `.git` 文件
- 查看历史版本：`git blame -l versions/l-/libuv.json`
- 自动添加baseline：`vcpkg x-update-baseline --add-initial-baseline`

```js
// libuv 1.41 是最后一个支持 win7 的版本
"overrides": [
  {
    "name": "libuv",
    "version": "1.41.0",
    "port-version": 1
  }
],
"builtin-baseline": "b051745c68faa6f65c493371d564c4eb8af34dad"
```

## Vcpkg

- 安装 `vcpkg` 参考本工程 `CMakeLists.txt`
- 手动安装建议使用 `git clone https://github.com/microsoft/vcpkg.git`
- 推荐使用环境变量 VCPKG_ROOT、VCPKG_DOWNLOADS 避免重复下载编译

### 参考

- <https://github.com/microsoft/vcpkg>
- <https://github.com/microsoft/vcpkg/blob/master/README_zh_CN.md>

### 查询 & 添加 & 查看

```Bash
.\vcpkg\vcpkg.exe search xxx
.\vcpkg\vcpkg.exe install xxx` or `vcpkg.json
.\vcpkg\packages\xxx\CONTROL
```

## License

选择合适的开源协议，例如 `MIT License`

![image](https://github.com/zxffffffff/start-cpp-vcpkg-template/blob/main/docs/choose-a-license.png)
