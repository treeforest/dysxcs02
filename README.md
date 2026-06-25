# dysxcs02

[![Go Reference](https://pkg.go.dev/badge/github.com/treeforest/dysxcs02/sdf.svg)](https://pkg.go.dev/github.com/treeforest/dysxcs02/sdf)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go)](https://go.dev/)

基于 CGO 的密码机 SDF 接口 Go 绑定库，对应 [GM/T 0018-2012](https://www.gmbz.org.cn/) 标准及 `include/libsdf.h` 头文件定义。

## 特性

- 以 `libsdf.h` 为 API 契约，封装 `libsdf.so` 导出的 SDF 函数
- 惯用 Go 风格：`Device`、`Session`、`KeyHandle` 资源类型，方法返回 `(result, error)`
- 覆盖对称/非对称加解密、签名验签、哈希、文件操作及 ECDSA / EdDSA / SM9 等扩展接口
- 提供基础用法与 ECDSA / EdDSA 示例程序

## 环境要求

| 项目 | 说明 |
|------|------|
| Go | 1.25 及以上 |
| 平台 | Linux x86_64（WSL2 可用） |
| CGO | 必须启用 |
| 动态库 | 厂商提供的 `libsdf.so`，需与 `include/libsdf.h` 版本匹配 |
| 配置文件 | `cacipher.ini`（见 `testdata/cacipher.ini` 模板） |

## 安装

```bash
go get github.com/treeforest/dysxcs02/sdf
```

将厂商提供的 `libsdf.so` 放入项目 `lib/` 目录，并确保运行时可加载：

```bash
export LD_LIBRARY_PATH=/path/to/dysxcs02/lib:$LD_LIBRARY_PATH
```

## 快速开始

```go
package main

import (
    "fmt"
    "log"

    "github.com/treeforest/dysxcs02/sdf"
)

func main() {
    dev, err := sdf.OpenDevice()
    if err != nil {
        log.Fatal(err)
    }
    defer dev.Close()

    sess, err := dev.OpenSession()
    if err != nil {
        log.Fatal(err)
    }
    defer sess.Close()

    info, err := sess.GetDeviceInfo()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Issuer: %s\n", info.IssuerName)

    rand, err := sess.GenerateRandom(16)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Random: %x\n", rand)
}
```

## 示例

在项目根目录执行（需 `cacipher.ini` 与可达密码机）：

```bash
cp testdata/cacipher.ini .

# 设备信息、随机数、ECDSA 密钥探测
go run ./examples/basic

# ECDSA：内部签名 → 导出公钥 → 外部验签
go run ./examples/ecdsa

# EdDSA：内部签名 → 导出公钥 → 外部验签
go run ./examples/eddsa
```

`examples/ecdsa` 与 `examples/eddsa` 依赖 `libsdf.so` 导出 `SDF_ExportPublicKey_ECDSA` / `SDF_ExportPublicKey_EDDSA`。部署前请确认：

```bash
nm -D lib/libsdf.so | grep -E 'ExportPublicKey_(ECDSA|EDDSA)'
```

更多说明见 [examples/README.md](examples/README.md)。

## 项目结构

```
include/libsdf.h    # C 头文件（API 契约）
lib/libsdf.so       # 密码机动态库（不入 git，运行时放置）
sdf/                # Go 公开包
examples/           # 使用示例
testdata/           # 测试配置模板
```

## 兼容性说明

| 项目 | 说明 |
|------|------|
| 标准 | GM/T 0018-2012（`libsdf.h`） |
| 头文件 | `include/libsdf.h`（`MAXCIPHER=16`） |
| 链接选项 | `-Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all` |

本绑定以头文件为 API 契约。若厂商库版本较旧、缺少部分扩展函数（如 SM9、`SDFE_*`），调用时将返回 `SDR_NOTSUPPORT` 或在链接阶段报错。头文件声明但当前 `libsdf.so` 未导出的符号可在编译期通过，运行期调用将失败。

> **并发提示：** `Session` 及依赖会话状态的哈希流（如 `HashInit`）非线程安全，并发场景请为每个 goroutine 使用独立 `Session`。

## 测试

```bash
# 单元测试（无需硬件）
go test ./sdf/ -run 'TestErr|TestRV|TestECC|TestRSA|TestSM9|TestDeviceInfo' -count=1

# 集成测试（需要 cacipher.ini 与密码机/模拟库）
cp testdata/cacipher.ini .
go test -v ./sdf/ -tags=integration -count=1
```

## 相关标准

- [GM/T 0018-2012 密码设备应用接口规范](https://www.gmbz.org.cn/)
