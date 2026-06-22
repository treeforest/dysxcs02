# dysxcs02

基于 CGO 封装的密码机 SDF 接口 Go 绑定库，对应 [GM/T 0018-2012](https://www.gmbz.org.cn/) 标准的 `libsdf.h`。

## 目录结构

```
include/libsdf.h    # C 头文件（API 契约）
lib/libsdf.so       # 密码机动态库（不入 git，运行时放置）
sdf/                # Go 公开包
examples/           # 使用示例
testdata/           # 测试配置模板
```

## 依赖

1. 将厂商提供的 `libsdf.so` 放入 `lib/` 目录
2. 将 `testdata/cacipher.ini` 复制到程序工作目录（或按厂商要求配置路径）
3. 确保运行时可加载动态库：

```bash
export LD_LIBRARY_PATH=/path/to/dysxcs02/lib:$LD_LIBRARY_PATH
```

## 使用

```go
import "github.com/treeforest/dysxcs02/sdf"
```

## 文档

- [实现纲领](docs/implementation-plan.md)
- [API 清单与实现状态](docs/api-inventory.md)
- [厂商接口说明 PDF](docs/大有数信服务器密码机DYSX-CS02接口文档(扩展接口版).pdf)

## 示例

```bash
cp testdata/cacipher.ini .
go run ./examples/basic
```

## 版本与兼容性

| 项目 | 说明 |
|------|------|
| Go 版本 | 1.25+ |
| 标准 | GM/T 0018-2012（`libsdf.h`） |
| 头文件 | `include/libsdf.h`（`MAXCIPHER=16`） |
| 动态库 | `lib/libsdf.so`（厂商提供，需与头文件版本匹配） |
| 平台 | Linux x86_64（WSL2 可用） |
| CGO | 必须启用；链接 `-lsdf`，运行时需 `LD_LIBRARY_PATH` 包含 `lib/` |
| 链接选项 | `-Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all`（头文件声明但当前 `libsdf.so` 未导出的符号可在编译期通过，运行期调用将失败） |

本绑定以头文件为 API 契约。若厂商库版本较旧、缺少部分扩展函数（如 SM9、`SDFE_*`），调用时将返回 `SDR_NOTSUPPORT` 或链接错误。

### 运行测试

```bash
# 单元测试（无需硬件）
go test ./sdf/ -run 'TestErr|TestRV|TestECC|TestRSA|TestSM9|TestDeviceInfo' -count=1

# 集成测试（需要 cacipher.ini 与密码机/模拟库）
cp testdata/cacipher.ini .
go test ./sdf/ -tags=integration -count=1
```
