# 示例

| 目录 | 说明 |
|------|------|
| [basic/](basic/) | 设备信息、随机数、ECDSA 探测（简版） |
| [ecdsa/](ecdsa/) | 索引 1：内部签名 → `ExportPublicKeyECDSA` → 外部验签 → secp256k1 曲线判定 |
| [eddsa/](eddsa/) | 索引 1：内部签名 → `ExportPublicKeyEDDSA` → 外部验签 → Ed25519 判定 |

## 运行

在项目根目录执行（需 `cacipher.ini` 与可达密码机）：

```bash
cp testdata/cacipher.ini .

go run ./examples/ecdsa
go run ./examples/eddsa
```

## 动态库要求

`ecdsa` / `eddsa` 示例需新版 `lib/libsdf.so` 包含：

- `SDF_ExportPublicKey_ECDSA`
- `SDF_ExportPublicKey_EDDSA`

检查命令：

```bash
nm -D lib/libsdf.so | grep -E 'ExportPublicKey_(ECDSA|EDDSA)'
```

集成测试见 `sdf/*_integration_test.go`（`-tags=integration`）。
