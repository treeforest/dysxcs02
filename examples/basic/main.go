// Package main 演示设备打开、随机数生成与 ECDSA 签名验签。
package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/treeforest/dysxcs02/sdf"
)

const maxECDSAKeyScan = 128
const ecdsaAbsentStreakStop = 16 // 连续 N 个索引无密钥则停止扫描

type ecdsaKeyInfo struct {
	Index uint32
	Bits  uint32
}

// listECDSAKeys 探测设备内可用的内部 ECDSA 签名密钥。
//
// 当前 libsdf.so 未导出 SDF_ExportPublicKey_ECDSA，无法通过导出公钥列举。
// 改以对索引 1..maxECDSAKeyScan 调用 InternalVerifyECDSA（故意传入无效签名）：
//   - SDR_KEYNOTEXIST / SDR_KEYTYPEERR → 该索引无 ECDSA 密钥
//   - SDR_VERIFYERR 等 → 密钥存在（验签失败因签名无效）
func listECDSAKeys(sess *sdf.Session, digest []byte) []ecdsaKeyInfo {
	bogusSig := sdf.ECCSignatureECDSA{
		R: make([]byte, 66),
		S: make([]byte, 66),
	}

	var keys []ecdsaKeyInfo
	absent := 0
	for i := uint32(1); i <= maxECDSAKeyScan; i++ {
		err := sess.InternalVerifyECDSA(i, sdf.SGDECDSA_1, digest, &bogusSig)
		if ecdsaKeyExists(err) {
			keys = append(keys, ecdsaKeyInfo{Index: i})
			absent = 0
			continue
		}
		absent++
		if absent >= ecdsaAbsentStreakStop {
			break
		}
	}
	return keys
}

func ecdsaKeyExists(err error) bool {
	if err == nil {
		return true
	}
	var sdferr *sdf.Error
	if !errors.As(err, &sdferr) {
		return false
	}
	switch sdferr.Code {
	case sdf.RVKeyNotExist, sdf.RVKeyTypeErr, sdf.RVAlgNotSupport:
		return false
	default:
		return true
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat("cacipher.ini"); err != nil {
		return fmt.Errorf("请将 testdata/cacipher.ini 复制到当前工作目录")
	}

	dev, err := sdf.OpenDeviceWithConfig("cacipher.ini", nil)
	if err != nil {
		return fmt.Errorf("打开设备失败: %w", err)
	}
	defer func() {
		if err := dev.Close(); err != nil {
			log.Printf("关闭设备: %v", err)
		}
	}()

	sess, err := dev.OpenSession()
	if err != nil {
		return fmt.Errorf("打开会话失败: %w", err)
	}
	defer func() {
		if err := sess.Close(); err != nil {
			log.Printf("关闭会话: %v", err)
		}
	}()

	info, err := sess.GetDeviceInfo()
	if err != nil {
		return fmt.Errorf("获取设备信息失败: %w", err)
	}
	fmt.Printf("设备名称: %s\n", strings.TrimRight(string(info.DeviceName[:]), "\x00"))
	fmt.Printf("设备版本: %d\n", info.DeviceVersion)

	rand, err := sess.GenerateRandom(16)
	if err != nil {
		return fmt.Errorf("生成随机数失败: %w", err)
	}
	fmt.Printf("随机数 (16B): %x\n", rand)

	message := []byte("dysxcs02 ecdsa sign demo")
	digest := sha256.Sum256(message)

	keys := listECDSAKeys(sess, digest[:])
	fmt.Printf("\nECDSA 内部密钥数量: %d\n", len(keys))
	for _, k := range keys {
		if k.Bits > 0 {
			fmt.Printf("  索引=%d  模长=%d bits\n", k.Index, k.Bits)
		} else {
			fmt.Printf("  索引=%d\n", k.Index)
		}
	}

	var sig sdf.ECCSignatureECDSA
	if len(keys) > 0 {
		sig = runInternalECDSADemo(sess, keys, digest[:])
	} else {
		sig = runExternalECDSADemo(sess, digest[:])
	}

	verifyBadDigest(sess, keys, digest, sig)
	return nil
}

func runInternalECDSADemo(sess *sdf.Session, keys []ecdsaKeyInfo, digest []byte) sdf.ECCSignatureECDSA {
	key := keys[0]
	fmt.Printf("\n使用内部 ECDSA 密钥索引 %d 签名...\n", key.Index)

	sig, err := sess.InternalSignECDSA(key.Index, sdf.SGDECDSA_1, digest)
	if err != nil {
		log.Fatalf("内部 ECDSA 签名失败: %v", err)
	}
	fmt.Printf("签名 r: %x\n", sig.R)
	fmt.Printf("签名 s: %x\n", sig.S)

	if err := sess.InternalVerifyECDSA(key.Index, sdf.SGDECDSA_1, digest, &sig); err != nil {
		log.Fatalf("内部 ECDSA 验签失败: %v", err)
	}
	fmt.Println("内部 ECDSA 验签: 通过")
	return sig
}

func runExternalECDSADemo(sess *sdf.Session, digest []byte) sdf.ECCSignatureECDSA {
	fmt.Println("\n未检测到内部 ECDSA 密钥，使用外部密钥演示...")

	pub, priv, err := sess.GenerateKeyPairECDSA(sdf.SGDECDSA, 256)
	if err != nil {
		log.Fatalf("生成 ECDSA 密钥对失败: %v", err)
	}
	fmt.Printf("已生成外部 ECDSA 密钥对，模长=%d bits\n", pub.Bits)

	sig, err := sess.ExternalSignECDSA(sdf.SGDECDSA_1, &priv, digest)
	if err != nil {
		log.Fatalf("外部 ECDSA 签名失败: %v", err)
	}
	fmt.Printf("签名 r: %x\n", sig.R)
	fmt.Printf("签名 s: %x\n", sig.S)

	if err := sess.ExternalVerifyECDSA(sdf.SGDECDSA_1, &pub, digest, &sig); err != nil {
		log.Fatalf("外部 ECDSA 验签失败: %v", err)
	}
	fmt.Println("外部 ECDSA 验签: 通过")
	return sig
}

func verifyBadDigest(sess *sdf.Session, keys []ecdsaKeyInfo, digest [32]byte, sig sdf.ECCSignatureECDSA) {
	if len(keys) == 0 {
		return
	}
	badDigest := digest
	badDigest[0] ^= 0xff
	verifyKeyIndex := keys[0].Index
	if err := sess.InternalVerifyECDSA(verifyKeyIndex, sdf.SGDECDSA_1, badDigest[:], &sig); err == nil {
		log.Println("警告: 错误摘要验签意外通过")
	} else if isSDFError(err, sdf.RVVerifyErr) {
		fmt.Println("错误摘要验签: 拒绝（符合预期）")
	} else {
		fmt.Printf("错误摘要验签: %v\n", err)
	}
}

func isSDFError(err error, code sdf.RV) bool {
	var sdferr *sdf.Error
	return errors.As(err, &sdferr) && sdferr.Code == code
}
