// Package main 演示 ECDSA 内部签名、公钥导出与验签。
package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/treeforest/dysxcs02/sdf"
)

const (
	keyIndex = uint32(1)
	message  = "dysxcs02 ecdsa sign/verify demo"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat("cacipher.ini"); err != nil {
		return fmt.Errorf("请将 cacipher.ini 放在当前工作目录（可复制 testdata/cacipher.ini）")
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

	algID := uint32(sdf.SGDECDSA_1)
	digest := sha256.Sum256([]byte(message))

	fmt.Printf("密钥索引: %d\n", keyIndex)
	fmt.Printf("算法标识: SGDECDSA_1 (0x%08x)\n", algID)
	fmt.Printf("消息摘要 (SHA-256): %x\n", digest)

	sig, err := sess.InternalSignECDSA(keyIndex, algID, digest[:])
	if err != nil {
		return fmt.Errorf("内部 ECDSA 签名失败: %w", err)
	}
	fmt.Printf("签名:\n  R:%x\n  S:%x\n", sig.R, sig.S)

	pub, err := sess.ExportPublicKeyECDSA(keyIndex)
	if err != nil {
		return fmt.Errorf("导出 ECDSA 公钥失败: %w", err)
	}

	x, y := pubCoords(&pub)
	fmt.Printf("公钥 bits: %d\n", pub.Bits)
	fmt.Printf("公钥 X: %x\n", x.Bytes())
	fmt.Printf("公钥 Y: %x\n", y.Bytes())

	curve := identifyCurve(x, y)
	fmt.Printf("曲线判定: %s\n", curve)

	if err := sess.ExternalVerifyECDSA(algID, &pub, digest[:], &sig); err != nil {
		return fmt.Errorf("密码机外部验签失败: %w", err)
	}
	fmt.Println("密码机外部验签: 通过")

	if curve == "secp256k1" {
		if verifyGoECDSAsecp256k1(x, y, digest[:], &sig) {
			fmt.Println("Go secp256k1 验签: 通过")
		} else {
			fmt.Println("Go secp256k1 验签: 失败（请以密码机验签为准）")
		}
	}

	bad := digest
	bad[0] ^= 0xff
	if err := sess.ExternalVerifyECDSA(algID, &pub, bad[:], &sig); err == nil {
		log.Println("警告: 错误摘要验签意外通过")
	} else if isSDFError(err, sdf.RVVerifyErr) {
		fmt.Println("错误摘要验签: 拒绝（符合预期）")
	} else {
		fmt.Printf("错误摘要验签: %v\n", err)
	}
	return nil
}

func pubCoords(pub *sdf.ECCPublicKeyECDSA) (*big.Int, *big.Int) {
	n := int((pub.Bits + 7) / 8)
	x := trimLeadingZeros(pub.X)
	y := trimLeadingZeros(pub.Y)
	if n > 0 && len(x) > n {
		x = x[len(x)-n:]
	}
	if n > 0 && len(y) > n {
		y = y[len(y)-n:]
	}
	return new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
}

func identifyCurve(x, y *big.Int) string {
	if isSecp256k1Point(x, y) {
		return "secp256k1"
	}
	if isP256Point(x, y) {
		return "P-256"
	}
	return "未知曲线"
}

func isP256Point(x, y *big.Int) bool {
	_, err := ecdh.P256().NewPublicKey(serializeUncompressedPoint(x, y))
	return err == nil
}

func isSecp256k1Point(x, y *big.Int) bool {
	_, err := secp256k1.ParsePubKey(serializeUncompressedPoint(x, y))
	return err == nil
}

func serializeUncompressedPoint(x, y *big.Int) []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:65])
	return out
}

func verifyGoECDSAsecp256k1(x, y *big.Int, digest []byte, sig *sdf.ECCSignatureECDSA) bool {
	pubKey, err := secp256k1.ParsePubKey(serializeUncompressedPoint(x, y))
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(trimLeadingZeros(sig.R))
	s := new(big.Int).SetBytes(trimLeadingZeros(sig.S))
	return ecdsa.Verify(pubKey.ToECDSA(), digest, r, s)
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

func isSDFError(err error, code sdf.RV) bool {
	var sdferr *sdf.Error
	return errors.As(err, &sdferr) && sdferr.Code == code
}
