package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	if _, err := os.Stat("cacipher.ini"); err != nil {
		fmt.Fprintln(os.Stderr, "请将 cacipher.ini 放在当前工作目录（可复制 testdata/cacipher.ini）")
		os.Exit(1)
	}

	dev, err := sdf.OpenDeviceWithConfig("cacipher.ini", nil)
	if err != nil {
		log.Fatalf("打开设备失败: %v", err)
	}
	defer dev.Close()

	sess, err := dev.OpenSession()
	if err != nil {
		log.Fatalf("打开会话失败: %v", err)
	}
	defer sess.Close()

	algID := uint32(sdf.SGDECDSA_1)
	digest := sha256.Sum256([]byte(message))

	fmt.Printf("密钥索引: %d\n", keyIndex)
	fmt.Printf("算法标识: SGDECDSA_1 (0x%08x)\n", algID)
	fmt.Printf("消息摘要 (SHA-256): %x\n", digest)

	sig, err := sess.InternalSignECDSA(keyIndex, algID, digest[:])
	if err != nil {
		log.Fatalf("内部 ECDSA 签名失败: %v", err)
	}
	fmt.Printf("签名:\n  R:%x\n  S:%x\n", sig.R, sig.S)

	pub, err := sess.ExportPublicKeyECDSA(keyIndex)
	if err != nil {
		log.Fatalf("导出 ECDSA 公钥失败: %v", err)
	}

	x, y := pubCoords(&pub)
	fmt.Printf("公钥 bits: %d\n", pub.Bits)
	fmt.Printf("公钥 X: %x\n", x.Bytes())
	fmt.Printf("公钥 Y: %x\n", y.Bytes())

	curve := identifyCurve(x, y)
	fmt.Printf("曲线判定: %s\n", curve)

	if err := sess.ExternalVerifyECDSA(algID, &pub, digest[:], &sig); err != nil {
		log.Fatalf("密码机外部验签失败: %v", err)
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
	switch {
	case secp256k1.S256().IsOnCurve(x, y):
		return "secp256k1"
	case elliptic.P256().IsOnCurve(x, y):
		return "P-256"
	default:
		return "未知曲线"
	}
}

func verifyGoECDSAsecp256k1(x, y *big.Int, digest []byte, sig *sdf.ECCSignatureECDSA) bool {
	pubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     x,
		Y:     y,
	}
	r := new(big.Int).SetBytes(trimLeadingZeros(sig.R))
	s := new(big.Int).SetBytes(trimLeadingZeros(sig.S))
	return ecdsa.Verify(pubKey, digest, r, s)
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
