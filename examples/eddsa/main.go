package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/treeforest/dysxcs02/sdf"
)

const (
	keyIndex = uint32(1)
	message  = "dysxcs02 eddsa sign/verify demo"
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

	algID := uint32(sdf.SGDEDDSA_1)
	digest := sha256.Sum256([]byte(message))

	fmt.Printf("密钥索引: %d\n", keyIndex)
	fmt.Printf("算法标识: SGDEDDSA_1 (0x%08x)\n", algID)
	fmt.Printf("消息摘要 (SHA-256): %x\n", digest)

	sig, err := sess.InternalSignEDDSA(keyIndex, algID, digest[:])
	if err != nil {
		log.Fatalf("内部 EDDSA 签名失败: %v", err)
	}

	pub, err := sess.ExportPublicKeyEDDSA(keyIndex)
	if err != nil {
		log.Fatalf("导出 EDDSA 公钥失败: %v", err)
	}

	pubBytes := trimLeadingZeros(pub.Pub)
	fmt.Printf("公钥 bits: %d\n", pub.Bits)
	fmt.Printf("公钥: %x\n", pubBytes)
	fmt.Printf("曲线判定: %s\n", identifyEDDSACurve(&pub))

	if err := sess.ExternalVerifyEDDSA(algID, &pub, digest[:], &sig); err != nil {
		log.Fatalf("密码机外部验签失败: %v", err)
	}
	fmt.Println("密码机外部验签: 通过")

	if ok, note := verifyGoEd25519(&pub, digest[:], &sig); ok {
		fmt.Println("Go Ed25519 验签: 通过")
	} else {
		fmt.Printf("Go Ed25519 验签: 跳过或失败（%s；以密码机验签为准）\n", note)
	}

	bad := digest
	bad[0] ^= 0xff
	if err := sess.ExternalVerifyEDDSA(algID, &pub, bad[:], &sig); err == nil {
		log.Println("警告: 错误摘要验签意外通过")
	} else if isSDFError(err, sdf.RVVerifyErr) {
		fmt.Println("错误摘要验签: 拒绝（符合预期）")
	} else {
		fmt.Printf("错误摘要验签: %v\n", err)
	}
}

func identifyEDDSACurve(pub *sdf.ECCPublicKeyEDDSA) string {
	pubBytes := trimLeadingZeros(pub.Pub)
	if pub.Bits == 256 && len(pubBytes) == ed25519.PublicKeySize {
		return "Ed25519"
	}
	return fmt.Sprintf("未知 EDDSA 曲线 (bits=%d, pubLen=%d)", pub.Bits, len(pubBytes))
}

func verifyGoEd25519(pub *sdf.ECCPublicKeyEDDSA, digest []byte, sig *sdf.ECCSignatureEDDSA) (bool, string) {
	pubKey := trimLeadingZeros(pub.Pub)
	if len(pubKey) != ed25519.PublicKeySize {
		return false, fmt.Sprintf("公钥长度 %d，非 Ed25519", len(pubKey))
	}

	r := trimLeadingZeros(sig.R)
	s := trimLeadingZeros(sig.S)
	if len(r) == 0 || len(s) == 0 {
		return false, "签名 r/s 为空"
	}

	sigBytes := append(padTo32(r), padTo32(s)...)
	if len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Sprintf("签名长度 %d，非 64 字节", len(sigBytes))
	}

	if ed25519.Verify(ed25519.PublicKey(pubKey), digest, sigBytes) {
		return true, ""
	}
	return false, "Verify 返回 false"
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
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
