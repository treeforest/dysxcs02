// Package main 演示 EDDSA 内部签名与外部验签。
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/treeforest/dysxcs02/sdf"
)

const (
	keyIndex = uint32(1)
	message  = "dysxcs02 eddsa sign/verify demo: hello world!!"
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

	algID := uint32(sdf.SGDEDDSA_1)
	msg := []byte(message)

	fmt.Printf("密钥索引: %d\n", keyIndex)
	fmt.Printf("算法标识: SGDEDDSA_1 (0x%08x)\n", algID)
	fmt.Printf("原始消息 (%d 字节): %q\n", len(msg), message)

	pub, err := sess.ExportPublicKeyEDDSA(keyIndex)
	if err != nil {
		return fmt.Errorf("导出 EDDSA 公钥失败: %w", err)
	}

	pubBytes := trimLeadingZeros(pub.Pub)
	fmt.Printf("公钥 bits: %d\n", pub.Bits)
	fmt.Printf("公钥: %x\n", pubBytes)
	fmt.Printf("曲线判定: %s\n", identifyEDDSACurve(&pub))

	sig, err := sess.InternalSignEDDSA(keyIndex, algID, msg)
	if err != nil {
		return fmt.Errorf("内部 EDDSA 签名失败: %w", err)
	}
	fmt.Printf("签名:\n  R:%x\n  S:%x\n", sig.R, sig.S)

	if err := sess.ExternalVerifyEDDSA(algID, &pub, msg, &sig); err != nil {
		return fmt.Errorf("密码机外部验签失败: %w", err)
	}
	fmt.Println("密码机外部验签: 通过")

	if ok, note := verifyGoEd25519(&pub, msg, &sig); ok {
		fmt.Println("Go Ed25519 验签: 通过")
	} else {
		fmt.Printf("Go Ed25519 验签: 跳过或失败（%s；以密码机验签为准）\n", note)
	}

	badMsg := append([]byte(nil), msg...)
	badMsg[0] ^= 0xff
	if err := sess.ExternalVerifyEDDSA(algID, &pub, badMsg, &sig); err == nil {
		log.Println("警告: 篡改消息验签意外通过")
	} else if isSDFError(err, sdf.RVVerifyErr) {
		fmt.Println("篡改消息验签: 拒绝（符合预期）")
	} else {
		fmt.Printf("篡改消息验签: %v\n", err)
	}
	return nil
}

func identifyEDDSACurve(pub *sdf.ECCPublicKeyEDDSA) string {
	pubBytes := trimLeadingZeros(pub.Pub)
	if pub.Bits == 256 && len(pubBytes) == ed25519.PublicKeySize {
		return "Ed25519"
	}
	return fmt.Sprintf("未知 EDDSA 曲线 (bits=%d, pubLen=%d)", pub.Bits, len(pubBytes))
}

func verifyGoEd25519(pub *sdf.ECCPublicKeyEDDSA, message []byte, sig *sdf.ECCSignatureEDDSA) (bool, string) {
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

	if ed25519.Verify(ed25519.PublicKey(pubKey), message, sigBytes) {
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
