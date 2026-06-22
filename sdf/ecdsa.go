package sdf

/*
#cgo CFLAGS: -I${SRCDIR}/../include -DMAXCIPHER=16
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdf -Wl,-rpath,${SRCDIR}/../lib -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all

#include <stdlib.h>
#include <string.h>
#include "libsdf.h"
*/
import "C"



import "unsafe"

// GenerateKeyPairECDSA 生成 ECDSA 密钥对（SDF_GenerateKeyPair_ECDSA）。
func (s *Session) GenerateKeyPairECDSA(algID, keyBits uint32) (ECCPublicKeyECDSA, ECCPrivateKeyECDSA, error) {
	var pub C.ECCrefPublicKey_ECDSA
	var priv C.ECCrefPrivateKey_ECDSA
	rv := RV(C.SDF_GenerateKeyPair_ECDSA(cHandle(s.h), C.uint(algID), C.uint(keyBits), &pub, &priv))
	if err := Err(rv); err != nil {
		return ECCPublicKeyECDSA{}, ECCPrivateKeyECDSA{}, err
	}
	return eccPublicKeyECDSAFromC(&pub), eccPrivateKeyECDSAFromC(&priv), nil
}

// ExternalSignECDSA 外部 ECDSA 签名（SDF_ExternalSign_ECC_ECDSA）。
func (s *Session) ExternalSignECDSA(algID uint32, priv *ECCPrivateKeyECDSA, data []byte) (ECCSignatureECDSA, error) {
	cPriv := eccPrivateKeyECDSAToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	var sig C.ECCSignature_ECDSA
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalSign_ECC_ECDSA(cHandle(s.h), C.uint(algID), cPriv, puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignatureECDSA{}, err
	}
	return eccSignatureECDSAFromC(&sig), nil
}

// ExternalVerifyECDSA 外部 ECDSA 验签（SDF_ExternalVerify_ECC_ECDSA）。
func (s *Session) ExternalVerifyECDSA(algID uint32, pub *ECCPublicKeyECDSA, data []byte, sig *ECCSignatureECDSA) error {
	cPub := eccPublicKeyECDSAToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cSig := eccSignatureECDSAToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalVerify_ECC_ECDSA(cHandle(s.h), C.uint(algID), cPub, puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// InternalSignECDSA 内部 ECDSA 签名（SDF_InternalSign_ECC_ECDSA）。
func (s *Session) InternalSignECDSA(iskIndex, algID uint32, data []byte) (ECCSignatureECDSA, error) {
	var sig C.ECCSignature_ECDSA
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSign_ECC_ECDSA(cHandle(s.h), C.uint(iskIndex), C.uint(algID), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignatureECDSA{}, err
	}
	return eccSignatureECDSAFromC(&sig), nil
}

// InternalVerifyECDSA 内部 ECDSA 验签（SDF_InternalVerify_ECC_ECDSA）。
func (s *Session) InternalVerifyECDSA(iskIndex, algID uint32, data []byte, sig *ECCSignatureECDSA) error {
	cSig := eccSignatureECDSAToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalVerify_ECC_ECDSA(cHandle(s.h), C.uint(iskIndex), C.uint(algID), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// ExportPublicKeyECDSA 导出 ECDSA 公钥（SDF_ExportPublicKey_ECDSA）。
func (s *Session) ExportPublicKeyECDSA(keyID uint32) (ECCPublicKeyECDSA, error) {
	var pub C.ECCrefPublicKey_ECDSA
	rv := RV(C.SDF_ExportPublicKey_ECDSA(cHandle(s.h), C.uint(keyID), &pub))
	if err := Err(rv); err != nil {
		return ECCPublicKeyECDSA{}, err
	}
	return eccPublicKeyECDSAFromC(&pub), nil
}
