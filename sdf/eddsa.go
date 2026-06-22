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

// GenerateKeyPairEDDSA 生成 EDDSA 密钥对（SDF_GenerateKeyPair_EDDSA）。
func (s *Session) GenerateKeyPairEDDSA(algID, keyBits uint32) (ECCPublicKeyEDDSA, ECCPrivateKeyEDDSA, error) {
	var pub C.ECCrefPublicKey_EDDSA
	var priv C.ECCrefPrivateKey_EDDSA
	rv := RV(C.SDF_GenerateKeyPair_EDDSA(cHandle(s.h), C.uint(algID), C.uint(keyBits), &pub, &priv))
	if err := Err(rv); err != nil {
		return ECCPublicKeyEDDSA{}, ECCPrivateKeyEDDSA{}, err
	}
	return eccPublicKeyEDDSAFromC(&pub), eccPrivateKeyEDDSAFromC(&priv), nil
}

// ExternalSignEDDSA 外部 EDDSA 签名（SDF_ExternalSign_ECC_EDDSA）。
func (s *Session) ExternalSignEDDSA(algID uint32, priv *ECCPrivateKeyEDDSA, data []byte) (ECCSignatureEDDSA, error) {
	cPriv := eccPrivateKeyEDDSAToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	var sig C.ECCSignature_EDDSA
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalSign_ECC_EDDSA(cHandle(s.h), C.uint(algID), cPriv, puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignatureEDDSA{}, err
	}
	return eccSignatureEDDSAFromC(&sig), nil
}

// ExternalVerifyEDDSA 外部 EDDSA 验签（SDF_ExternalVerify_ECC_EDDSA）。
func (s *Session) ExternalVerifyEDDSA(algID uint32, pub *ECCPublicKeyEDDSA, data []byte, sig *ECCSignatureEDDSA) error {
	cPub := eccPublicKeyEDDSAToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cSig := eccSignatureEDDSAToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalVerify_ECC_EDDSA(cHandle(s.h), C.uint(algID), cPub, puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// InternalSignEDDSA 内部 EDDSA 签名（SDF_InternalSign_ECC_EDDSA）。
func (s *Session) InternalSignEDDSA(iskIndex, algID uint32, data []byte) (ECCSignatureEDDSA, error) {
	var sig C.ECCSignature_EDDSA
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSign_ECC_EDDSA(cHandle(s.h), C.uint(iskIndex), C.uint(algID), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignatureEDDSA{}, err
	}
	return eccSignatureEDDSAFromC(&sig), nil
}

// InternalVerifyEDDSA 内部 EDDSA 验签（SDF_InternalVerify_ECC_EDDSA）。
func (s *Session) InternalVerifyEDDSA(iskIndex, algID uint32, data []byte, sig *ECCSignatureEDDSA) error {
	cSig := eccSignatureEDDSAToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalVerify_ECC_EDDSA(cHandle(s.h), C.uint(iskIndex), C.uint(algID), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// ExportPublicKeyEDDSA 导出 EDDSA 公钥（SDF_ExportPublicKey_EDDSA）。
func (s *Session) ExportPublicKeyEDDSA(keyID uint32) (ECCPublicKeyEDDSA, error) {
	var pub C.ECCrefPublicKey_EDDSA
	rv := RV(C.SDF_ExportPublicKey_EDDSA(cHandle(s.h), C.uint(keyID), &pub))
	if err := Err(rv); err != nil {
		return ECCPublicKeyEDDSA{}, err
	}
	return eccPublicKeyEDDSAFromC(&pub), nil
}
