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

// GenerateKeyPairDSA 生成 DSA 密钥对（SDF_GenerateKeyPair_DSA）。
func (s *Session) GenerateKeyPairDSA(keyBits uint32) (DSAPublicKey, DSAPrivateKey, error) {
	var pub C.DSArefPublicKey
	var priv C.DSArefPrivateKey
	rv := RV(C.SDF_GenerateKeyPair_DSA(cHandle(s.h), C.uint(keyBits), &pub, &priv))
	if err := Err(rv); err != nil {
		return DSAPublicKey{}, DSAPrivateKey{}, err
	}
	return dsaPublicKeyFromC(&pub), dsaPrivateKeyFromC(&priv), nil
}

// ExternalSignDSA 外部 DSA 签名（SDF_ExternalSign_DSA）。
func (s *Session) ExternalSignDSA(priv *DSAPrivateKey, data []byte) (DSASignature, error) {
	cPriv := dsaPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	var sig C.DSASignature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalSign_DSA(cHandle(s.h), cPriv, puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return DSASignature{}, err
	}
	return dsaSignatureFromC(&sig), nil
}

// ExternalVerifyDSA 外部 DSA 验签（SDF_ExternalVerify_DSA）。
func (s *Session) ExternalVerifyDSA(pub *DSAPublicKey, data []byte, sig *DSASignature) error {
	cPub := dsaPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cSig := dsaSignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalVerify_DSA(cHandle(s.h), cPub, puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// InternalSignDSAEcc 内部 DSA 签名（SDF_InternalSign_ECC_DSA）。
func (s *Session) InternalSignDSAEcc(index uint32, data []byte) (DSASignature, error) {
	var sig C.DSASignature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSign_ECC_DSA(cHandle(s.h), C.uint(index), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return DSASignature{}, err
	}
	return dsaSignatureFromC(&sig), nil
}

// InternalVerifyDSAEcc 内部 DSA 验签（SDF_InternalVerify_ECC_DSA）。
func (s *Session) InternalVerifyDSAEcc(index uint32, data []byte, sig *DSASignature) error {
	cSig := dsaSignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalVerify_ECC_DSA(cHandle(s.h), C.uint(index), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// ExportPublicKeyDSA 导出 DSA 公钥（SDF_ExportPublicKey_DSA）。
func (s *Session) ExportPublicKeyDSA(keyID uint32) (DSAPublicKey, error) {
	var pub C.DSArefPublicKey
	rv := RV(C.SDF_ExportPublicKey_DSA(cHandle(s.h), C.uint(keyID), &pub))
	if err := Err(rv); err != nil {
		return DSAPublicKey{}, err
	}
	return dsaPublicKeyFromC(&pub), nil
}
