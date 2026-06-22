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

// ExportSignPublicKeyECC 导出 ECC 签名公钥（SDF_ExportSignPublicKey_ECC）。
func (s *Session) ExportSignPublicKeyECC(keyIndex uint32) (ECCPublicKey, error) {
	var pk C.ECCrefPublicKey
	rv := RV(C.SDF_ExportSignPublicKey_ECC(cHandle(s.h), C.uint(keyIndex), &pk))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, err
	}
	return eccPublicKeyFromC(&pk), nil
}

// ExportEncPublicKeyECC 导出 ECC 加密公钥（SDF_ExportEncPublicKey_ECC）。
func (s *Session) ExportEncPublicKeyECC(keyIndex uint32) (ECCPublicKey, error) {
	var pk C.ECCrefPublicKey
	rv := RV(C.SDF_ExportEncPublicKey_ECC(cHandle(s.h), C.uint(keyIndex), &pk))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, err
	}
	return eccPublicKeyFromC(&pk), nil
}

// GenerateKeyPairECC 生成 ECC 密钥对（SDF_GenerateKeyPair_ECC）。
func (s *Session) GenerateKeyPairECC(algID, keyBits uint32) (ECCPublicKey, ECCPrivateKey, error) {
	var pub C.ECCrefPublicKey
	var priv C.ECCrefPrivateKey
	rv := RV(C.SDF_GenerateKeyPair_ECC(cHandle(s.h), C.uint(algID), C.uint(keyBits), &pub, &priv))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, ECCPrivateKey{}, err
	}
	return eccPublicKeyFromC(&pub), eccPrivateKeyFromC(&priv), nil
}

// GenerateKeyWithIPKECC 使用内部 ECC 公钥生成会话密钥（SDF_GenerateKeyWithIPK_ECC）。
func (s *Session) GenerateKeyWithIPKECC(ipkIndex, keyBits uint32) (ECCCipher, *KeyHandle, error) {
	var cipher C.ECCCipher
	var h unsafe.Pointer
	rv := RV(C.SDF_GenerateKeyWithIPK_ECC(cHandle(s.h), C.uint(ipkIndex), C.uint(keyBits), &cipher, &h))
	if err := Err(rv); err != nil {
		return ECCCipher{}, nil, err
	}
	return eccCipherFromC(&cipher), newKeyHandle(s, h), nil
}

// GenerateKeyWithEPKECC 使用外部 ECC 公钥生成会话密钥（SDF_GenerateKeyWithEPK_ECC）。
func (s *Session) GenerateKeyWithEPKECC(keyBits, algID uint32, pub *ECCPublicKey) (ECCCipher, *KeyHandle, error) {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var cipher C.ECCCipher
	var h unsafe.Pointer
	rv := RV(C.SDF_GenerateKeyWithEPK_ECC(cHandle(s.h), C.uint(keyBits), C.uint(algID), cPub, &cipher, &h))
	if err := Err(rv); err != nil {
		return ECCCipher{}, nil, err
	}
	return eccCipherFromC(&cipher), newKeyHandle(s, h), nil
}

// ImportKeyWithISKECC 使用内部 ECC 私钥导入会话密钥（SDF_ImportKeyWithISK_ECC）。
func (s *Session) ImportKeyWithISKECC(iskIndex uint32, cipher *ECCCipher) (*KeyHandle, error) {
	cCipher, free := eccCipherAlloc(cipher)
	defer free()
	var h unsafe.Pointer
	rv := RV(C.SDF_ImportKeyWithISK_ECC(cHandle(s.h), C.uint(iskIndex), cCipher, &h))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// GenerateAgreementDataWithECC 生成 ECC 密钥协商参数（SDF_GenerateAgreementDataWithECC）。
func (s *Session) GenerateAgreementDataWithECC(iskIndex, keyBits uint32, sponsorID []byte) (ECCPublicKey, ECCPublicKey, *AgreementHandle, error) {
	var sponsorPub, sponsorTmp C.ECCrefPublicKey
	var h unsafe.Pointer
	var id *C.uchar
	if len(sponsorID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&sponsorID[0]))
	}
	rv := RV(C.SDF_GenerateAgreementDataWithECC(cHandle(s.h), C.uint(iskIndex), C.uint(keyBits), id, C.uint(len(sponsorID)), &sponsorPub, &sponsorTmp, &h))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, ECCPublicKey{}, nil, err
	}
	return eccPublicKeyFromC(&sponsorPub), eccPublicKeyFromC(&sponsorTmp), newAgreementHandle(s, h), nil
}

// GenerateKeyWithECC 响应方计算会话密钥（SDF_GenerateKeyWithECC）。
func (s *Session) GenerateKeyWithECC(sponsorID []byte, responsePub, responseTmp *ECCPublicKey, agreement *AgreementHandle) (*KeyHandle, error) {
	cResp := eccPublicKeyToC(responsePub)
	defer C.free(unsafe.Pointer(cResp))
	cTmp := eccPublicKeyToC(responseTmp)
	defer C.free(unsafe.Pointer(cTmp))
	var id *C.uchar
	if len(sponsorID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&sponsorID[0]))
	}
	var h unsafe.Pointer
	rv := RV(C.SDF_GenerateKeyWithECC(cHandle(s.h), id, C.uint(len(sponsorID)), cResp, cTmp, cHandle(agreement.h), &h))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// GenerateAgreementDataAndKeyWithECC 一步生成协商数据与会话密钥（SDF_GenerateAgreementDataAndKeyWithECC）。
func (s *Session) GenerateAgreementDataAndKeyWithECC(iskIndex, keyBits uint32, sponsorID, responseID []byte) (ECCPublicKey, ECCPublicKey, ECCPublicKey, ECCPublicKey, *KeyHandle, error) {
	var sponsorPub, sponsorTmp, responsePub, responseTmp C.ECCrefPublicKey
	var h unsafe.Pointer
	var sid, rid *C.uchar
	if len(sponsorID) > 0 {
		sid = (*C.uchar)(unsafe.Pointer(&sponsorID[0]))
	}
	if len(responseID) > 0 {
		rid = (*C.uchar)(unsafe.Pointer(&responseID[0]))
	}
	rv := RV(C.SDF_GenerateAgreementDataAndKeyWithECC(cHandle(s.h), C.uint(iskIndex), C.uint(keyBits), sid, C.uint(len(sponsorID)), rid, C.uint(len(responseID)), &sponsorPub, &sponsorTmp, &responsePub, &responseTmp, &h))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, ECCPublicKey{}, ECCPublicKey{}, ECCPublicKey{}, nil, err
	}
	return eccPublicKeyFromC(&sponsorPub), eccPublicKeyFromC(&sponsorTmp), eccPublicKeyFromC(&responsePub), eccPublicKeyFromC(&responseTmp), newKeyHandle(s, h), nil
}

// ExchangeDigitEnvelopeBaseOnECC ECC 数字信封交换（SDF_ExchangeDigitEnvelopeBaseOnECC）。
func (s *Session) ExchangeDigitEnvelopeBaseOnECC(keyIndex, algID uint32, pub *ECCPublicKey, encIn *ECCCipher) (ECCCipher, error) {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cIn, freeIn := eccCipherAlloc(encIn)
	defer freeIn()
	var out C.ECCCipher
	rv := RV(C.SDF_ExchangeDigitEnvelopeBaseOnECC(cHandle(s.h), C.uint(keyIndex), C.uint(algID), cPub, cIn, &out))
	if err := Err(rv); err != nil {
		return ECCCipher{}, err
	}
	return eccCipherFromC(&out), nil
}

// ExternalSignECC 外部 ECC 签名（SDF_ExternalSign_ECC）。
func (s *Session) ExternalSignECC(algID uint32, priv *ECCPrivateKey, data []byte) (ECCSignature, error) {
	cPriv := eccPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	var sig C.ECCSignature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalSign_ECC(cHandle(s.h), C.uint(algID), cPriv, puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignature{}, err
	}
	return eccSignatureFromC(&sig), nil
}

// ExternalVerifyECC 外部 ECC 验签（SDF_ExternalVerify_ECC）。
func (s *Session) ExternalVerifyECC(algID uint32, pub *ECCPublicKey, data []byte, sig *ECCSignature) error {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cSig := eccSignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalVerify_ECC(cHandle(s.h), C.uint(algID), cPub, puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// InternalSignECC 内部 ECC 签名（SDF_InternalSign_ECC）。
func (s *Session) InternalSignECC(iskIndex uint32, data []byte) (ECCSignature, error) {
	var sig C.ECCSignature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSign_ECC(cHandle(s.h), C.uint(iskIndex), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignature{}, err
	}
	return eccSignatureFromC(&sig), nil
}

// InternalVerifyECC 内部 ECC 验签（SDF_InternalVerify_ECC）。
func (s *Session) InternalVerifyECC(iskIndex uint32, data []byte, sig *ECCSignature) error {
	cSig := eccSignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalVerify_ECC(cHandle(s.h), C.uint(iskIndex), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// ExternalEncryptECC 外部 ECC 加密（SDF_ExternalEncrypt_ECC）。
func (s *Session) ExternalEncryptECC(algID uint32, pub *ECCPublicKey, data []byte) (ECCCipher, error) {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var cipher C.ECCCipher
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_ExternalEncrypt_ECC(cHandle(s.h), C.uint(algID), cPub, puc, C.uint(len(data)), &cipher))
	if err := Err(rv); err != nil {
		return ECCCipher{}, err
	}
	return eccCipherFromC(&cipher), nil
}

// ExternalDecryptECC 外部 ECC 解密（SDF_ExternalDecrypt_ECC）。
func (s *Session) ExternalDecryptECC(algID uint32, priv *ECCPrivateKey, cipher *ECCCipher) ([]byte, error) {
	cPriv := eccPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	cCipher, free := eccCipherAlloc(cipher)
	defer free()
	return bytesOut(uint32(cipher.L), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_ExternalDecrypt_ECC(cHandle(s.h), C.uint(algID), cPriv, cCipher, out, outLen)
	})
}

// InternalEncryptECC 内部 ECC 加密（SDF_InternalEncrypt_ECC，参数顺序 uiKeyIndex, uiAlgID）。
func (s *Session) InternalEncryptECC(keyIndex, algID uint32, data []byte) (ECCCipher, error) {
	var cipher C.ECCCipher
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalEncrypt_ECC(cHandle(s.h), C.uint(keyIndex), C.uint(algID), puc, C.uint(len(data)), &cipher))
	if err := Err(rv); err != nil {
		return ECCCipher{}, err
	}
	return eccCipherFromC(&cipher), nil
}

// InternalDecryptECC 内部 ECC 解密（SDF_InternalDecrypt_ECC，参数顺序 uiKeyIndex, uiAlgID）。
func (s *Session) InternalDecryptECC(keyIndex, algID uint32, cipher *ECCCipher) ([]byte, error) {
	cCipher, free := eccCipherAlloc(cipher)
	defer free()
	return bytesOut(cipher.L, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalDecrypt_ECC(cHandle(s.h), C.uint(keyIndex), C.uint(algID), cCipher, out, outLen)
	})
}

// GenerateKeyHandleECC 生成 SM2 私钥句柄（SDF_GenerateKey_Handle_ECC）。
func (s *Session) GenerateKeyHandleECC(algID, keyBits, kekIndex uint32, encPrivKey []byte) (*ECCKeyHandle, error) {
	var puc *C.uchar
	if len(encPrivKey) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&encPrivKey[0]))
	}
	var h unsafe.Pointer
	rv := RV(C.SDF_GenerateKey_Handle_ECC(cHandle(s.h), C.uint(algID), C.uint(keyBits), C.uint(kekIndex), puc, &h))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newECCKeyHandle(s, h), nil
}

// HandleSignECC 使用 SM2 私钥句柄签名（SDF_HandleSign_ECC）。
func (s *Session) HandleSignECC(handle *ECCKeyHandle, data []byte) (ECCSignature, error) {
	var sig C.ECCSignature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_HandleSign_ECC(cHandle(s.h), cHandle(handle.h), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return ECCSignature{}, err
	}
	return eccSignatureFromC(&sig), nil
}

// HandleDecryptECC 使用 SM2 私钥句柄解密（SDF_HandleDecrypt_ECC）。
func (s *Session) HandleDecryptECC(handle *ECCKeyHandle, algID uint32, cipher *ECCCipher) ([]byte, error) {
	cCipher, free := eccCipherAlloc(cipher)
	defer free()
	return bytesOut(cipher.L, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_HandleDecrypt_ECC(cHandle(s.h), cHandle(handle.h), C.uint(algID), cCipher, out, outLen)
	})
}

// ImportKeyWithHandleECC 使用 SM2 私钥句柄导入会话密钥（SDF_ImportKeyWithHandle_ECC）。
func (s *Session) ImportKeyWithHandleECC(handle *ECCKeyHandle, cipher *ECCCipher) (*KeyHandle, error) {
	cCipher, free := eccCipherAlloc(cipher)
	defer free()
	var h unsafe.Pointer
	rv := RV(C.SDF_ImportKeyWithHandle_ECC(cHandle(s.h), cHandle(handle.h), cCipher, &h))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// ExchangeHandleEnvelopeBaseOnECC 使用 SM2 私钥句柄进行数字信封交换（SDF_ExchangeHandleEnvelopeBaseOnECC）。
func (s *Session) ExchangeHandleEnvelopeBaseOnECC(handle *ECCKeyHandle, algID uint32, pub *ECCPublicKey, encIn *ECCCipher) (ECCCipher, error) {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cIn, freeIn := eccCipherAlloc(encIn)
	defer freeIn()
	var out C.ECCCipher
	rv := RV(C.SDF_ExchangeHandleEnvelopeBaseOnECC(cHandle(s.h), cHandle(handle.h), C.uint(algID), cPub, cIn, &out))
	if err := Err(rv); err != nil {
		return ECCCipher{}, err
	}
	return eccCipherFromC(&out), nil
}

// ImportCryptKeyPairECC 导入加密 ECC 密钥对（SDF_ImportCryptKeyPair_ECC）。
func (s *Session) ImportCryptKeyPairECC(keyIndex, forceUpdate uint32, pub *ECCPublicKey, priv *ECCPrivateKey) error {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cPriv := eccPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	rv := RV(C.SDF_ImportCryptKeyPair_ECC(cHandle(s.h), C.uint(keyIndex), C.uint(forceUpdate), cPub, cPriv))
	return Err(rv)
}

// ImportSignKeyPairECC 导入签名 ECC 密钥对（SDF_ImportSignKeyPair_ECC）。
func (s *Session) ImportSignKeyPairECC(keyIndex, forceUpdate uint32, pub *ECCPublicKey, priv *ECCPrivateKey) error {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cPriv := eccPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	rv := RV(C.SDF_ImportSignKeyPair_ECC(cHandle(s.h), C.uint(keyIndex), C.uint(forceUpdate), cPub, cPriv))
	return Err(rv)
}
