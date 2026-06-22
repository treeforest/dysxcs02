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

// GetSM2DecEncTemp 获取 SM2 加解密临时参数（SDF_GETSM2_DECENC_Temp）。
func GetSM2DecEncTemp() error {
	rv := RV(C.SDF_GETSM2_DECENC_Temp())
	return Err(rv)
}

// GenerateKeyPairWithKEKECC 使用 KEK 生成 ECC 密钥对（SDF_GenerateKeyPairWithKEK_ECC）。
func (s *Session) GenerateKeyPairWithKEKECC(algID, keyBits, kekIndex uint32) (ECCPublicKey, []byte, error) {
	var pub C.ECCrefPublicKey
	encPriv := make([]byte, ECCrefMaxLen)
	rv := RV(C.SDF_GenerateKeyPairWithKEK_ECC(cHandle(s.h), C.uint(algID), C.uint(keyBits), C.uint(kekIndex), &pub, (*C.uchar)(unsafe.Pointer(&encPriv[0]))))
	if err := Err(rv); err != nil {
		return ECCPublicKey{}, nil, err
	}
	return eccPublicKeyFromC(&pub), encPriv, nil
}

// ImportKeyPairWithKEKECC 使用 KEK 导入 ECC 密钥对（SDF_ImportKeyPairWithKEK_ECC）。
func (s *Session) ImportKeyPairWithKEKECC(algID, keyBits, kekIndex, keyPairIndex, eccAlgID uint32, pub *ECCPublicKey, encPrivKey []byte) error {
	cPub := eccPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var puc *C.uchar
	if len(encPrivKey) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&encPrivKey[0]))
	}
	rv := RV(C.SDF_ImportKeyPairWithKEK_ECC(cHandle(s.h), C.uint(algID), C.uint(keyBits), C.uint(kekIndex), C.uint(keyPairIndex), C.uint(eccAlgID), cPub, puc))
	return Err(rv)
}

// ImportKeyWithKEKEX 扩展 KEK 导入密钥（SDF_ImportKeyWithKEK_EX）。
func (s *Session) ImportKeyWithKEKEX(algID, kekIndex, keyIndex uint32, key []byte) error {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	rv := RV(C.SDF_ImportKeyWithKEK_EX(cHandle(s.h), C.uint(algID), C.uint(kekIndex), C.uint(keyIndex), puc, C.uint(len(key))))
	return Err(rv)
}

// ImportEncData 导入加密数据（API_ImportEncData）。
func (s *Session) ImportEncData(data []byte, decIndex, algID uint32, iv []byte, index, saveOpt, cut, cutLen uint32, reserve unsafe.Pointer) error {
	var puc, ivPtr *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	rv := RV(C.API_ImportEncData(cHandle(s.h), puc, C.uint(len(data)), C.uint(decIndex), C.uint(algID), ivPtr, C.uint(index), C.uint(saveOpt), C.uint(cut), C.uint(cutLen), reserve))
	return Err(rv)
}

// EncDataIndex 按索引加密数据（API_EncData_Index）。
func (s *Session) EncDataIndex(keyIndex, algID uint32, iv, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)+16), func(out *C.uchar, outLen *C.uint) C.int {
		return C.API_EncData_Index(cHandle(s.h), C.uint(keyIndex), C.uint(algID), ivPtr, dataPtr, C.uint(len(data)), out, outLen)
	})
}

// GenRandData 生成并可选保存随机数（API_GenRandData）。
func (s *Session) GenRandData(length, index, saveOpt uint32) ([]byte, error) {
	buf := make([]byte, length)
	rv := RV(C.API_GenRandData(cHandle(s.h), (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(length), C.uint(index), C.uint(saveOpt)))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return buf, nil
}

// ExportEncData 导出加密数据（API_ExportEncData）。
func (s *Session) ExportEncData(encIndex, algID uint32, iv []byte, index, saveOpt, cut, cutLen uint32, reserve unsafe.Pointer) ([]byte, error) {
	var ivPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return bytesOut(defaultOutBufSize, func(out *C.uchar, outLen *C.uint) C.int {
		return C.API_ExportEncData(cHandle(s.h), out, outLen, C.uint(encIndex), C.uint(algID), ivPtr, C.uint(index), C.uint(saveOpt), C.uint(cut), C.uint(cutLen), reserve)
	})
}

// ImportEncDataCov 导入加密数据（覆盖模式，API_ImportEncData_Cov）。
func (s *Session) ImportEncDataCov(data []byte, decIndex, algID uint32, iv []byte, index, saveOpt, cut, cutLen, isCover uint32, reserve unsafe.Pointer) error {
	var puc, ivPtr *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	rv := RV(C.API_ImportEncData_Cov(cHandle(s.h), puc, C.uint(len(data)), C.uint(decIndex), C.uint(algID), ivPtr, C.uint(index), C.uint(saveOpt), C.uint(cut), C.uint(cutLen), C.uint(isCover), reserve))
	return Err(rv)
}

// ExportEncDataCov 导出加密数据（覆盖模式，API_ExportEncData_Cov）。
func (s *Session) ExportEncDataCov(encIndex, algID uint32, iv []byte, index, saveOpt, cut, cutLen, isCover uint32, reserve unsafe.Pointer) ([]byte, error) {
	var ivPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return bytesOut(defaultOutBufSize, func(out *C.uchar, outLen *C.uint) C.int {
		return C.API_ExportEncData_Cov(cHandle(s.h), out, outLen, C.uint(encIndex), C.uint(algID), ivPtr, C.uint(index), C.uint(saveOpt), C.uint(cut), C.uint(cutLen), C.uint(isCover), reserve)
	})
}

// EGenerateKeyPair 扩展生成密钥对（SDFE_GenerateKeyPair）。
func (s *Session) EGenerateKeyPair(algID, keyIndex, keyBits uint32) error {
	rv := RV(C.SDFE_GenerateKeyPair(cHandle(s.h), C.uint(algID), C.uint(keyIndex), C.uint(keyBits)))
	return Err(rv)
}

// EImportKeyPair 扩展导入密钥对（SDFE_ImportKeyPair）。
func (s *Session) EImportKeyPair(algID, keyIndex uint32, publicKey, privateKey []byte) error {
	var pubPtr, privPtr *C.uchar
	if len(publicKey) > 0 {
		pubPtr = (*C.uchar)(unsafe.Pointer(&publicKey[0]))
	}
	if len(privateKey) > 0 {
		privPtr = (*C.uchar)(unsafe.Pointer(&privateKey[0]))
	}
	rv := RV(C.SDFE_ImportKeyPair(cHandle(s.h), C.uint(algID), C.uint(keyIndex), pubPtr, C.uint(len(publicKey)), privPtr, C.uint(len(privateKey))))
	return Err(rv)
}

// EDeleteKeyPair 扩展删除密钥对（SDFE_DeleteKeyPair）。
func (s *Session) EDeleteKeyPair(algID, keyIndex uint32) error {
	rv := RV(C.SDFE_DeleteKeyPair(cHandle(s.h), C.uint(algID), C.uint(keyIndex)))
	return Err(rv)
}

// EGenerateKEK 扩展生成 KEK（SDFE_GenerateKEK）。
func (s *Session) EGenerateKEK(algID, keyIndex, keyBits uint32) error {
	rv := RV(C.SDFE_GenerateKEK(cHandle(s.h), C.uint(algID), C.uint(keyIndex), C.uint(keyBits)))
	return Err(rv)
}

// EDeleteKEK 扩展删除 KEK（SDFE_DeleteKEK）。
func (s *Session) EDeleteKEK(algID, keyIndex uint32) error {
	rv := RV(C.SDFE_DeleteKEK(cHandle(s.h), C.uint(algID), C.uint(keyIndex)))
	return Err(rv)
}

// EImportKEK 扩展导入 KEK（SDFE_ImportKEK）。
func (s *Session) EImportKEK(kekIndex uint32, key []byte, keyBits uint32) error {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	rv := RV(C.SDFE_ImportKEK(cHandle(s.h), C.uint(kekIndex), puc, C.uint(keyBits)))
	return Err(rv)
}
