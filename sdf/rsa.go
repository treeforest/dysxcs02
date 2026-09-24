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

// ExportSignPublicKeyRSA 导出 RSA 签名公钥（SDF_ExportSignPublicKey_RSA）。
func (s *Session) ExportSignPublicKeyRSA(keyIndex uint32) (RSAPublicKey, error) {
	var pk C.RSArefPublicKey
	rv := RV(C.SDF_ExportSignPublicKey_RSA(cHandle(s.h), C.uint(keyIndex), &pk))
	if err := Err(rv); err != nil {
		return RSAPublicKey{}, err
	}
	return rsaPublicKeyFromC(&pk), nil
}

// ExportEncPublicKeyRSA 导出 RSA 加密公钥（SDF_ExportEncPublicKey_RSA）。
func (s *Session) ExportEncPublicKeyRSA(keyIndex uint32) (RSAPublicKey, error) {
	var pk C.RSArefPublicKey
	rv := RV(C.SDF_ExportEncPublicKey_RSA(cHandle(s.h), C.uint(keyIndex), &pk))
	if err := Err(rv); err != nil {
		return RSAPublicKey{}, err
	}
	return rsaPublicKeyFromC(&pk), nil
}

// GenerateKeyPairRSA 生成 RSA 密钥对（SDF_GenerateKeyPair_RSA）。
func (s *Session) GenerateKeyPairRSA(keyBits uint32) (RSAPublicKey, RSAPrivateKey, error) {
	var pub C.RSArefPublicKey
	var priv C.RSArefPrivateKey
	rv := RV(C.SDF_GenerateKeyPair_RSA(cHandle(s.h), C.uint(keyBits), &pub, &priv))
	if err := Err(rv); err != nil {
		return RSAPublicKey{}, RSAPrivateKey{}, err
	}
	return rsaPublicKeyFromC(&pub), rsaPrivateKeyFromC(&priv), nil
}

// GenerateKeyWithIPKRSA 使用内部 RSA 公钥生成会话密钥（SDF_GenerateKeyWithIPK_RSA）。
func (s *Session) GenerateKeyWithIPKRSA(ipkIndex, keyBits uint32) ([]byte, *KeyHandle, error) {
	size := uint32(defaultOutBufSize)
	for {
		buf := (*C.uchar)(C.malloc(C.size_t(size)))
		length := C.uint(size)
		var h unsafe.Pointer
		hOut := &h
		cRv := C.SDF_GenerateKeyWithIPK_RSA(cHandle(s.h), C.uint(ipkIndex), C.uint(keyBits), buf, &length, hOut)
		rv := RV(cRv)
		if rv == RVBufferTooSmall {
			C.free(unsafe.Pointer(buf))
			size = uint32(length)
			continue
		}
		if err := Err(rv); err != nil {
			C.free(unsafe.Pointer(buf))
			return nil, nil, err
		}
		key := C.GoBytes(unsafe.Pointer(buf), C.int(length))
		C.free(unsafe.Pointer(buf))
		return key, newKeyHandle(s, h), nil
	}
}

// GenerateKeyWithEPKRSA 使用外部 RSA 公钥生成会话密钥（SDF_GenerateKeyWithEPK_RSA）。
func (s *Session) GenerateKeyWithEPKRSA(keyBits uint32, pub *RSAPublicKey) ([]byte, *KeyHandle, error) {
	cPub := rsaPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	size := uint32(defaultOutBufSize)
	for {
		buf := (*C.uchar)(C.malloc(C.size_t(size)))
		length := C.uint(size)
		var h unsafe.Pointer
		hOut := &h
		cRv := C.SDF_GenerateKeyWithEPK_RSA(cHandle(s.h), C.uint(keyBits), cPub, buf, &length, hOut)
		rv := RV(cRv)
		if rv == RVBufferTooSmall {
			C.free(unsafe.Pointer(buf))
			size = uint32(length)
			continue
		}
		if err := Err(rv); err != nil {
			C.free(unsafe.Pointer(buf))
			return nil, nil, err
		}
		key := C.GoBytes(unsafe.Pointer(buf), C.int(length))
		C.free(unsafe.Pointer(buf))
		return key, newKeyHandle(s, h), nil
	}
}

// ImportKeyWithISKRSA 使用内部 RSA 私钥导入会话密钥（SDF_ImportKeyWithISK_RSA）。
func (s *Session) ImportKeyWithISKRSA(iskIndex uint32, key []byte) (*KeyHandle, error) {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_ImportKeyWithISK_RSA(cHandle(s.h), C.uint(iskIndex), puc, C.uint(len(key)), hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// ExchangeDigitEnvelopeBaseOnRSA RSA 数字信封交换（SDF_ExchangeDigitEnvelopeBaseOnRSA）。
func (s *Session) ExchangeDigitEnvelopeBaseOnRSA(keyIndex uint32, pub *RSAPublicKey, deInput []byte) ([]byte, error) {
	cPub := rsaPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var in *C.uchar
	if len(deInput) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&deInput[0]))
	}
	return bytesOut(uint32(len(deInput)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_ExchangeDigitEnvelopeBaseOnRSA(cHandle(s.h), C.uint(keyIndex), cPub, in, C.uint(len(deInput)), out, outLen)
	})
}

// ExternalPublicKeyOperationRSA 外部 RSA 公钥运算（SDF_ExternalPublicKeyOperation_RSA）。
func (s *Session) ExternalPublicKeyOperationRSA(pub *RSAPublicKey, data []byte) ([]byte, error) {
	cPub := rsaPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_ExternalPublicKeyOperation_RSA(cHandle(s.h), cPub, in, C.uint(len(data)), out, outLen)
	})
}

// ExternalPrivateKeyOperationRSA 外部 RSA 私钥运算（SDF_ExternalPrivateKeyOperation_RSA）。
func (s *Session) ExternalPrivateKeyOperationRSA(priv *RSAPrivateKey, data []byte) ([]byte, error) {
	cPriv := rsaPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_ExternalPrivateKeyOperation_RSA(cHandle(s.h), cPriv, in, C.uint(len(data)), out, outLen)
	})
}

// InternalPublicKeyOperationRSA 内部 RSA 公钥运算（SDF_InternalPublicKeyOperation_RSA）。
func (s *Session) InternalPublicKeyOperationRSA(keyIndex uint32, data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalPublicKeyOperation_RSA(cHandle(s.h), C.uint(keyIndex), in, C.uint(len(data)), out, outLen)
	})
}

// InternalPrivateKeyOperationRSA 内部 RSA 私钥运算（SDF_InternalPrivateKeyOperation_RSA）。
func (s *Session) InternalPrivateKeyOperationRSA(keyIndex uint32, data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalPrivateKeyOperation_RSA(cHandle(s.h), C.uint(keyIndex), in, C.uint(len(data)), out, outLen)
	})
}

// InternalEncryptRSA 内部 RSA 加密（SDF_InternalEncrypt_RSA）。
func (s *Session) InternalEncryptRSA(keyIndex uint32, data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalEncrypt_RSA(cHandle(s.h), C.uint(keyIndex), in, C.uint(len(data)), out, outLen)
	})
}

// InternalDecryptRSA 内部 RSA 解密（SDF_InternalDecrypt_RSA）。
func (s *Session) InternalDecryptRSA(keyIndex uint32, data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalDecrypt_RSA(cHandle(s.h), C.uint(keyIndex), in, C.uint(len(data)), out, outLen)
	})
}
