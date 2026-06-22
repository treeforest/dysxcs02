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

// Encrypt 对称加密（SDF_Encrypt）。
func (s *Session) Encrypt(kh *KeyHandle, algID uint32, iv, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)+16), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_Encrypt(cHandle(s.h), cHandle(kh.h), C.uint(algID), ivPtr, dataPtr, C.uint(len(data)), out, outLen)
	})
}

// Decrypt 对称解密（SDF_Decrypt）。
func (s *Session) Decrypt(kh *KeyHandle, algID uint32, iv, encData []byte) ([]byte, error) {
	var ivPtr, encPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(encData) > 0 {
		encPtr = (*C.uchar)(unsafe.Pointer(&encData[0]))
	}
	return bytesOut(uint32(len(encData)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_Decrypt(cHandle(s.h), cHandle(kh.h), C.uint(algID), ivPtr, encPtr, C.uint(len(encData)), out, outLen)
	})
}

// CalculateMAC 计算 MAC（SDF_CalculateMAC）。
func (s *Session) CalculateMAC(kh *KeyHandle, algID uint32, iv, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(32, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_CalculateMAC(cHandle(s.h), cHandle(kh.h), C.uint(algID), ivPtr, dataPtr, C.uint(len(data)), out, outLen)
	})
}

// InternalEncrypt 内部对称加密（SDF_InternalEncrypt）。
func (s *Session) InternalEncrypt(algID, keyIndex uint32, iv, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)+16), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalEncrypt(cHandle(s.h), C.uint(algID), C.uint(keyIndex), ivPtr, dataPtr, C.uint(len(data)), out, outLen)
	})
}

// InternalDecrypt 内部对称解密（SDF_InternalDecrypt）。
func (s *Session) InternalDecrypt(algID, keyIndex uint32, iv, encData []byte) ([]byte, error) {
	var ivPtr, encPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(encData) > 0 {
		encPtr = (*C.uchar)(unsafe.Pointer(&encData[0]))
	}
	return bytesOut(uint32(len(encData)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalDecrypt(cHandle(s.h), C.uint(algID), C.uint(keyIndex), ivPtr, encPtr, C.uint(len(encData)), out, outLen)
	})
}

// InternalMAC 内部 MAC（SDF_InternalMAC）。
func (s *Session) InternalMAC(algID, keyIndex uint32, iv, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(32, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_InternalMAC(cHandle(s.h), C.uint(algID), C.uint(keyIndex), ivPtr, dataPtr, C.uint(len(data)), out, outLen)
	})
}

// EncryptIndex 按索引对称加密（SDF_Encrypt_Index）。
func (s *Session) EncryptIndex(algID uint32, iv []byte, keyIndex uint32, data []byte) ([]byte, error) {
	var ivPtr, dataPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(uint32(len(data)+16), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_Encrypt_Index(cHandle(s.h), C.uint(algID), ivPtr, C.uint(keyIndex), dataPtr, C.uint(len(data)), out, outLen)
	})
}

// DecryptIndex 按索引对称解密（SDF_Decrypt_Index）。
func (s *Session) DecryptIndex(algID uint32, iv []byte, keyIndex uint32, encData []byte) ([]byte, error) {
	var ivPtr, encPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(encData) > 0 {
		encPtr = (*C.uchar)(unsafe.Pointer(&encData[0]))
	}
	return bytesOut(uint32(len(encData)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_Decrypt_Index(cHandle(s.h), C.uint(algID), ivPtr, C.uint(keyIndex), encPtr, C.uint(len(encData)), out, outLen)
	})
}

// HMAC 计算 HMAC（SDF_HMAC）。
func (s *Session) HMAC(kh *KeyHandle, algID uint32, data []byte) ([]byte, error) {
	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	return bytesOut(64, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_HMAC(cHandle(s.h), cHandle(kh.h), C.uint(algID), dataPtr, C.uint(len(data)), out, outLen)
	})
}

// HMACBatch 批量 HMAC（SDF_HMACBatch）。
func (s *Session) HMACBatch(kh *KeyHandle, algID uint32, dataArray [][]byte) ([][]byte, error) {
	n := len(dataArray)
	if n == 0 {
		return nil, nil
	}
	dataPtrs := make([]*C.uchar, n)
	dataLens := make([]C.uint, n)
	hmacPtrs := make([]*C.uchar, n)
	hmacLens := make([]C.uint, n)
	hmacBufs := make([][]byte, n)
	for i, d := range dataArray {
		if len(d) > 0 {
			dataPtrs[i] = (*C.uchar)(unsafe.Pointer(&d[0]))
		}
		dataLens[i] = C.uint(len(d))
		hmacBufs[i] = make([]byte, 64)
		hmacPtrs[i] = (*C.uchar)(unsafe.Pointer(&hmacBufs[i][0]))
		hmacLens[i] = C.uint(len(hmacBufs[i]))
	}
	rv := RV(C.SDF_HMACBatch(cHandle(s.h), cHandle(kh.h), C.uint(algID), &dataPtrs[0], &dataLens[0], &hmacPtrs[0], &hmacLens[0], C.uint(n)))
	if err := Err(rv); err != nil {
		return nil, err
	}
	result := make([][]byte, n)
	for i := range hmacBufs {
		result[i] = hmacBufs[i][:hmacLens[i]]
	}
	return result, nil
}
