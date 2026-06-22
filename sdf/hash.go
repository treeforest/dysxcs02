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

// HashInit 初始化哈希（SDF_HashInit）。
func (s *Session) HashInit(algID uint32, pub *ECCPublicKey, id []byte) error {
	var cPub *C.ECCrefPublicKey
	if pub != nil {
		cPub = eccPublicKeyToC(pub)
		defer C.free(unsafe.Pointer(cPub))
	}
	var pucID *C.uchar
	if len(id) > 0 {
		pucID = (*C.uchar)(unsafe.Pointer(&id[0]))
	}
	rv := RV(C.SDF_HashInit(cHandle(s.h), C.uint(algID), cPub, pucID, C.uint(len(id))))
	return Err(rv)
}

// HashUpdate 更新哈希（SDF_HashUpdate）。
func (s *Session) HashUpdate(data []byte) error {
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_HashUpdate(cHandle(s.h), puc, C.uint(len(data))))
	return Err(rv)
}

// HashFinal 结束哈希（SDF_HashFinal）。
func (s *Session) HashFinal() ([]byte, error) {
	return bytesOut(64, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_HashFinal(cHandle(s.h), out, outLen)
	})
}

// Hash 便捷方法：一次性计算哈希。
func (s *Session) Hash(algID uint32, pub *ECCPublicKey, id, data []byte) ([]byte, error) {
	if err := s.HashInit(algID, pub, id); err != nil {
		return nil, err
	}
	if err := s.HashUpdate(data); err != nil {
		return nil, err
	}
	return s.HashFinal()
}

// HashEInit 扩展哈希初始化（SDFE_HashInit）。
func (s *Session) HashEInit(algID uint32, pub *ECCPublicKey, id []byte) (HashCtx, error) {
	var ctx HashCtx
	var cPub *C.ECCrefPublicKey
	if pub != nil {
		cPub = eccPublicKeyToC(pub)
		defer C.free(unsafe.Pointer(cPub))
	}
	var pucID *C.uchar
	if len(id) > 0 {
		pucID = (*C.uchar)(unsafe.Pointer(&id[0]))
	}
	rv := RV(C.SDFE_HashInit(cHandle(s.h), C.uint(algID), cPub, pucID, C.uint(len(id)), hashCtxToC(&ctx)))
	if err := Err(rv); err != nil {
		return HashCtx{}, err
	}
	return ctx, nil
}

// HashEUpdate 扩展哈希更新（SDFE_HashUpdate）。
func (s *Session) HashEUpdate(ctx *HashCtx, data []byte) error {
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDFE_HashUpdate(cHandle(s.h), hashCtxToC(ctx), puc, C.uint(len(data))))
	return Err(rv)
}

// HashEFinal 扩展哈希结束（SDFE_HashFinal）。
func (s *Session) HashEFinal(ctx *HashCtx) ([]byte, error) {
	return bytesOut(64, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDFE_HashFinal(cHandle(s.h), hashCtxToC(ctx), out, outLen)
	})
}

// HmacEInit 扩展 HMAC 初始化（SDFE_HmacInit）。
func (s *Session) HmacEInit(algID, keyIndex uint32, key []byte) error {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	rv := RV(C.SDFE_HmacInit(cHandle(s.h), C.uint(algID), C.uint(keyIndex), puc, C.uint(len(key))))
	return Err(rv)
}

// HmacEUpdate 扩展 HMAC 更新（SDFE_HmacUpdate）。
func (s *Session) HmacEUpdate(data []byte) error {
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDFE_HmacUpdate(cHandle(s.h), puc, C.uint(len(data))))
	return Err(rv)
}

// HmacEFinal 扩展 HMAC 结束（SDFE_HmacFinal）。
func (s *Session) HmacEFinal() ([]byte, error) {
	return bytesOut(64, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDFE_HmacFinal(cHandle(s.h), out, outLen)
	})
}

// GcmEInit 扩展 GCM 初始化（SDFE_GcmInit）。
func (s *Session) GcmEInit(mode int, algID, keyIndex uint32, iv, key, aad []byte) error {
	var ivPtr, keyPtr, aadPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	if len(aad) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&aad[0]))
	}
	rv := RV(C.SDFE_GcmInit(cHandle(s.h), C.int(mode), C.uint(algID), C.uint(keyIndex), ivPtr, C.int(len(iv)), keyPtr, C.uint(len(key)), aadPtr, C.size_t(len(aad))))
	return Err(rv)
}

// GcmEUpdate 扩展 GCM 更新（SDFE_GcmUpdate）。
func (s *Session) GcmEUpdate(data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	outLen := C.int(len(data) + 16)
	out := make([]byte, outLen)
	cOutLen := outLen
	rv := RV(C.SDFE_GcmUpdate(cHandle(s.h), in, C.int(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return out[:cOutLen], nil
}

// GcmEFinal 扩展 GCM 结束（SDFE_GcmFinal）。
func (s *Session) GcmEFinal(outLen int) (tag []byte, err error) {
	tag = make([]byte, 16)
	tagLen := C.int(len(tag))
	rv := RV(C.SDFE_GcmFinal(cHandle(s.h), C.int(outLen), (*C.uchar)(unsafe.Pointer(&tag[0])), &tagLen))
	if err = Err(rv); err != nil {
		return nil, err
	}
	return tag[:tagLen], nil
}

// CcmEInit 扩展 CCM 初始化（SDFE_CcmInit）。
func (s *Session) CcmEInit(mode int, algID, keyIndex uint32, length int, iv, key, aad []byte) error {
	var ivPtr, keyPtr, aadPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	if len(aad) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&aad[0]))
	}
	rv := RV(C.SDFE_CcmInit(cHandle(s.h), C.int(mode), C.uint(algID), C.uint(keyIndex), C.int(length), ivPtr, C.int(len(iv)), keyPtr, C.uint(len(key)), aadPtr, C.size_t(len(aad))))
	return Err(rv)
}

// CcmEUpdate 扩展 CCM 更新（SDFE_CcmUpdate）。
func (s *Session) CcmEUpdate(data []byte) ([]byte, error) {
	var in *C.uchar
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	outLen := C.int(len(data) + 16)
	out := make([]byte, outLen)
	cOutLen := outLen
	rv := RV(C.SDFE_CcmUpdate(cHandle(s.h), in, C.int(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return out[:cOutLen], nil
}

// CcmEFinal 扩展 CCM 结束（SDFE_CcmFinal）。
func (s *Session) CcmEFinal() (tag []byte, err error) {
	tag = make([]byte, 16)
	tagLen := C.int(len(tag))
	rv := RV(C.SDFE_CcmFinal(cHandle(s.h), (*C.uchar)(unsafe.Pointer(&tag[0])), &tagLen))
	if err = Err(rv); err != nil {
		return nil, err
	}
	return tag[:tagLen], nil
}
