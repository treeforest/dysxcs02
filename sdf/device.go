package sdf

/*
#cgo CFLAGS: -I${SRCDIR}/../include -DMAXCIPHER=16
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdf -Wl,-rpath,${SRCDIR}/../lib -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all

#include <stdlib.h>
#include <string.h>
#include "libsdf.h"
*/
import "C"



import (
	"unsafe"
)

// OpenDevice 打开密码设备（SDF_OpenDevice）。
func OpenDevice() (*Device, error) {
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_OpenDevice(hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return &Device{h: h}, nil
}

// OpenDeviceWithConfig 使用配置文件打开设备（SDF_OpenDeviceEx）。
func OpenDeviceWithConfig(iniPath string, conf *SysConf) (*Device, error) {
	cPath := cString(iniPath)
	defer freeCString(cPath)
	var cConf *C.SysConf
	if conf != nil {
		cConf = sysConfToC(conf)
		defer C.free(unsafe.Pointer(cConf))
	}
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_OpenDeviceEx(hOut, cPath, cConf)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return &Device{h: h}, nil
}

// OpenDeviceWithAddr 通过网络地址打开设备（SDF_OpenDevice_EX）。
func OpenDeviceWithAddr(addr string, port int) (*Device, error) {
	cAddr := cString(addr)
	defer freeCString(cAddr)
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_OpenDevice_EX(cAddr, C.int(port), hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return &Device{h: h}, nil
}

// Close 关闭设备（SDF_CloseDevice）。
func (d *Device) Close() error {
	if d == nil || d.h == nil {
		return nil
	}
	rv := RV(C.SDF_CloseDevice(cHandle(d.h)))
	d.h = nil
	return Err(rv)
}

// OpenSession 打开会话（SDF_OpenSession）。
func (d *Device) OpenSession() (*Session, error) {
	if d == nil || d.h == nil {
		return nil, &Error{Code: RVInArgErr}
	}
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_OpenSession(d.h, hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return &Session{device: d, h: h}, nil
}

// Close 关闭会话（SDF_CloseSession）。
func (s *Session) Close() error {
	if s == nil || s.h == nil {
		return nil
	}
	rv := RV(C.SDF_CloseSession(cHandle(s.h)))
	s.h = nil
	return Err(rv)
}

// GetDeviceInfo 获取设备信息（SDF_GetDeviceInfo）。
func (s *Session) GetDeviceInfo() (*DeviceInfo, error) {
	var info C.DEVICEINFO
	rv := RV(C.SDF_GetDeviceInfo(cHandle(s.h), &info))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return deviceInfoFromC(&info), nil
}

// GenerateRandom 生成随机数（SDF_GenerateRandom）。
func (s *Session) GenerateRandom(length uint32) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	buf := make([]byte, length)
	rv := RV(C.SDF_GenerateRandom(cHandle(s.h), C.uint(length), (*C.uchar)(unsafe.Pointer(&buf[0]))))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return buf, nil
}

// GenerateRandomExt 生成随机数（SDF_GenerateRandomExt，长度由库决定）。
func (s *Session) GenerateRandomExt(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		buf = make([]byte, defaultOutBufSize)
	}
	rv := RV(C.SDF_GenerateRandomExt(cHandle(s.h), (*C.uchar)(unsafe.Pointer(&buf[0])), C.uint(len(buf))))
	if err := Err(rv); err != nil {
		return nil, err
	}
	return buf, nil
}

// GetPrivateKeyAccessRight 获取私钥访问权限（SDF_GetPrivateKeyAccessRight）。
func (s *Session) GetPrivateKeyAccessRight(keyIndex uint32, password []byte) error {
	var puc *C.uchar
	var plen C.uint
	if len(password) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&password[0]))
		plen = C.uint(len(password))
	}
	rv := RV(C.SDF_GetPrivateKeyAccessRight(cHandle(s.h), C.uint(keyIndex), puc, plen))
	return Err(rv)
}

// ReleasePrivateKeyAccessRight 释放私钥访问权限（SDF_ReleasePrivateKeyAccessRight）。
func (s *Session) ReleasePrivateKeyAccessRight(keyIndex uint32) error {
	rv := RV(C.SDF_ReleasePrivateKeyAccessRight(cHandle(s.h), C.uint(keyIndex)))
	return Err(rv)
}

// Echo 回显测试（SDF_Echo）。
func (s *Session) Echo(data []byte) ([]byte, error) {
	var in *C.uchar
	var inLen C.uint
	if len(data) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&data[0]))
		inLen = C.uint(len(data))
	}
	return bytesOut(uint32(len(data)), func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_Echo(cHandle(s.h), in, inLen, out, outLen)
	})
}

// GetSymmKeyHandle 获取对称密钥句柄（SDF_GetSymmKeyHandle）。
func (s *Session) GetSymmKeyHandle(keyIndex uint32) (*KeyHandle, error) {
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_GetSymmKeyHandle(cHandle(s.h), C.uint(keyIndex), hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// ImportKey 导入明文对称密钥（SDF_ImportKey）。
func (s *Session) ImportKey(key []byte) (*KeyHandle, error) {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_ImportKey(cHandle(s.h), puc, C.uint(len(key)), hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}

// DestroyKey 销毁密钥句柄（SDF_DestroyKey）。
func (s *Session) DestroyKey(k *KeyHandle) error {
	if k == nil || k.h == nil {
		return nil
	}
	rv := RV(C.SDF_DestroyKey(cHandle(s.h), cHandle(k.h)))
	k.h = nil
	return Err(rv)
}

// GenerateKeyWithKEK 使用 KEK 生成密钥（SDF_GenerateKeyWithKEK）。
func (s *Session) GenerateKeyWithKEK(keyBits, algID, kekIndex uint32) (key []byte, kh *KeyHandle, err error) {
	size := uint32(defaultOutBufSize)
	for {
		buf := (*C.uchar)(C.malloc(C.size_t(size)))
		length := C.uint(size)
		var h unsafe.Pointer
		hOut := &h
		cRv := C.SDF_GenerateKeyWithKEK(cHandle(s.h), C.uint(keyBits), C.uint(algID), C.uint(kekIndex), buf, &length, hOut)
		rv := RV(cRv)
		if rv == RVBufferTooSmall {
			C.free(unsafe.Pointer(buf))
			size = uint32(length)
			continue
		}
		if err = Err(rv); err != nil {
			C.free(unsafe.Pointer(buf))
			return nil, nil, err
		}
		key = C.GoBytes(unsafe.Pointer(buf), C.int(length))
		C.free(unsafe.Pointer(buf))
		return key, newKeyHandle(s, h), nil
	}
}

// ImportKeyWithKEK 使用 KEK 导入密钥（SDF_ImportKeyWithKEK）。
func (s *Session) ImportKeyWithKEK(algID, kekIndex uint32, key []byte) (*KeyHandle, error) {
	var puc *C.uchar
	if len(key) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	var h unsafe.Pointer
	hOut := &h
	cRv := C.SDF_ImportKeyWithKEK(cHandle(s.h), C.uint(algID), C.uint(kekIndex), puc, C.uint(len(key)), hOut)
	rv := RV(cRv)
	if err := Err(rv); err != nil {
		return nil, err
	}
	return newKeyHandle(s, h), nil
}
