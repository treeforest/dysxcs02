package sdf

import (
	"unsafe"
)

// Device 表示密码设备句柄（SDF_OpenDevice）。
type Device struct {
	h unsafe.Pointer
}

func (d *Device) handle() unsafe.Pointer {
	return d.h
}

// Session 表示设备会话句柄（SDF_OpenSession）。
type Session struct {
	device *Device
	h      unsafe.Pointer
}

func (s *Session) handle() unsafe.Pointer {
	return s.h
}

// Device 返回会话所属设备。
func (s *Session) Device() *Device {
	return s.device
}

// KeyHandle 表示对称密钥句柄，Close 时调用 SDF_DestroyKey。
type KeyHandle struct {
	session *Session
	h       unsafe.Pointer
}

func (k *KeyHandle) handle() unsafe.Pointer {
	return k.h
}

// Session 返回密钥句柄所属会话。
func (k *KeyHandle) Session() *Session {
	return k.session
}

// AgreementHandle 表示 ECC/SM9 密钥协商中间句柄。
type AgreementHandle struct {
	session *Session
	h       unsafe.Pointer
}

func (a *AgreementHandle) handle() unsafe.Pointer {
	return a.h
}

// Session 返回协商句柄所属会话。
func (a *AgreementHandle) Session() *Session {
	return a.session
}

// ECCKeyHandle 表示 SM2 私钥句柄（SDF_GenerateKey_Handle_ECC 等）。
type ECCKeyHandle struct {
	session *Session
	h       unsafe.Pointer
}

func (e *ECCKeyHandle) handle() unsafe.Pointer {
	return e.h
}

// Session 返回 ECC 密钥句柄所属会话。
func (e *ECCKeyHandle) Session() *Session {
	return e.session
}
