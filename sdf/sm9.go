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

// GenerateSignMasterKeyPairSM9 生成 SM9 签名主密钥对（SDF_GenerateSignMasterKeyPair_SM9）。
func (s *Session) GenerateSignMasterKeyPairSM9(algID uint32) (SM9MasterPrivateKey, SM9SignMasterPublicKey, error) {
	var priv C.SM9MasterPrivateKey
	var pub C.SM9SignMasterPublicKey
	rv := RV(C.SDF_GenerateSignMasterKeyPair_SM9(cHandle(s.h), C.uint(algID), &priv, &pub))
	if err := Err(rv); err != nil {
		return SM9MasterPrivateKey{}, SM9SignMasterPublicKey{}, err
	}
	return sm9MasterPrivateKeyFromC(&priv), sm9SignMasterPublicKeyFromC(&pub), nil
}

// GenerateEncMasterKeyPairSM9 生成 SM9 加密主密钥对（SDF_GenerateEncMasterKeyPair_SM9）。
func (s *Session) GenerateEncMasterKeyPairSM9(algID uint32) (SM9MasterPrivateKey, SM9EncMasterPublicKey, error) {
	var priv C.SM9MasterPrivateKey
	var pub C.SM9EncMasterPublicKey
	rv := RV(C.SDF_GenerateEncMasterKeyPair_SM9(cHandle(s.h), C.uint(algID), &priv, &pub))
	if err := Err(rv); err != nil {
		return SM9MasterPrivateKey{}, SM9EncMasterPublicKey{}, err
	}
	return sm9MasterPrivateKeyFromC(&priv), sm9EncMasterPublicKeyFromC(&pub), nil
}

// GenerateUserSignKeySM9 生成 SM9 用户签名私钥（SDF_GenerateUserSignKey_SM9）。
func (s *Session) GenerateUserSignKeySM9(algID uint32, master *SM9MasterPrivateKey, userID []byte) (SM9UserSignPrivateKey, error) {
	cMaster := sm9MasterPrivateKeyToC(master)
	defer C.free(unsafe.Pointer(cMaster))
	var vk C.SM9UserSignPrivateKey
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_GenerateUserSignKey_SM9(cHandle(s.h), C.uint(algID), cMaster, id, C.uint(len(userID)), &vk))
	if err := Err(rv); err != nil {
		return SM9UserSignPrivateKey{}, err
	}
	return sm9UserSignPrivateKeyFromC(&vk), nil
}

// GenerateUserEncKeySM9 生成 SM9 用户加密私钥（SDF_GenerateUserEncKey_SM9）。
func (s *Session) GenerateUserEncKeySM9(algID uint32, master *SM9MasterPrivateKey, userID []byte) (SM9UserEncPrivateKey, error) {
	cMaster := sm9MasterPrivateKeyToC(master)
	defer C.free(unsafe.Pointer(cMaster))
	var vk C.SM9UserEncPrivateKey
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_GenerateUserEncKey_SM9(cHandle(s.h), C.uint(algID), cMaster, id, C.uint(len(userID)), &vk))
	if err := Err(rv); err != nil {
		return SM9UserEncPrivateKey{}, err
	}
	return sm9UserEncPrivateKeyFromC(&vk), nil
}

// ExportSignMasterPublicKeySM9 导出 SM9 签名主公钥（SDF_ExportSignMasterPublicKey_SM9）。
func (s *Session) ExportSignMasterPublicKeySM9(masterKeyIndex uint32) (SM9SignMasterPublicKey, error) {
	var pub C.SM9SignMasterPublicKey
	rv := RV(C.SDF_ExportSignMasterPublicKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), &pub))
	if err := Err(rv); err != nil {
		return SM9SignMasterPublicKey{}, err
	}
	return sm9SignMasterPublicKeyFromC(&pub), nil
}

// ExportEncMasterPublicKeySM9 导出 SM9 加密主公钥（SDF_ExportEncMasterPublicKey_SM9）。
func (s *Session) ExportEncMasterPublicKeySM9(masterKeyIndex uint32) (SM9EncMasterPublicKey, error) {
	var pub C.SM9EncMasterPublicKey
	rv := RV(C.SDF_ExportEncMasterPublicKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), &pub))
	if err := Err(rv); err != nil {
		return SM9EncMasterPublicKey{}, err
	}
	return sm9EncMasterPublicKeyFromC(&pub), nil
}

// CreateSignMasterKeyPairSM9 在设备内创建 SM9 签名主密钥对（SDF_CreateSignMasterKeyPair_SM9）。
func (s *Session) CreateSignMasterKeyPairSM9(masterKeyIndex uint32) (SM9SignMasterPublicKey, error) {
	var pub C.SM9SignMasterPublicKey
	rv := RV(C.SDF_CreateSignMasterKeyPair_SM9(cHandle(s.h), C.uint(masterKeyIndex), &pub))
	if err := Err(rv); err != nil {
		return SM9SignMasterPublicKey{}, err
	}
	return sm9SignMasterPublicKeyFromC(&pub), nil
}

// CreateEncMasterKeyPairSM9 在设备内创建 SM9 加密主密钥对（SDF_CreateEncMasterKeyPair_SM9）。
func (s *Session) CreateEncMasterKeyPairSM9(masterKeyIndex uint32) (SM9EncMasterPublicKey, error) {
	var pub C.SM9EncMasterPublicKey
	rv := RV(C.SDF_CreateEncMasterKeyPair_SM9(cHandle(s.h), C.uint(masterKeyIndex), &pub))
	if err := Err(rv); err != nil {
		return SM9EncMasterPublicKey{}, err
	}
	return sm9EncMasterPublicKeyFromC(&pub), nil
}

// CreateUserSignKeySM9 在设备内创建 SM9 用户签名密钥（SDF_CreateUserSignKey_SM9）。
func (s *Session) CreateUserSignKeySM9(masterKeyIndex, userKeyIndex uint32, userID []byte) error {
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_CreateUserSignKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex), id, C.uint(len(userID))))
	return Err(rv)
}

// CreateUserEncKeySM9 在设备内创建 SM9 用户加密密钥（SDF_CreateUserEncKey_SM9）。
func (s *Session) CreateUserEncKeySM9(masterKeyIndex, userKeyIndex uint32, userID []byte) error {
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_CreateUserEncKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex), id, C.uint(len(userID))))
	return Err(rv)
}

// ImportSignMasterKeySM9 导入 SM9 签名主密钥（SDF_ImportSignMasterKey_SM9）。
func (s *Session) ImportSignMasterKeySM9(masterKeyIndex uint32, priv *SM9MasterPrivateKey, pub *SM9SignMasterPublicKey) error {
	cPriv := sm9MasterPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	cPub := sm9SignMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	rv := RV(C.SDF_ImportSignMasterKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), cPriv, cPub))
	return Err(rv)
}

// ImportEncMasterKeySM9 导入 SM9 加密主密钥（SDF_ImportEncMasterKey_SM9）。
func (s *Session) ImportEncMasterKeySM9(masterKeyIndex uint32, priv *SM9MasterPrivateKey, pub *SM9EncMasterPublicKey) error {
	cPriv := sm9MasterPrivateKeyToC(priv)
	defer C.free(unsafe.Pointer(cPriv))
	cPub := sm9EncMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	rv := RV(C.SDF_ImportEncMasterKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), cPriv, cPub))
	return Err(rv)
}

// ImportUserSignKeySM9 导入 SM9 用户签名密钥（SDF_ImportUserSignKey_SM9）。
func (s *Session) ImportUserSignKeySM9(masterKeyIndex, userKeyIndex uint32, userID []byte, vk *SM9UserSignPrivateKey) error {
	cVK := sm9UserSignPrivateKeyToC(vk)
	defer C.free(unsafe.Pointer(cVK))
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_ImportUserSignKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex), id, C.uint(len(userID)), cVK))
	return Err(rv)
}

// ImportUserEncKeySM9 导入 SM9 用户加密密钥（SDF_ImportUserEncKey_SM9）。
func (s *Session) ImportUserEncKeySM9(masterKeyIndex, userKeyIndex uint32, userID []byte, vk *SM9UserEncPrivateKey) error {
	cVK := sm9UserEncPrivateKeyToC(vk)
	defer C.free(unsafe.Pointer(cVK))
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_ImportUserEncKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex), id, C.uint(len(userID)), cVK))
	return Err(rv)
}

// DeleteSignMasterKeySM9 删除 SM9 签名主密钥（SDF_DeleteSignMasterKey_SM9）。
func (s *Session) DeleteSignMasterKeySM9(masterKeyIndex uint32) error {
	rv := RV(C.SDF_DeleteSignMasterKey_SM9(cHandle(s.h), C.uint(masterKeyIndex)))
	return Err(rv)
}

// DeleteEncMasterKeySM9 删除 SM9 加密主密钥（SDF_DeleteEncMasterKey_SM9）。
func (s *Session) DeleteEncMasterKeySM9(masterKeyIndex uint32) error {
	rv := RV(C.SDF_DeleteEncMasterKey_SM9(cHandle(s.h), C.uint(masterKeyIndex)))
	return Err(rv)
}

// DeleteSignUserKeySM9 删除 SM9 用户签名密钥（SDF_DeleteSignUserKey_SM9）。
func (s *Session) DeleteSignUserKeySM9(masterKeyIndex, userKeyIndex uint32) error {
	rv := RV(C.SDF_DeleteSignUserKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex)))
	return Err(rv)
}

// DeleteEncUserKeySM9 删除 SM9 用户加密密钥（SDF_DeleteEncUserKey_SM9）。
func (s *Session) DeleteEncUserKeySM9(masterKeyIndex, userKeyIndex uint32) error {
	rv := RV(C.SDF_DeleteEncUserKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(userKeyIndex)))
	return Err(rv)
}

// SignWithMasterEPKSM9 使用外部主公钥 SM9 签名（SDF_SignWithMasterEPK_SM9）。
func (s *Session) SignWithMasterEPKSM9(pub *SM9SignMasterPublicKey, vk *SM9UserSignPrivateKey, data []byte) (SM9Signature, error) {
	cPub := sm9SignMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cVK := sm9UserSignPrivateKeyToC(vk)
	defer C.free(unsafe.Pointer(cVK))
	var sig C.SM9Signature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_SignWithMasterEPK_SM9(cHandle(s.h), cPub, cVK, puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return SM9Signature{}, err
	}
	return sm9SignatureFromC(&sig), nil
}

// InternalSignWithMasterEPKSM9 内部使用外部主公钥 SM9 签名（SDF_InternalSignWithMasterEPK_SM9）。
func (s *Session) InternalSignWithMasterEPKSM9(pub *SM9SignMasterPublicKey, iskIndex uint32, data []byte) (SM9Signature, error) {
	cPub := sm9SignMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var sig C.SM9Signature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSignWithMasterEPK_SM9(cHandle(s.h), cPub, C.uint(iskIndex), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return SM9Signature{}, err
	}
	return sm9SignatureFromC(&sig), nil
}

// InternalSignWithMasterIPKSM9 内部使用主密钥索引 SM9 签名（SDF_InternalSignWithMasterIPK_SM9）。
func (s *Session) InternalSignWithMasterIPKSM9(masterKeyIndex, iskIndex uint32, data []byte) (SM9Signature, error) {
	var sig C.SM9Signature
	var puc *C.uchar
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_InternalSignWithMasterIPK_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(iskIndex), puc, C.uint(len(data)), &sig))
	if err := Err(rv); err != nil {
		return SM9Signature{}, err
	}
	return sm9SignatureFromC(&sig), nil
}

// VerifyWithMasterEPKSM9 使用外部主公钥 SM9 验签（SDF_VerifyWithMasterEPK_SM9）。
func (s *Session) VerifyWithMasterEPKSM9(pub *SM9SignMasterPublicKey, userID, data []byte, sig *SM9Signature) error {
	cPub := sm9SignMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	cSig := sm9SignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var uid, puc *C.uchar
	if len(userID) > 0 {
		uid = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_VerifyWithMasterEPK_SM9(cHandle(s.h), cPub, uid, C.uint(len(userID)), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// VerifyWithMasterIPKSM9 使用主密钥索引 SM9 验签（SDF_VerifyWithMasterIPK_SM9）。
func (s *Session) VerifyWithMasterIPKSM9(masterKeyIndex uint32, userID, data []byte, sig *SM9Signature) error {
	cSig := sm9SignatureToC(sig)
	defer C.free(unsafe.Pointer(cSig))
	var uid, puc *C.uchar
	if len(userID) > 0 {
		uid = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	rv := RV(C.SDF_VerifyWithMasterIPK_SM9(cHandle(s.h), C.uint(masterKeyIndex), uid, C.uint(len(userID)), puc, C.uint(len(data)), cSig))
	return Err(rv)
}

// EncryptWithMasterEPKSM9 使用外部主公钥 SM9 加密（SDF_EncryptWithMasterEPK_SM9）。
func (s *Session) EncryptWithMasterEPKSM9(pub *SM9EncMasterPublicKey, userID []byte, algID uint32, iv, data []byte) (SM9Cipher, error) {
	cPub := sm9EncMasterPublicKeyToC(pub)
	defer C.free(unsafe.Pointer(cPub))
	var uid, ivPtr, puc *C.uchar
	if len(userID) > 0 {
		uid = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	var enc C.SM9Cipher
	rv := RV(C.SDF_EncryptWithMasterEPK_SM9(cHandle(s.h), cPub, uid, C.uint(len(userID)), C.uint(algID), ivPtr, C.uint(len(iv)), puc, C.uint(len(data)), &enc))
	if err := Err(rv); err != nil {
		return SM9Cipher{}, err
	}
	return sm9CipherFromC(&enc), nil
}

// EncryptWithMasterIPKSM9 使用主密钥索引 SM9 加密（SDF_EncryptWithMasterIPK_SM9）。
func (s *Session) EncryptWithMasterIPKSM9(masterKeyIndex uint32, userID []byte, algID uint32, iv, data []byte) (SM9Cipher, error) {
	var uid, ivPtr, puc *C.uchar
	if len(userID) > 0 {
		uid = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	if len(data) > 0 {
		puc = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	var enc C.SM9Cipher
	rv := RV(C.SDF_EncryptWithMasterIPK_SM9(cHandle(s.h), C.uint(masterKeyIndex), uid, C.uint(len(userID)), C.uint(algID), ivPtr, C.uint(len(iv)), puc, C.uint(len(data)), &enc))
	if err := Err(rv); err != nil {
		return SM9Cipher{}, err
	}
	return sm9CipherFromC(&enc), nil
}

// DecryptWithUserEncKeySM9 使用用户加密私钥 SM9 解密（SDF_DecryptWithUserEncKey_SM9）。
func (s *Session) DecryptWithUserEncKeySM9(vk *SM9UserEncPrivateKey, userID, iv []byte, enc *SM9Cipher) ([]byte, error) {
	cVK := sm9UserEncPrivateKeyToC(vk)
	defer C.free(unsafe.Pointer(cVK))
	cEnc, freeEnc := sm9CipherAlloc(enc)
	defer freeEnc()
	var uid, ivPtr *C.uchar
	if len(userID) > 0 {
		uid = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return bytesOut(enc.L, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_DecryptWithUserEncKey_SM9(cHandle(s.h), cVK, uid, C.uint(len(userID)), ivPtr, C.uint(len(iv)), cEnc, out, outLen)
	})
}

// DecryptWithInternalKeySM9 使用内部密钥 SM9 解密（SDF_DecryptWithInternalKey_SM9）。
func (s *Session) DecryptWithInternalKeySM9(masterKeyIndex, keyIndex uint32, iv []byte, enc *SM9Cipher) ([]byte, error) {
	cEnc, freeEnc := sm9CipherAlloc(enc)
	defer freeEnc()
	var ivPtr *C.uchar
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	return bytesOut(enc.L, func(out *C.uchar, outLen *C.uint) C.int {
		return C.SDF_DecryptWithInternalKey_SM9(cHandle(s.h), C.uint(masterKeyIndex), C.uint(keyIndex), ivPtr, C.uint(len(iv)), cEnc, out, outLen)
	})
}

// GenerateUserSignKeyWithIPKSM9 使用内部主密钥生成用户签名私钥（SDF_GenerateUserSignKeyWithIPK_SM9）。
func (s *Session) GenerateUserSignKeyWithIPKSM9(masterKeyIndex uint32, userID []byte) (SM9UserSignPrivateKey, error) {
	var vk C.SM9UserSignPrivateKey
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_GenerateUserSignKeyWithIPK_SM9(cHandle(s.h), C.uint(masterKeyIndex), id, C.uint(len(userID)), &vk))
	if err := Err(rv); err != nil {
		return SM9UserSignPrivateKey{}, err
	}
	return sm9UserSignPrivateKeyFromC(&vk), nil
}

// GenerateUserEncKeyWithIPKSM9 使用内部主密钥生成用户加密私钥（SDF_GenerateUserEncKeyWithIPK_SM9）。
func (s *Session) GenerateUserEncKeyWithIPKSM9(masterKeyIndex uint32, userID []byte) (SM9UserEncPrivateKey, error) {
	var vk C.SM9UserEncPrivateKey
	var id *C.uchar
	if len(userID) > 0 {
		id = (*C.uchar)(unsafe.Pointer(&userID[0]))
	}
	rv := RV(C.SDF_GenerateUserEncKeyWithIPK_SM9(cHandle(s.h), C.uint(masterKeyIndex), id, C.uint(len(userID)), &vk))
	if err := Err(rv); err != nil {
		return SM9UserEncPrivateKey{}, err
	}
	return sm9UserEncPrivateKeyFromC(&vk), nil
}
