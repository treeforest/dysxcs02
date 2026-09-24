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

func cgoArrayPtr[T any](elem *T) unsafe.Pointer {
	return unsafe.Pointer(elem)
}

func cgoBytes(ptr unsafe.Pointer, length int) []byte {
	return C.GoBytes(ptr, C.int(length))
}

func deviceInfoFromC(c *C.DEVICEINFO) *DeviceInfo {
	if c == nil {
		return nil
	}
	return &DeviceInfo{
		IssuerName:      *(*[40]byte)(unsafe.Pointer(&c.IssuerName)),
		DeviceName:      *(*[16]byte)(unsafe.Pointer(&c.DeviceName)),
		DeviceSerial:    *(*[16]byte)(unsafe.Pointer(&c.DeviceSerial)),
		DeviceVersion:   uint32(c.DeviceVersion),
		StandardVersion: uint32(c.StandardVersion),
		AsymAlgAbility:  [2]uint32{uint32(c.AsymAlgAbility[0]), uint32(c.AsymAlgAbility[1])},
		SymAlgAbility:   uint32(c.SymAlgAbility),
		HashAlgAbility:  uint32(c.HashAlgAbility),
		BufferSize:      uint32(c.BufferSize),
	}
}

func sysConfToC(g *SysConf) *C.SysConf {
	if g == nil {
		return nil
	}
	c := (*C.SysConf)(C.malloc(C.size_t(unsafe.Sizeof(C.SysConf{}))))
	c.timeout = C.uint(g.Timeout)
	c.worktype = C.uint(g.WorkType)
	c.maxcipher = C.uint(g.MaxCipher)
	for i := range MaxCipherHosts {
		C.memcpy(cgoArrayPtr(&c.ip[i][0]), cgoArrayPtr(&g.IP[i][0]), 16)
		c.port[i] = C.uint(g.Port[i])
	}
	return c
}

func rsaPublicKeyFromC(c *C.RSArefPublicKey) RSAPublicKey {
	n := effectiveLen(uint32(c.bits), SGDRSAMaxLen)
	return RSAPublicKey{
		Bits: uint32(c.bits),
		M:    cgoBytes(unsafe.Pointer(&c.m), n),
		E:    cgoBytes(unsafe.Pointer(&c.e), n),
	}
}

func rsaPublicKeyToC(g *RSAPublicKey) *C.RSArefPublicKey {
	c := (*C.RSArefPublicKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.RSArefPublicKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.m[0]), SGDRSAMaxLen, g.M)
	copyFixed(unsafe.Pointer(&c.e[0]), SGDRSAMaxLen, g.E)
	return c
}

func rsaPrivateKeyFromC(c *C.RSArefPrivateKey) RSAPrivateKey {
	n := effectiveLen(uint32(c.bits), SGDRSAMaxLen)
	pn := effectiveLen(uint32(c.bits)/2, SGDRSAMaxPLen)
	return RSAPrivateKey{
		Bits: uint32(c.bits),
		M:    cgoBytes(unsafe.Pointer(&c.m), n),
		E:    cgoBytes(unsafe.Pointer(&c.e), n),
		D:    cgoBytes(unsafe.Pointer(&c.d), n),
		Prime: [2][]byte{
			cgoBytes(unsafe.Pointer(&c.prime[0][0]), pn),
			cgoBytes(unsafe.Pointer(&c.prime[1][0]), pn),
		},
		PExp: [2][]byte{
			cgoBytes(unsafe.Pointer(&c.pexp[0][0]), pn),
			cgoBytes(unsafe.Pointer(&c.pexp[1][0]), pn),
		},
		Coef: cgoBytes(unsafe.Pointer(&c.coef), pn),
	}
}

func rsaPrivateKeyToC(g *RSAPrivateKey) *C.RSArefPrivateKey {
	c := (*C.RSArefPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.RSArefPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.m[0]), SGDRSAMaxLen, g.M)
	copyFixed(unsafe.Pointer(&c.e[0]), SGDRSAMaxLen, g.E)
	copyFixed(unsafe.Pointer(&c.d[0]), SGDRSAMaxLen, g.D)
	for i := range 2 {
		copyFixed(unsafe.Pointer(&c.prime[i][0]), SGDRSAMaxPLen, g.Prime[i])
		copyFixed(unsafe.Pointer(&c.pexp[i][0]), SGDRSAMaxPLen, g.PExp[i])
	}
	copyFixed(unsafe.Pointer(&c.coef[0]), SGDRSAMaxPLen, g.Coef)
	return c
}

func eccPublicKeyFromC(c *C.ECCrefPublicKey) ECCPublicKey {
	return ECCPublicKey{
		Bits: uint32(c.bits),
		X:    cgoBytes(unsafe.Pointer(&c.x), ECCrefMaxLen),
		Y:    cgoBytes(unsafe.Pointer(&c.y), ECCrefMaxLen),
	}
}

func eccPublicKeyToC(g *ECCPublicKey) *C.ECCrefPublicKey {
	c := (*C.ECCrefPublicKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPublicKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.x[0]), ECCrefMaxLen, g.X)
	copyFixedRightAligned(unsafe.Pointer(&c.y[0]), ECCrefMaxLen, g.Y)
	return c
}

func eccPrivateKeyFromC(c *C.ECCrefPrivateKey) ECCPrivateKey {
	return ECCPrivateKey{
		Bits: uint32(c.bits),
		K:    cgoBytes(unsafe.Pointer(&c.K), ECCrefMaxLen),
	}
}

func eccPrivateKeyToC(g *ECCPrivateKey) *C.ECCrefPrivateKey {
	c := (*C.ECCrefPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.K[0]), ECCrefMaxLen, g.K)
	return c
}

func eccSignatureFromC(c *C.ECCSignature) ECCSignature {
	return ECCSignature{
		R: cgoBytes(unsafe.Pointer(&c.r), ECCrefMaxLen),
		S: cgoBytes(unsafe.Pointer(&c.s), ECCrefMaxLen),
	}
}

func eccSignatureToC(g *ECCSignature) *C.ECCSignature {
	c := (*C.ECCSignature)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCSignature{}))))
	copyFixed(unsafe.Pointer(&c.r[0]), ECCrefMaxLen, g.R)
	copyFixed(unsafe.Pointer(&c.s[0]), ECCrefMaxLen, g.S)
	return c
}

func eccCipherAlloc(g *ECCCipher) (*C.ECCCipher, func()) {
	l := len(g.C)
	size := C.size_t(unsafe.Sizeof(C.ECCCipher{})) - 1 + C.size_t(l)
	p := C.calloc(1, size)
	c := (*C.ECCCipher)(p)
	copyFixed(unsafe.Pointer(&c.x[0]), ECCrefMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), ECCrefMaxLen, g.Y)
	copyFixed(unsafe.Pointer(&c.M[0]), 32, g.M[:])
	c.L = C.uint(g.L)
	if l > 0 {
		copyFixed(unsafe.Pointer(&c.C[0]), l, g.C)
	}
	return c, func() { C.free(p) }
}

func eccCipherFromC(c *C.ECCCipher) ECCCipher {
	l := max(int(c.L), 0)
	out := ECCCipher{
		X: cgoBytes(unsafe.Pointer(&c.x), ECCrefMaxLen),
		Y: cgoBytes(unsafe.Pointer(&c.y), ECCrefMaxLen),
		L: uint32(c.L),
	}
	copy(out.M[:], cgoBytes(unsafe.Pointer(&c.M), 32))
	if l > 0 {
		out.C = cgoBytes(unsafe.Pointer(&c.C), l)
	}
	return out
}

func eccPublicKeyECDSAFromC(c *C.ECCrefPublicKey_ECDSA) ECCPublicKeyECDSA {
	return ECCPublicKeyECDSA{
		Bits: uint32(c.bits),
		X:    cgoBytes(unsafe.Pointer(&c.x), ECCrefMaxLenECDSA),
		Y:    cgoBytes(unsafe.Pointer(&c.y), ECCrefMaxLenECDSA),
	}
}

func eccPublicKeyECDSAToC(g *ECCPublicKeyECDSA) *C.ECCrefPublicKey_ECDSA {
	c := (*C.ECCrefPublicKey_ECDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPublicKey_ECDSA{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.x[0]), ECCrefMaxLenECDSA, g.X)
	copyFixedRightAligned(unsafe.Pointer(&c.y[0]), ECCrefMaxLenECDSA, g.Y)
	return c
}

func eccPrivateKeyECDSAFromC(c *C.ECCrefPrivateKey_ECDSA) ECCPrivateKeyECDSA {
	return ECCPrivateKeyECDSA{
		Bits: uint32(c.bits),
		K:    cgoBytes(unsafe.Pointer(&c.K), ECCrefMaxLenECDSA),
	}
}

func eccPrivateKeyECDSAToC(g *ECCPrivateKeyECDSA) *C.ECCrefPrivateKey_ECDSA {
	c := (*C.ECCrefPrivateKey_ECDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPrivateKey_ECDSA{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.K[0]), ECCrefMaxLenECDSA, g.K)
	return c
}

func eccSignatureECDSAFromC(c *C.ECCSignature_ECDSA) ECCSignatureECDSA {
	return ECCSignatureECDSA{
		R: cgoBytes(unsafe.Pointer(&c.r), ECCrefMaxLenECDSA),
		S: cgoBytes(unsafe.Pointer(&c.s), ECCrefMaxLenECDSA),
	}
}

func eccSignatureECDSAToC(g *ECCSignatureECDSA) *C.ECCSignature_ECDSA {
	c := (*C.ECCSignature_ECDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCSignature_ECDSA{}))))
	copyFixed(unsafe.Pointer(&c.r[0]), ECCrefMaxLenECDSA, g.R)
	copyFixed(unsafe.Pointer(&c.s[0]), ECCrefMaxLenECDSA, g.S)
	return c
}

func eccPublicKeyEDDSAFromC(c *C.ECCrefPublicKey_EDDSA) ECCPublicKeyEDDSA {
	return ECCPublicKeyEDDSA{
		Bits: uint32(c.bits),
		Pub:  cgoBytes(unsafe.Pointer(&c.pub), ECCrefMaxLenEDDSA),
	}
}

func eccPublicKeyEDDSAToC(g *ECCPublicKeyEDDSA) *C.ECCrefPublicKey_EDDSA {
	c := (*C.ECCrefPublicKey_EDDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPublicKey_EDDSA{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.pub[0]), ECCrefMaxLenEDDSA, g.Pub)
	return c
}

func eccPrivateKeyEDDSAFromC(c *C.ECCrefPrivateKey_EDDSA) ECCPrivateKeyEDDSA {
	return ECCPrivateKeyEDDSA{
		Bits: uint32(c.bits),
		Pri:  cgoBytes(unsafe.Pointer(&c.pri), ECCrefMaxLenEDDSA),
	}
}

func eccPrivateKeyEDDSAToC(g *ECCPrivateKeyEDDSA) *C.ECCrefPrivateKey_EDDSA {
	c := (*C.ECCrefPrivateKey_EDDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCrefPrivateKey_EDDSA{}))))
	c.bits = C.uint(g.Bits)
	copyFixedRightAligned(unsafe.Pointer(&c.pri[0]), ECCrefMaxLenEDDSA, g.Pri)
	return c
}

func eccSignatureEDDSAFromC(c *C.ECCSignature_EDDSA) ECCSignatureEDDSA {
	return ECCSignatureEDDSA{
		R: cgoBytes(unsafe.Pointer(&c.r), ECCrefMaxLenEDDSA),
		S: cgoBytes(unsafe.Pointer(&c.s), ECCrefMaxLenEDDSA),
	}
}

func eccSignatureEDDSAToC(g *ECCSignatureEDDSA) *C.ECCSignature_EDDSA {
	c := (*C.ECCSignature_EDDSA)(C.calloc(1, C.size_t(unsafe.Sizeof(C.ECCSignature_EDDSA{}))))
	copyFixed(unsafe.Pointer(&c.r[0]), ECCrefMaxLenEDDSA, g.R)
	copyFixed(unsafe.Pointer(&c.s[0]), ECCrefMaxLenEDDSA, g.S)
	return c
}

func dsaPublicKeyFromC(c *C.DSArefPublicKey) DSAPublicKey {
	n := effectiveLen(uint32(c.bits), DSArefMaxLen)
	return DSAPublicKey{
		Bits: uint32(c.bits),
		Y:    cgoBytes(unsafe.Pointer(&c.y), n),
		P:    cgoBytes(unsafe.Pointer(&c.p), n),
		Q:    cgoBytes(unsafe.Pointer(&c.q), n),
		G:    cgoBytes(unsafe.Pointer(&c.g), n),
	}
}

func dsaPublicKeyToC(g *DSAPublicKey) *C.DSArefPublicKey {
	c := (*C.DSArefPublicKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.DSArefPublicKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.y[0]), DSArefMaxLen, g.Y)
	copyFixed(unsafe.Pointer(&c.p[0]), DSArefMaxLen, g.P)
	copyFixed(unsafe.Pointer(&c.q[0]), DSArefMaxLen, g.Q)
	copyFixed(unsafe.Pointer(&c.g[0]), DSArefMaxLen, g.G)
	return c
}

func dsaPrivateKeyFromC(c *C.DSArefPrivateKey) DSAPrivateKey {
	n := effectiveLen(uint32(c.bits), DSArefMaxLen)
	return DSAPrivateKey{
		Bits: uint32(c.bits),
		X:    cgoBytes(unsafe.Pointer(&c.x), n),
		P:    cgoBytes(unsafe.Pointer(&c.p), n),
		Q:    cgoBytes(unsafe.Pointer(&c.q), n),
		G:    cgoBytes(unsafe.Pointer(&c.g), n),
	}
}

func dsaPrivateKeyToC(g *DSAPrivateKey) *C.DSArefPrivateKey {
	c := (*C.DSArefPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.DSArefPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.x[0]), DSArefMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.p[0]), DSArefMaxLen, g.P)
	copyFixed(unsafe.Pointer(&c.q[0]), DSArefMaxLen, g.Q)
	copyFixed(unsafe.Pointer(&c.g[0]), DSArefMaxLen, g.G)
	return c
}

func dsaSignatureFromC(c *C.DSASignature) DSASignature {
	return DSASignature{
		R: cgoBytes(unsafe.Pointer(&c.r), DSArefMaxLen),
		S: cgoBytes(unsafe.Pointer(&c.s), DSArefMaxLen),
	}
}

func dsaSignatureToC(g *DSASignature) *C.DSASignature {
	c := (*C.DSASignature)(C.calloc(1, C.size_t(unsafe.Sizeof(C.DSASignature{}))))
	copyFixed(unsafe.Pointer(&c.r[0]), DSArefMaxLen, g.R)
	copyFixed(unsafe.Pointer(&c.s[0]), DSArefMaxLen, g.S)
	return c
}

func sm9MasterPrivateKeyFromC(c *C.SM9MasterPrivateKey) SM9MasterPrivateKey {
	n := effectiveLen(uint32(c.bits), SM9refMaxLen)
	return SM9MasterPrivateKey{
		Bits: uint32(c.bits),
		S:    cgoBytes(unsafe.Pointer(&c.s), n),
	}
}

func sm9MasterPrivateKeyToC(g *SM9MasterPrivateKey) *C.SM9MasterPrivateKey {
	c := (*C.SM9MasterPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9MasterPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.s[0]), SM9refMaxLen, g.S)
	return c
}

func sm9SignMasterPublicKeyFromC(c *C.SM9SignMasterPublicKey) SM9SignMasterPublicKey {
	n := effectiveLen(uint32(c.bits), SM9refMaxLen)
	return SM9SignMasterPublicKey{
		Bits: uint32(c.bits),
		XA:   cgoBytes(unsafe.Pointer(&c.xa), n),
		XB:   cgoBytes(unsafe.Pointer(&c.xb), n),
		YA:   cgoBytes(unsafe.Pointer(&c.ya), n),
		YB:   cgoBytes(unsafe.Pointer(&c.yb), n),
	}
}

func sm9SignMasterPublicKeyToC(g *SM9SignMasterPublicKey) *C.SM9SignMasterPublicKey {
	c := (*C.SM9SignMasterPublicKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9SignMasterPublicKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.xa[0]), SM9refMaxLen, g.XA)
	copyFixed(unsafe.Pointer(&c.xb[0]), SM9refMaxLen, g.XB)
	copyFixed(unsafe.Pointer(&c.ya[0]), SM9refMaxLen, g.YA)
	copyFixed(unsafe.Pointer(&c.yb[0]), SM9refMaxLen, g.YB)
	return c
}

func sm9EncMasterPublicKeyFromC(c *C.SM9EncMasterPublicKey) SM9EncMasterPublicKey {
	n := effectiveLen(uint32(c.bits), SM9refMaxLen)
	return SM9EncMasterPublicKey{
		Bits: uint32(c.bits),
		X:    cgoBytes(unsafe.Pointer(&c.x), n),
		Y:    cgoBytes(unsafe.Pointer(&c.y), n),
	}
}

func sm9EncMasterPublicKeyToC(g *SM9EncMasterPublicKey) *C.SM9EncMasterPublicKey {
	c := (*C.SM9EncMasterPublicKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9EncMasterPublicKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.x[0]), SM9refMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), SM9refMaxLen, g.Y)
	return c
}

func sm9UserSignPrivateKeyFromC(c *C.SM9UserSignPrivateKey) SM9UserSignPrivateKey {
	n := effectiveLen(uint32(c.bits), SM9refMaxLen)
	return SM9UserSignPrivateKey{
		Bits: uint32(c.bits),
		X:    cgoBytes(unsafe.Pointer(&c.x), n),
		Y:    cgoBytes(unsafe.Pointer(&c.y), n),
	}
}

func sm9UserSignPrivateKeyToC(g *SM9UserSignPrivateKey) *C.SM9UserSignPrivateKey {
	c := (*C.SM9UserSignPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9UserSignPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.x[0]), SM9refMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), SM9refMaxLen, g.Y)
	return c
}

func sm9UserEncPrivateKeyFromC(c *C.SM9UserEncPrivateKey) SM9UserEncPrivateKey {
	n := effectiveLen(uint32(c.bits), SM9refMaxLen)
	return SM9UserEncPrivateKey{
		Bits: uint32(c.bits),
		XA:   cgoBytes(unsafe.Pointer(&c.xa), n),
		XB:   cgoBytes(unsafe.Pointer(&c.xb), n),
		YA:   cgoBytes(unsafe.Pointer(&c.ya), n),
		YB:   cgoBytes(unsafe.Pointer(&c.yb), n),
	}
}

func sm9UserEncPrivateKeyToC(g *SM9UserEncPrivateKey) *C.SM9UserEncPrivateKey {
	c := (*C.SM9UserEncPrivateKey)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9UserEncPrivateKey{}))))
	c.bits = C.uint(g.Bits)
	copyFixed(unsafe.Pointer(&c.xa[0]), SM9refMaxLen, g.XA)
	copyFixed(unsafe.Pointer(&c.xb[0]), SM9refMaxLen, g.XB)
	copyFixed(unsafe.Pointer(&c.ya[0]), SM9refMaxLen, g.YA)
	copyFixed(unsafe.Pointer(&c.yb[0]), SM9refMaxLen, g.YB)
	return c
}

func sm9CipherAlloc(g *SM9Cipher) (*C.SM9Cipher, func()) {
	l := len(g.C)
	size := C.size_t(unsafe.Sizeof(C.SM9Cipher{})) - 1 + C.size_t(l)
	p := C.calloc(1, size)
	c := (*C.SM9Cipher)(p)
	c.enType = C.uint(g.EnType)
	copyFixed(unsafe.Pointer(&c.x[0]), SM9refMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), SM9refMaxLen, g.Y)
	copyFixed(unsafe.Pointer(&c.h[0]), SM9refMaxLen, g.H)
	c.L = C.uint(g.L)
	if l > 0 {
		copyFixed(unsafe.Pointer(&c.C[0]), l, g.C)
	}
	return c, func() { C.free(p) }
}

func sm9CipherFromC(c *C.SM9Cipher) SM9Cipher {
	l := max(int(c.L), 0)
	out := SM9Cipher{
		EnType: uint32(c.enType),
		X:      cgoBytes(unsafe.Pointer(&c.x), SM9refMaxLen),
		Y:      cgoBytes(unsafe.Pointer(&c.y), SM9refMaxLen),
		H:      cgoBytes(unsafe.Pointer(&c.h), SM9refMaxLen),
		L:      uint32(c.L),
	}
	if l > 0 {
		out.C = cgoBytes(unsafe.Pointer(&c.C), l)
	}
	return out
}

func sm9SignatureFromC(c *C.SM9Signature) SM9Signature {
	return SM9Signature{
		H: cgoBytes(unsafe.Pointer(&c.h), SM9refMaxLen),
		X: cgoBytes(unsafe.Pointer(&c.x), SM9refMaxLen),
		Y: cgoBytes(unsafe.Pointer(&c.y), SM9refMaxLen),
	}
}

func sm9SignatureToC(g *SM9Signature) *C.SM9Signature {
	c := (*C.SM9Signature)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9Signature{}))))
	copyFixed(unsafe.Pointer(&c.h[0]), SM9refMaxLen, g.H)
	copyFixed(unsafe.Pointer(&c.x[0]), SM9refMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), SM9refMaxLen, g.Y)
	return c
}

func sm9KeyPackageFromC(c *C.SM9KeyPackage) SM9KeyPackage {
	return SM9KeyPackage{
		X: cgoBytes(unsafe.Pointer(&c.x), SM9refMaxLen),
		Y: cgoBytes(unsafe.Pointer(&c.y), SM9refMaxLen),
	}
}

func sm9KeyPackageToC(g *SM9KeyPackage) *C.SM9KeyPackage {
	c := (*C.SM9KeyPackage)(C.calloc(1, C.size_t(unsafe.Sizeof(C.SM9KeyPackage{}))))
	copyFixed(unsafe.Pointer(&c.x[0]), SM9refMaxLen, g.X)
	copyFixed(unsafe.Pointer(&c.y[0]), SM9refMaxLen, g.Y)
	return c
}

func hashCtxToC(g *HashCtx) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&g[0]))
}

func hashCtxFromC(c *[512]C.uchar) HashCtx {
	var out HashCtx
	copy(out[:], cgoBytes(unsafe.Pointer(c), 512))
	return out
}

func newKeyHandle(s *Session, h unsafe.Pointer) *KeyHandle {
	if h == nil {
		return nil
	}
	return &KeyHandle{session: s, h: h}
}

func newAgreementHandle(s *Session, h unsafe.Pointer) *AgreementHandle {
	if h == nil {
		return nil
	}
	return &AgreementHandle{session: s, h: h}
}

func newECCKeyHandle(s *Session, h unsafe.Pointer) *ECCKeyHandle {
	if h == nil {
		return nil
	}
	return &ECCKeyHandle{session: s, h: h}
}

func cHandle(p unsafe.Pointer) unsafe.Pointer {
	return p
}
