package sdf

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestEffectiveLen(t *testing.T) {
	if got := effectiveLen(256, ECCrefMaxLen); got != 32 {
		t.Fatalf("effectiveLen(256) = %d, want 32", got)
	}
	if got := effectiveLen(512, ECCrefMaxLen); got != 64 {
		t.Fatalf("effectiveLen(512) = %d, want 64", got)
	}
}

func TestTrimZeros(t *testing.T) {
	in := []byte{1, 2, 0, 0}
	if got := trimZeros(in); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("trimZeros = %v", got)
	}
}

func TestCopyFixed(t *testing.T) {
	dst := make([]byte, 8)
	copyFixed(unsafe.Pointer(&dst[0]), len(dst), []byte{1, 2, 3}) // #nosec G103 -- 测试 CGO 辅助函数
	if !bytes.Equal(dst[:3], []byte{1, 2, 3}) {
		t.Fatalf("copyFixed failed: %v", dst)
	}
}

func TestCopyFixedRightAligned(t *testing.T) {
	dst := make([]byte, 8)
	copyFixedRightAligned(unsafe.Pointer(&dst[0]), len(dst), []byte{1, 2, 3}) // #nosec G103 -- 测试 CGO 辅助函数
	want := []byte{0, 0, 0, 0, 0, 1, 2, 3}
	if !bytes.Equal(dst, want) {
		t.Fatalf("copyFixedRightAligned = %v, want %v", dst, want)
	}
}

func TestECCPublicKeyFields(t *testing.T) {
	pk := ECCPublicKey{
		Bits: 256,
		X:    bytes.Repeat([]byte{0x01}, 32),
		Y:    bytes.Repeat([]byte{0x02}, 32),
	}
	if pk.Bits != 256 || len(pk.X) != 32 {
		t.Fatal("ECCPublicKey field setup failed")
	}
}

func TestECCCipherFields(t *testing.T) {
	c := ECCCipher{L: 4, C: []byte{1, 2, 3, 4}}
	if c.L != 4 || len(c.C) != 4 {
		t.Fatal("ECCCipher field setup failed")
	}
}
