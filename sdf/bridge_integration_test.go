//go:build integration

package sdf

import (
	"bytes"
	"testing"
)

func TestECCPublicKeyRoundTrip(t *testing.T) {
	orig := ECCPublicKey{
		Bits: 256,
		X:    bytes.Repeat([]byte{0x01}, 32),
		Y:    bytes.Repeat([]byte{0x02}, 32),
	}
	c, free := eccPublicKeyAlloc(&orig)
	defer free()
	got := eccPublicKeyFromC(c)
	if got.Bits != orig.Bits {
		t.Fatalf("bits = %d, want %d", got.Bits, orig.Bits)
	}
	if !bytes.Equal(got.X, orig.X) || !bytes.Equal(got.Y, orig.Y) {
		t.Fatalf("coordinate mismatch: x=%x y=%x", got.X, got.Y)
	}
}

func TestECCCipherRoundTrip(t *testing.T) {
	orig := ECCCipher{
		X: bytes.Repeat([]byte{0x03}, 32),
		Y: bytes.Repeat([]byte{0x04}, 32),
		L: 8,
		C: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	copy(orig.M[:], bytes.Repeat([]byte{0xAA}, 32))
	c, free := eccCipherAlloc(&orig)
	defer free()
	got := eccCipherFromC(c)
	if got.L != orig.L || !bytes.Equal(got.C, orig.C) {
		t.Fatalf("cipher mismatch: L=%d C=%x", got.L, got.C)
	}
}

func TestRSAPublicKeyRoundTrip(t *testing.T) {
	orig := RSAPublicKey{
		Bits: 2048,
		M:    bytes.Repeat([]byte{0x11}, 256),
		E:    []byte{0x01, 0x00, 0x01},
	}
	c, free := rsaPublicKeyAlloc(&orig)
	defer free()
	got := rsaPublicKeyFromC(c)
	if got.Bits != orig.Bits {
		t.Fatalf("bits = %d, want %d", got.Bits, orig.Bits)
	}
	if !bytes.Equal(got.M, orig.M) || !bytes.Equal(trimZeros(got.E), orig.E) {
		t.Fatalf("key material mismatch")
	}
}

func TestSM9CipherRoundTrip(t *testing.T) {
	orig := SM9Cipher{
		EnType: 1,
		X:      bytes.Repeat([]byte{0x05}, 32),
		Y:      bytes.Repeat([]byte{0x06}, 32),
		H:      bytes.Repeat([]byte{0x07}, 32),
		L:      4,
		C:      []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	c, free := sm9CipherAlloc(&orig)
	defer free()
	got := sm9CipherFromC(c)
	if got.L != orig.L || !bytes.Equal(got.C, orig.C) {
		t.Fatalf("sm9 cipher mismatch")
	}
}

func TestDeviceInfoFromC(t *testing.T) {
	info := deviceInfoFromTestFields("TestDevice", 0x01020304)
	if info.DeviceVersion != 0x01020304 {
		t.Fatalf("version = %#x", info.DeviceVersion)
	}
	if info.DeviceName[0] != 'T' {
		t.Fatalf("device name not copied")
	}
}
