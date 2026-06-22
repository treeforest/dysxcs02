//go:build integration

package sdf

import (
	"os"
	"strings"
	"testing"
)

func TestDeviceIntegration(t *testing.T) {
	if _, err := os.Stat("cacipher.ini"); err != nil {
		t.Skip("cacipher.ini not found, skipping integration test")
	}

	dev, err := OpenDeviceWithConfig("cacipher.ini", nil)
	if err != nil {
		t.Fatalf("OpenDeviceWithConfig: %v", err)
	}
	defer dev.Close()

	sess, err := dev.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()

	info, err := sess.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo: %v", err)
	}
	name := strings.TrimRight(string(info.DeviceName[:]), "\x00")
	if name == "" {
		t.Fatal("empty device name")
	}

	rand, err := sess.GenerateRandom(16)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(rand) != 16 {
		t.Fatalf("random length = %d, want 16", len(rand))
	}
}
