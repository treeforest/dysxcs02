//go:build integration

package sdf

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const integrationKeyIndex = uint32(1)

func requireIntegrationSession(t *testing.T) *Session {
	t.Helper()
	configPath := findCACipherINI()
	if configPath == "" {
		t.Skip("cacipher.ini not found, skipping integration test")
	}
	dev, err := OpenDeviceWithConfig(configPath, nil)
	if err != nil {
		t.Fatalf("OpenDeviceWithConfig: %v", err)
	}
	t.Cleanup(func() { _ = dev.Close() })
	sess, err := dev.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func findCACipherINI() string {
	for _, p := range []string{"cacipher.ini", "../cacipher.ini", "../testdata/cacipher.ini"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func requireLibSymbol(t *testing.T, name string) {
	t.Helper()
	if !hasLibSymbol(name) {
		t.Skipf("%s not exported by libsdf.so", name)
	}
}

func hasLibSymbol(name string) bool {
	for _, lib := range []string{"../lib/libsdf.so", "lib/libsdf.so"} {
		if _, err := os.Stat(lib); err != nil {
			continue
		}
		out, err := exec.Command("nm", "-D", lib).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(out), name) {
			return true
		}
	}
	return false
}

func isSDFError(err error, code RV) bool {
	var sdferr *Error
	return errors.As(err, &sdferr) && sdferr.Code == code
}

func hasECDSAPublicKeyMaterial(pub *ECCPublicKeyECDSA) bool {
	return len(trimLeadingZeros(pub.X)) > 0 || len(trimLeadingZeros(pub.Y)) > 0
}
