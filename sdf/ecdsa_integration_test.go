//go:build integration

package sdf

import (
	"crypto/sha256"
	"testing"
)

const (
	ecdsaAlgID  = uint32(SGDECDSA_1)
	ecdsaBits   = uint32(256)
	ecdsaDigest = "dysxcs02 ecdsa integration test"
)

func ecdsaTestDigest() [32]byte {
	return sha256.Sum256([]byte(ecdsaDigest))
}

func TestGenerateKeyPairECDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	pub, priv, err := sess.GenerateKeyPairECDSA(ecdsaAlgID, ecdsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairECDSA: %v", err)
	}
	if pub.Bits != ecdsaBits {
		t.Fatalf("pub.Bits = %d, want %d", pub.Bits, ecdsaBits)
	}
	if priv.Bits != ecdsaBits {
		t.Fatalf("priv.Bits = %d, want %d", priv.Bits, ecdsaBits)
	}
}

func ecdsaExternalKeyPair(t *testing.T, sess *Session) (ECCPublicKeyECDSA, ECCPrivateKeyECDSA) {
	t.Helper()
	pub, priv, err := sess.GenerateKeyPairECDSA(ecdsaAlgID, ecdsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairECDSA: %v", err)
	}
	if !hasECDSAPublicKeyMaterial(&pub) {
		t.Skip("HSM did not return ECDSA public key material from GenerateKeyPairECDSA")
	}
	return pub, priv
}

func TestExternalSignECDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	_, priv, err := sess.GenerateKeyPairECDSA(ecdsaAlgID, ecdsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairECDSA: %v", err)
	}

	digest := ecdsaTestDigest()
	sig, err := sess.ExternalSignECDSA(ecdsaAlgID, &priv, digest[:])
	if err != nil {
		t.Fatalf("ExternalSignECDSA: %v", err)
	}
	if len(trimZeros(sig.R)) == 0 || len(trimZeros(sig.S)) == 0 {
		t.Fatal("empty signature")
	}
}

func TestExternalVerifyECDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	pub, priv := ecdsaExternalKeyPair(t, sess)

	digest := ecdsaTestDigest()
	sig, err := sess.ExternalSignECDSA(ecdsaAlgID, &priv, digest[:])
	if err != nil {
		t.Fatalf("ExternalSignECDSA: %v", err)
	}
	if err := sess.ExternalVerifyECDSA(ecdsaAlgID, &pub, digest[:], &sig); err != nil {
		t.Fatalf("ExternalVerifyECDSA: %v", err)
	}

	bad := digest
	bad[0] ^= 0xff
	if err := sess.ExternalVerifyECDSA(ecdsaAlgID, &pub, bad[:], &sig); err == nil {
		t.Fatal("expected verify error for tampered digest")
	} else if !isSDFError(err, RVVerifyErr) {
		t.Fatalf("verify error = %v, want RVVerifyErr", err)
	}
}

func TestInternalSignECDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	digest := ecdsaTestDigest()
	sig, err := sess.InternalSignECDSA(integrationKeyIndex, ecdsaAlgID, digest[:])
	if err != nil {
		t.Fatalf("InternalSignECDSA: %v", err)
	}
	if len(trimZeros(sig.R)) == 0 || len(trimZeros(sig.S)) == 0 {
		t.Fatal("empty signature")
	}
}

func TestInternalVerifyECDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	digest := ecdsaTestDigest()
	sig, err := sess.InternalSignECDSA(integrationKeyIndex, ecdsaAlgID, digest[:])
	if err != nil {
		t.Fatalf("InternalSignECDSA: %v", err)
	}
	if err := sess.InternalVerifyECDSA(integrationKeyIndex, ecdsaAlgID, digest[:], &sig); err != nil {
		t.Fatalf("InternalVerifyECDSA: %v", err)
	}
}

func TestExportPublicKeyECDSA(t *testing.T) {
	requireLibSymbol(t, "SDF_ExportPublicKey_ECDSA")
	sess := requireIntegrationSession(t)

	pub, err := sess.ExportPublicKeyECDSA(integrationKeyIndex)
	if err != nil {
		t.Fatalf("ExportPublicKeyECDSA: %v", err)
	}
	if pub.Bits == 0 {
		t.Fatal("zero key bits")
	}
	if len(trimLeadingZeros(pub.X)) == 0 || len(trimLeadingZeros(pub.Y)) == 0 {
		t.Fatal("empty exported public key")
	}
}
