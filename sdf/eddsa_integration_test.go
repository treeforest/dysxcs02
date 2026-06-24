//go:build integration

package sdf

import (
	"crypto/sha256"
	"testing"
)

const (
	eddsaAlgID  = uint32(SGDEDDSA_1)
	eddsaBits   = uint32(256)
	eddsaDigest = "dysxcs02 eddsa integration test"
)

func eddsaTestDigest() [32]byte {
	return sha256.Sum256([]byte(eddsaDigest))
}

func TestGenerateKeyPairEDDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	pub, priv, err := sess.GenerateKeyPairEDDSA(eddsaAlgID, eddsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairEDDSA: %v", err)
	}
	if pub.Bits != eddsaBits {
		t.Fatalf("pub.Bits = %d, want %d", pub.Bits, eddsaBits)
	}
	if priv.Bits != eddsaBits {
		t.Fatalf("priv.Bits = %d, want %d", priv.Bits, eddsaBits)
	}
	if len(trimZeros(pub.Pub)) == 0 {
		t.Fatal("empty public key")
	}
	if len(trimZeros(priv.Pri)) == 0 {
		t.Fatal("empty private key")
	}
}

func TestExternalSignEDDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	_, priv, err := sess.GenerateKeyPairEDDSA(eddsaAlgID, eddsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairEDDSA: %v", err)
	}

	digest := eddsaTestDigest()
	sig, err := sess.ExternalSignEDDSA(eddsaAlgID, &priv, digest[:])
	if err != nil {
		t.Fatalf("ExternalSignEDDSA: %v", err)
	}
	if len(trimZeros(sig.R)) == 0 || len(trimZeros(sig.S)) == 0 {
		t.Fatal("empty signature")
	}
}

func TestExternalVerifyEDDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	pub, priv, err := sess.GenerateKeyPairEDDSA(eddsaAlgID, eddsaBits)
	if err != nil {
		t.Fatalf("GenerateKeyPairEDDSA: %v", err)
	}

	digest := eddsaTestDigest()
	sig, err := sess.ExternalSignEDDSA(eddsaAlgID, &priv, digest[:])
	if err != nil {
		t.Fatalf("ExternalSignEDDSA: %v", err)
	}
	if err := sess.ExternalVerifyEDDSA(eddsaAlgID, &pub, digest[:], &sig); err != nil {
		t.Fatalf("ExternalVerifyEDDSA: %v", err)
	}

	bad := digest
	bad[0] ^= 0xff
	if err := sess.ExternalVerifyEDDSA(eddsaAlgID, &pub, bad[:], &sig); err == nil {
		t.Fatal("expected verify error for tampered digest")
	} else if !isSDFError(err, RVVerifyErr) {
		t.Fatalf("verify error = %v, want RVVerifyErr", err)
	}
}

func TestInternalSignEDDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	digest := eddsaTestDigest()
	sig, err := sess.InternalSignEDDSA(integrationKeyIndex, eddsaAlgID, digest[:])
	if err != nil {
		t.Fatalf("InternalSignEDDSA: %v", err)
	}
	if len(trimZeros(sig.R)) == 0 || len(trimZeros(sig.S)) == 0 {
		t.Fatal("empty signature")
	}
}

func TestInternalVerifyEDDSA(t *testing.T) {
	sess := requireIntegrationSession(t)

	digest := eddsaTestDigest()
	sig, err := sess.InternalSignEDDSA(integrationKeyIndex, eddsaAlgID, digest[:])
	if err != nil {
		t.Fatalf("InternalSignEDDSA: %v", err)
	}
	if err := sess.InternalVerifyEDDSA(integrationKeyIndex, eddsaAlgID, digest[:], &sig); err != nil {
		t.Fatalf("InternalVerifyEDDSA: %v", err)
	}
}

func TestExportPublicKeyEDDSA(t *testing.T) {
	requireLibSymbol(t, "SDF_ExportPublicKey_EDDSA")
	sess := requireIntegrationSession(t)

	pub, err := sess.ExportPublicKeyEDDSA(integrationKeyIndex)
	if err != nil {
		t.Fatalf("ExportPublicKeyEDDSA: %v", err)
	}
	if pub.Bits == 0 {
		t.Fatal("zero key bits")
	}
	if len(trimZeros(pub.Pub)) == 0 {
		t.Fatal("empty exported public key")
	}
}
