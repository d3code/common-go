package rsa

import (
	"strings"
	"testing"
)

func TestGenerateRsaKeyPair(t *testing.T) {
	privateKey, publicKey := GenerateRsaKeyPair()
	if &privateKey.PublicKey != publicKey {
		t.Error("Public keys are not the same")
	}
}

func TestExportRsaPrivateKeyAsPemStr(t *testing.T) {
	privateKey, _ := GenerateRsaKeyPair()
	privateKeyAsPemStr := ExportRsaPrivateKeyAsPemStr(privateKey)

	if !strings.HasPrefix(privateKeyAsPemStr, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Pem block does not start with correct string")
	}

	if !strings.HasSuffix(privateKeyAsPemStr, "-----END RSA PRIVATE KEY-----\n") {
		t.Error("Pem block does not end with correct string")
	}
}

func TestParseRsaPrivateKeyFromPemStr(t *testing.T) {
	privateKey, _ := GenerateRsaKeyPair()
	privateKeyAsPemStr := ExportRsaPrivateKeyAsPemStr(privateKey)

	privateKeyFromPemStr, err := ParseRsaPrivateKeyFromPemStr(privateKeyAsPemStr)

	if err != nil {
		t.Errorf("Error from parsing string: %s", err)
	}

	if privateKey.E != privateKeyFromPemStr.E {
		t.Error("Private keys not the same after string conversion")
	}
}

func TestExportRsaPublicKeyAsPemStr(t *testing.T) {
	_, publicKey := GenerateRsaKeyPair()
	publicKeyAsPemStr, err := ExportRsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Errorf("Error from exporting public key as string: %s", err)
	}

	if !strings.HasPrefix(publicKeyAsPemStr, "-----BEGIN RSA PUBLIC KEY-----") {
		t.Error("Pem block does not start with correct string")
	}

	if !strings.HasSuffix(publicKeyAsPemStr, "-----END RSA PUBLIC KEY-----\n") {
		t.Error("Pem block does not end with correct string")
	}
}

func TestParseRsaPublicKeyFromPemStr(t *testing.T) {
	_, publicKey := GenerateRsaKeyPair()
	publicKeyAsPemStr, err := ExportRsaPublicKeyAsPemStr(publicKey)
	if err != nil {
		t.Errorf("Error from exporting public key as string: %s", err)
	}

	publicKeyFromPemStr, err := ParseRsaPublicKeyFromPemStr(publicKeyAsPemStr)
	if err != nil {
		t.Errorf("Error from parsing string: %s", err)
	}

	if publicKey.E != publicKeyFromPemStr.E {
		t.Error("Private keys not the same after string conversion")
	}
}
