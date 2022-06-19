package rsa

import (
	"testing"
)

func TestGenerateRsaKeyPair(t *testing.T) {
	privateKey, publicKey := GenerateRsaKeyPair()
	if &privateKey.PublicKey != publicKey {
		t.Error("Public keys are not the same")
	}
}

func TestExportRsaPrivateKeyAsPemStr(t *testing.T) {

}

func TestParseRsaPrivateKeyFromPemStr(t *testing.T) {

}

func TestExportRsaPublicKeyAsPemStr(t *testing.T) {

}

func TestParseRsaPublicKeyFromPemStr(t *testing.T) {

}
