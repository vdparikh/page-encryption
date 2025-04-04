package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	_ = os.WriteFile("keys/ec_private.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}), 0600)

	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	_ = os.WriteFile("keys/ec_public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0644)
}
