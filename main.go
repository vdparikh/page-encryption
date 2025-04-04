package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
)

var (
	privateKeyECDH *ecdh.PrivateKey
)

type EncryptedPayload struct {
	EncryptedData string `json:"encrypted_data"`
	Signature     string `json:"signature"`
	EphemeralPub  string `json:"ephemeral_pub"`
	SigningPub    string `json:"signing_pub"`
}

func init() {
	var err error
	privateKeyECDH, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("ECDH keygen failed: %v", err)
	}
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var payload EncryptedPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	cipherData, _ := base64.StdEncoding.DecodeString(payload.EncryptedData)
	ephPubBytes, _ := base64.StdEncoding.DecodeString(payload.EphemeralPub)
	signatureBytes, _ := base64.StdEncoding.DecodeString(payload.Signature)
	signingPubBytes, _ := base64.StdEncoding.DecodeString(payload.SigningPub)

	// Import ephemeral public key
	clientECDHPubKey, err := ecdh.P256().NewPublicKey(ephPubBytes)
	if err != nil {
		http.Error(w, "invalid ephemeral pub key", http.StatusBadRequest)
		return
	}

	// Derive shared secret
	sharedSecret, err := privateKeyECDH.ECDH(clientECDHPubKey)
	if err != nil {
		http.Error(w, "key exchange failed", http.StatusInternalServerError)
		return
	}

	// AES-GCM decryption
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		http.Error(w, "cipher init failed", http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "gcm init failed", http.StatusInternalServerError)
		return
	}

	nonceSize := gcm.NonceSize()
	if len(cipherData) < nonceSize {
		http.Error(w, "invalid ciphertext", http.StatusBadRequest)
		return
	}

	nonce := cipherData[:nonceSize]
	ciphertext := cipherData[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}

	// Verify ECDSA signature
	signingPubIface, err := x509.ParsePKIXPublicKey(signingPubBytes)
	if err != nil {
		http.Error(w, "invalid signing pub", http.StatusBadRequest)
		return
	}
	signingPub := signingPubIface.(*ecdsa.PublicKey)

	msg := append(cipherData, ephPubBytes...)
	digest := sha256.Sum256(msg)

	rSig := new(big.Int).SetBytes(signatureBytes[:len(signatureBytes)/2])
	sSig := new(big.Int).SetBytes(signatureBytes[len(signatureBytes)/2:])
	valid := ecdsa.Verify(signingPub, digest[:], rSig, sSig)
	if !valid {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	log.Printf("✅ Card number decrypted: %s", string(plaintext))
	w.Write([]byte("Card decrypted and verified successfully"))
}

func handleGetKeyJS(w http.ResponseWriter, r *http.Request) {
	pubKey := privateKeyECDH.PublicKey().Bytes()

	js := "async function getServerPublicKey() {\n"
	js += "    const raw = Uint8Array.from(["

	for i, b := range pubKey {
		if i > 0 {
			js += ","
		}
		js += fmt.Sprintf("%d", b)
	}

	js += `]);
    return await window.crypto.subtle.importKey(
        "raw",
        raw.buffer,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        []
    );
}`

	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(js))
}

func main() {
	mux := http.NewServeMux()

	// Serve frontend
	mux.Handle("/", http.FileServer(http.Dir("static")))
	mux.HandleFunc("/js/getKey.js", handleGetKeyJS)

	// API endpoints
	mux.HandleFunc("/decrypt", handleDecrypt)

	port := 8080
	log.Printf("🚀 Server running on http://localhost:%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mux))
}
