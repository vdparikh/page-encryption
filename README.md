# Page Encryption

Demonstrates how to securely submit a credit card number from the client (browser) to the backend using **Elliptic Curve Integrated Encryption Scheme (ECIES)**. It utilizes **ECDH (Elliptic Curve Diffie-Hellman)** for key exchange, **AES-GCM** for encryption, and **ECDSA** for signature verification to ensure confidentiality and integrity during transmission.

## Overview

### **Components**
1. **Frontend (JavaScript)**:
    - The user enters their credit card number into a form.
    - The browser generates an ephemeral public key (via **ECDH**), encrypts the card number using **AES-GCM**, signs the encrypted data with an **ECDSA** private key, and sends the encrypted payload to the server.

2. **Backend (Go)**:
    - The Go server generates the server's public and private keys for **ECDH** key exchange.
    - When the encrypted payload is received, it decrypts the data using the shared secret derived from the client's ephemeral public key and its own private key.
    - The server also verifies the **ECDSA** signature on the payload to ensure data integrity.

---

## Sample Application

### **Prerequisites**
- **Go 1.18+** (for building and running the Go server)
- A **modern browser** that supports Web Crypto API for ECDH.

### **Steps to Run**

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/vdparikh/page-encryption.git
   cd page-encryption
   ```

2. **Run the Backend (Go Server):**
   - The Go server will serve the frontend files and handle the `/decrypt` endpoint to process the card number.
   
   ```bash
   go run main.go
   ```

   By default, the server will run on `http://localhost:8080`.

3. **Frontend:**
   - The frontend is a simple HTML form with JavaScript that will perform ECIES encryption and submit the payload to the Go backend.
   - When the server starts, it will dynamically generate the public key in JavaScript and serve it at `/js/getKey.js`.

4. **Testing:**
   - Open your browser and visit `http://localhost:8080`.
   - Enter a **credit card number** in the form and submit it. The card number will be encrypted on the frontend and sent to the backend.

---

## **Backend (Go) Details**

### **Key Generation**
- **ECDH (Elliptic Curve Diffie-Hellman)** is used for securely sharing keys between the client and server. The server generates an ECDH private key and sends the corresponding public key to the client.

```go
privateKeyECDH, err := ecdh.P256().GenerateKey(rand.Reader)
```

- **ECDSA (Elliptic Curve Digital Signature Algorithm)** is used for signing the encrypted payload. This ensures the integrity of the message.

### **Endpoints**

1. **`/js/getKey.js`**:
   - Dynamically serves the server’s public key in JavaScript format for client-side use.
   - The client will use this key to encrypt the card number and perform the key exchange.

2. **`/decrypt`**:
   - Accepts the encrypted card number and signature from the client.
   - The server performs:
     - **ECDH key exchange** to derive the shared secret.
     - **AES-GCM decryption** of the encrypted card number.
     - **ECDSA signature verification** to ensure the integrity of the payload.

### **Example Payload Structure** (Sent by the Client)
```json
{
  "encrypted_data": "jBfqdg8MDlcv1weo07mNEvVIdIo+qKYbld4XDnAQISS3gkED+IQQcP0=",
  "ephemeral_pub": "BEh1B7+Q4YHo80WEc2okfF2IbL4iUqZAk1br0iOjsheD/qTNs62KE9V0xPNdn1820JgJhOrECfhyM2wJx9MJgXA=",
  "signature": "IR4x8Kl/RmYQTxc57+RqPaUfvZWwugt0FbnK/CyZIUi9U859cu5k4I0zYKWlKUGg8Q4flqfNHM1CmRV9BAbOxw==",
  "signing_pub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWhzq6YEic97MFUDTm8OCYLM3r+4fLwv2OVl7KeSzLhQPTkE0knYap/WYTrehJr5+EAiyNLg1mHlnvH6CekGOsQ=="
}
```

### **Decryption Flow**
- The backend:
  1. Derives the shared secret from the **ECDH key exchange**.
  2. Decrypts the card number using **AES-GCM** with the derived shared secret.
  3. Verifies the signature using **ECDSA** to ensure the message was not tampered with.

---

## **Frontend (JavaScript) Details**

### **Key Concepts**

1. **ECIES Encryption**:
   - The frontend uses the **Web Crypto API** to:
     - Generate an ephemeral **ECDH public key**.
     - Encrypt the card number using **AES-GCM**.
     - Sign the encrypted data with the client’s private **ECDSA** key.

2. **Generating the Public Key**:
   - The public key used for encryption is obtained from the server dynamically via `getKey.js`.

3. **Signature**:
   - The frontend signs the encrypted data and includes the signature in the payload sent to the server.

### **Encrypting and Sending Data**
```javascript
async function encryptCardNumber(cardNumber) {
    const publicKey = await getServerPublicKey();

    // Generate ephemeral private and public keys
    const privateKey = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );

    const ephemeralPubKey = await crypto.subtle.exportKey("raw", privateKey.publicKey);

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        256
    );

    // Encrypt the card number using AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM nonce
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        sharedSecret,
        new TextEncoder().encode(cardNumber)
    );

    // Sign the encrypted data with ECDSA
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        privateKey,
        new Uint8Array([...new Uint8Array(encrypted), ...ephemeralPubKey])
    );

    return {
        encrypted_data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        ephemeral_pub: btoa(String.fromCharCode(...ephemeralPubKey)),
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
        signing_pub: btoa(String.fromCharCode(...ephemeralPubKey))
    };
}
```

---
## **Security Considerations**
- **ECDH** ensures that the server and client derive the same shared secret without exposing the private keys.
- **AES-GCM** ensures confidentiality of the card number and also provides integrity and authenticity through its built-in authentication tag.
- **ECDSA** ensures that the data sent by the client has not been tampered with during transmission.
