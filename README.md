# Page Encryption

Demonstrates how to securely submit a credit card number from the client (browser) to the backend using **Elliptic Curve Integrated Encryption Scheme (ECIES)**. It utilizes **ECDH (Elliptic Curve Diffie-Hellman)** for key exchange, **AES-GCM** for encryption, and **ECDSA** for signature verification to ensure confidentiality and integrity during transmission.

## Overview

### **Components**
1. **Frontend (JavaScript)**:
    - The user enters their credit card number into a form.
    - The browser generates an ephemeral ECDH key pair for key exchange, encrypts the card number using **AES-GCM**, and signs a combination of the encrypted data and its ephemeral ECDH public key using an ephemeral **ECDSA** private key. The resulting payload is then sent to the server.

2. **Backend (Go)**:
    - The Go server generates the server's public and private keys for **ECDH** key exchange.
    - When the encrypted payload is received, it decrypts the data using the shared secret derived from the client's ephemeral ECDH public key and its own private key.
    - The server also verifies the **ECDSA** signature on the payload using the client's ephemeral ECDSA public key (provided as `signing_pub` in SPKI format) to ensure data integrity.


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

- **ECDSA (Elliptic Curve Digital Signature Algorithm)** is utilized for data integrity. The client signs the payload using its ephemeral ECDSA private key, and the server verifies this signature using the client's corresponding ephemeral ECDSA public key (sent as `signing_pub`).

### **Endpoints**

1. **`/js/getKey.js`**:
   - Dynamically serves the server’s public key in JavaScript format for client-side use.
   - The client will use this key to encrypt the card number and perform the key exchange.

2. **`/decrypt`**:
   - Accepts the encrypted card number and signature from the client.
   - The server performs:
     - **ECDH key exchange** to derive the shared secret (using its ECDH private key and the client's `ephemeral_pub`).
     - **AES-GCM decryption** of the encrypted card number (using the derived shared secret and the IV from `encrypted_data`).
     - **ECDSA signature verification**: The server ensures the integrity of the payload by:
        1. Decoding the client's ephemeral ECDSA public key from the `signing_pub` field (which is Base64 encoded SPKI format).
        2. Parsing this key into a usable Go `*ecdsa.PublicKey` object (e.g., using `x509.ParsePKIXPublicKey`).
        3. Verifying the received `signature` against the originally signed data (IV || ciphertext || client's ephemeral ECDH public key) using a function like `ecdsa.Verify`.

### **Example Payload Structure** (Sent by the Client)
```json
{
  "encrypted_data": "jBfqdg8MDlcv1weo07mNEvVIdIo+qKYbld4XDnAQISS3gkED+IQQcP0=", // Base64 encoded: IV || AES-GCM ciphertext
  "ephemeral_pub": "BEh1B7+Q4YHo80WEc2okfF2IbL4iUqZAk1br0iOjsheD/qTNs62KE9V0xPNdn1820JgJhOrECfhyM2wJx9MJgXA=", // Client's ephemeral ECDH public key (raw format, Base64 encoded)
  "signature": "IR4x8Kl/RmYQTxc57+RqPaUfvZWwugt0FbnK/CyZIUi9U859cu5k4I0zYKWlKUGg8Q4flqfNHM1CmRV9BAbOxw==", // Base64 encoded signature of (IV || ciphertext || client's ephemeral ECDH public key)
  "signing_pub": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWhzq6YEic97MFUDTm8OCYLM3r+4fLwv2OVl7KeSzLhQPTkE0knYap/WYTrehJr5+EAiyNLg1mHlnvH6CekGOsQ==", // Client's ephemeral ECDSA public key (SPKI format, Base64 encoded), used by server to verify signature
  "timestamp": 1678886400, // Unix timestamp (seconds since epoch)
  "nonce": "aBcDeFgHiJkLmNoPqRsTuVwXyZ==" // Base64 encoded random nonce for replay protection
}
```

### **Decryption Flow**
- The backend:
  1. Derives the shared secret from the **ECDH key exchange** using its own ECDH private key and the client's ephemeral ECDH public key (`ephemeral_pub`).
  2. Decrypts the card number using **AES-GCM** with the derived shared secret and the IV (extracted from the beginning of `encrypted_data`).
  3. Verifies the client's signature:
     - The server takes the `signing_pub` string (Base64 encoded SPKI) from the payload, decodes it, and parses it into a Go `*ecdsa.PublicKey`.
     - It then uses this parsed public key to verify the `signature` (also from the payload) against the data that was originally signed by the client (which is the concatenation of IV, ciphertext, and the client's ephemeral ECDH public key). This is typically done using a function like `ecdsa.Verify` in Go.

---

## **Frontend (JavaScript) Details**

### **Key Concepts**

1.  **Client-Side Key Generation (Ephemeral Keys for Each Transaction)**:
    -   The frontend JavaScript, using the **Web Crypto API**, generates two distinct ephemeral (short-lived) key pairs for each transaction to ensure forward secrecy and prevent key reuse:
        *   **Ephemeral ECDH Key Pair**: An Elliptic Curve Diffie-Hellman (ECDH) key pair (P-256 curve) is generated.
            *   The **public part** of this key pair (`ephKeyPair.publicKey`) is sent to the server as `ephemeral_pub`. The server uses this to derive the shared secret.
            *   The **private part** (`ephKeyPair.privateKey`) is used, along with the server's public key, to derive a shared symmetric key (AES-GCM key) for encryption.
        *   **Ephemeral ECDSA Key Pair**: An Elliptic Curve Digital Signature Algorithm (ECDSA) key pair (P-256 curve) is generated.
            *   The **private part** of this key pair (`signingKeyPair.privateKey`) is used to sign a combination of the encrypted data (IV + ciphertext) and the client's ephemeral ECDH public key.
            *   The **public part** (`signingKeyPair.publicKey`) is exported in SPKI format and sent to the server as `signing_pub`. The server uses this to verify the signature.

2.  **Encryption Process (AES-GCM)**:
    -   The card number is encrypted using **AES-GCM** with the derived shared symmetric key. AES-GCM provides both encryption and authenticity.
    -   A unique 96-bit Initialization Vector (IV) is generated for each encryption and is prepended to the ciphertext. The `encrypted_data` field in the payload contains `IV || ciphertext`.

3.  **Server's Public Key for ECDH**:
    -   The server’s static ECDH public key is obtained dynamically (e.g., via `/js/getKey.js`). This key is used by the client in the ECDH key agreement process to derive the shared secret.

4.  **Signature Generation and Payload Assembly**:
    -   The frontend signs a combination of the encrypted data (including IV) and its ephemeral ECDH public key. This signature ensures the integrity and authenticity of these components.
    -   The final payload sent to the server includes the `encrypted_data` (IV || ciphertext), `ephemeral_pub` (client's ephemeral ECDH public key), `signature`, `signing_pub` (client's ephemeral ECDSA public key in SPKI format, for server-side signature verification), `timestamp`, and `nonce`.

### **Encrypting and Sending Data**
```javascript
async function encryptCardNumber(cardNumber) {
    // 1. Generate ephemeral ECDH key pair
    const ephKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
    );

    // 2. Get server's public key (ensure this function is defined elsewhere to fetch the key)
    const serverPubKey = await getServerPublicKey(); 

    // 3. Derive shared AES-GCM key
    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: serverPubKey // Server's ECDH public key
        },
        ephKeyPair.privateKey, // Client's ephemeral ECDH private key
        {
            name: "AES-GCM",
            length: 256
        },
        false, // exportable
        ["encrypt"] // key usages
    );

    // 4. Encrypt card number
    const encoder = new TextEncoder();
    const data = encoder.encode(cardNumber);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM

    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey, // Derived AES-GCM key
        data
    );

    // Concatenate IV and ciphertext: IV || ciphertext
    const encryptedBytes = new Uint8Array(iv.byteLength + encrypted.byteLength);
    encryptedBytes.set(iv, 0);
    encryptedBytes.set(new Uint8Array(encrypted), iv.byteLength);

    // 5. Export client's ephemeral public key (for server to derive shared secret)
    const rawEphPub = await window.crypto.subtle.exportKey("raw", ephKeyPair.publicKey);

    // 6. Generate client's ECDSA signing key pair
    const signingKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true, // extractable
        ["sign"] // key usages
    );

    // 7. Sign (IV || ciphertext || ephemeral public key)
    // This combined data is what the server will verify
    const combinedDataToSign = new Uint8Array(encryptedBytes.length + rawEphPub.byteLength);
    combinedDataToSign.set(encryptedBytes, 0);
    combinedDataToSign.set(new Uint8Array(rawEphPub), encryptedBytes.length);

    const signature = await window.crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        signingKeyPair.privateKey, // Client's ECDSA private key
        combinedDataToSign
    );

    // 8. Export client's signing public key (SPKI format for easy import by server)
    const exportedSigningPub = await window.crypto.subtle.exportKey("spki", signingKeyPair.publicKey);

    // Generate timestamp and nonce for replay protection (ensure generateNonce is defined)
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce(); // Example: Implement generateNonce() to create a unique string

    return {
        encrypted_data: btoa(String.fromCharCode(...encryptedBytes)), // Base64(IV || ciphertext)
        ephemeral_pub: btoa(String.fromCharCode(...new Uint8Array(rawEphPub))), // Base64(client's ephemeral public key)
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))), // Base64(signature of combinedDataToSign)
        signing_pub: btoa(String.fromCharCode(...new Uint8Array(exportedSigningPub))), // Base64(client's ECDSA public key in SPKI format)
        timestamp: timestamp,
        nonce: nonce
    };
}

// Helper function to get server's public key (example, replace with actual implementation)
// async function getServerPublicKey() {
//     // Fetch the key from an endpoint or a configuration
//     // Example: const response = await fetch('/js/getKey.js');
//     // const keyText = await response.text(); 
//     // For demonstration, assuming key is available in a specific format/variable
//     // This needs to be implemented based on how serverPubKey is actually provided.
//     // return crypto.subtle.importKey( ... ); 
// }

// Helper function to generate nonce (example)
// function generateNonce(length = 16) {
//     const array = new Uint8Array(length);
//     crypto.getRandomValues(array);
//     return btoa(String.fromCharCode(...array));
// }
```

## Threat Model
Current ECIES-based implementation secures the **payload**, it's critical to layer in **web security best practices** to defend against broader threats like **session hijacking**, **replay attacks**, **CSRF**, **redirect attacks**, and more.

Few common attack patterns you can associate with this are:
1. [X] Replay Attacks - An attacker captures the encrypted payload and resends it later
2. [ ] Session Hijacking - Attacker steals a user’s session cookie or JWT and impersonates them.
3. [ ] Redirect Attacks (Open Redirects) - Attacker tricks the app into redirecting a user to a malicious site.
4. [ ] Cross-Site Request Forgery (CSRF) - Attacker tricks a user into sending unwanted requests via authenticated session
5. [X] Input Sanitization / Injection - Encrypted data is safe, but attackers can still exploit form fields or input points.
6. [ ] Man-in-the-Middle Attacks - Attacker intercepts the transmission between client and server.
7. [ ] Public Key Integrity - If the attacker swaps out the server’s public key, all encryption is broken.
8. [ ] Cross-Origin Resource Sharing (CORS) - You unintentionally expose the encryption or decryption endpoints to other origins
9. [X] Content Security Policy (CSP) - XSS and Inline script protection (Note: A basic CSP header is defined in `main.go` but is currently commented out. Uncommenting and configuring it appropriately is highly recommended.)
10. [ ]  Rate Limiting + Brute Force Protection

## Summary Table

| Threat | Mitigation |
|--------|------------|
| Replay | Timestamp + Nonce + Signature |
| Session Hijacking | Secure, HttpOnly, SameSite cookies |
| CSRF | Tokens + SameSite cookies |
| XSS | CSP headers (Partially implemented; a basic policy is commented out in `main.go`. Recommended to uncomment and configure.) |
| Open Redirects | URL whitelist |
| MiTM | HTTPS + HSTS |
| Public Key Tampering | Key pinning or signed key API |
| CORS | Restrict by domain |
| Rate Limiting | Per-IP/user limits |

---
## **Security Considerations**
- **ECDH** ensures that the server and client derive the same shared secret (used for AES-GCM encryption) without exposing their respective private keys. The client uses its ephemeral ECDH private key and the server's public key, while the server uses its private ECDH key and the client's ephemeral ECDH public key (`ephemeral_pub`).
- **AES-GCM** ensures confidentiality of the card number and also provides integrity and authenticity through its built-in authentication tag. The IV for AES-GCM is prepended to the ciphertext and sent as part of `encrypted_data`.
- **ECDSA** ensures that the data sent by the client (specifically, the `encrypted_data` containing IV || ciphertext, and the client's `ephemeral_pub`) has not been tampered with during transmission. This is achieved by the server verifying the `signature` using the client's ephemeral ECDSA public key (`signing_pub` in SPKI format).
