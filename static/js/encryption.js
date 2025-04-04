async function encryptCardNumber(cardNumber) {
    // 1. Generate ephemeral key pair
    const ephKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey"]
    );

    // 2. Get server public key
    const serverPubKey = await getServerPublicKey();

    // 3. Derive shared AES-GCM key
    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: serverPubKey
        },
        ephKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt"]
    );

    // 4. Encrypt card number
    const encoder = new TextEncoder();
    const data = encoder.encode(cardNumber);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce

    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        derivedKey,
        data
    );

    const encryptedBytes = new Uint8Array(iv.byteLength + encrypted.byteLength);
    encryptedBytes.set(iv, 0);
    encryptedBytes.set(new Uint8Array(encrypted), iv.byteLength);

    // 5. Export ephemeral public key
    const rawEphPub = await window.crypto.subtle.exportKey("raw", ephKeyPair.publicKey);

    // 6. Generate signing key (ECDSA)
    const signingKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign"]
    );

    // 7. Sign (ciphertext + ephemeral pub key)
    const combined = new Uint8Array(encryptedBytes.length + rawEphPub.byteLength);
    combined.set(encryptedBytes, 0);
    combined.set(new Uint8Array(rawEphPub), encryptedBytes.length);

    const signature = await window.crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        signingKeyPair.privateKey,
        combined
    );

    // 8. Export signing public key (SPKI)
    const exportedSigningPub = await window.crypto.subtle.exportKey("spki", signingKeyPair.publicKey);

    return {
        encrypted_data: btoa(String.fromCharCode(...encryptedBytes)),
        ephemeral_pub: btoa(String.fromCharCode(...new Uint8Array(rawEphPub))),
        signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
        signing_pub: btoa(String.fromCharCode(...new Uint8Array(exportedSigningPub)))
    };
}
