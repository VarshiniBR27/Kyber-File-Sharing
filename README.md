# KyberShare — Post-Quantum Secure File Sharing

A hackathon prototype for sharing files with **ML-KEM-768 (NIST FIPS 203)** and **AES-256-GCM**.

## How it works

1. The recipient generates an ML-KEM-768 key pair in their browser and shares the **public-key JSON** with the sender.
2. The sender selects that public key. The browser encapsulates an ML-KEM shared secret and encrypts the file with AES-256-GCM.
3. Only the encrypted file, ML-KEM ciphertext, nonce, salt, and basic metadata are uploaded.
4. The recipient downloads the encrypted file and decrypts it in their browser with their private-key JSON.

**ML-KEM is a key-encapsulation mechanism, not a file-encryption algorithm.** AES-GCM encrypts the file. The server does not receive the plaintext file or private key.

## Requirements

- Node.js 20 LTS or newer
- npm
- A modern browser

## Run locally

```bash
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally http://localhost:5173). The API runs on http://localhost:3000.

Production build:

```bash
npm run build
npm start
```

Then open http://localhost:3000.

## First-time test

1. Click **Generate recipient keys**.
2. Save both key files somewhere safe. Share only the public-key file with the sender.
3. Use **Encrypt & upload** with a test file and the recipient's public-key JSON.
4. Copy the share ID, then use **Download & decrypt** with that ID and the recipient's private-key JSON.

Use a small, non-sensitive test file first. Losing the private key means the file cannot be decrypted.

## Security notes — read before real use

- This is a learning/hackathon prototype, not a production-audited secure file-sharing service.
- Anyone who obtains a share ID can download that encrypted object; the ID is a bearer link, not user authentication.
- ML-KEM does **not** authenticate the sender or recipient public key. Verify the recipient public key fingerprint through a trusted separate channel to reduce man-in-the-middle risk.
- Private-key JSON is unencrypted. Store it securely, never upload it, and never commit it to Git.
- Use HTTPS in deployment. Add authentication, rate limits, malware scanning, quotas, expiration/deletion, access control, monitoring, and a professional security review before real use.
- Server metadata includes the original filename and content type; avoid sensitive filenames.
- Do not use this prototype for confidential or irreplaceable data.

## Stack

HTML, CSS, JavaScript, Node.js, Express, Vite, `@noble/post-quantum`, and the browser Web Crypto API.

## Cryptography references

- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- Noble Post-Quantum package: https://www.npmjs.com/package/@noble/post-quantum
