import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import './style.css';

const $ = (id) => document.getElementById(id);
const MAX_FILE_BYTES = 25 * 1024 * 1024;
let generatedKeys = null;

function toBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function setStatus(id, message, type = '') {
  const el = $(id);
  el.textContent = message;
  el.className = 'inline-status' + (type ? ' ' + type : '');
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function readJsonFile(file) {
  if (!file) throw new Error('Please select a JSON key file.');
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch {
    throw new Error('That file is not valid JSON.');
  }
  if (parsed.algorithm !== 'ML-KEM-768' || typeof parsed.key !== 'string') {
    throw new Error('This is not a KyberShare ML-KEM-768 key file.');
  }
  return fromBase64(parsed.key);
}

async function deriveAesKey(sharedSecret, salt) {
  const baseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('KyberShare-v1 file encryption') },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function validateBrowserCrypto() {
  if (!window.crypto?.subtle || !window.crypto?.getRandomValues) {
    throw new Error('Web Crypto is unavailable. Use a modern browser on localhost or HTTPS.');
  }
}

$('generate-keys').addEventListener('click', () => {
  try {
    validateBrowserCrypto();
    generatedKeys = ml_kem768.keygen();
    $('download-public').disabled = false;
    $('download-private').disabled = false;
    setStatus('key-status', 'Key pair generated in memory. Download both files now.', 'success');
  } catch (error) {
    setStatus('key-status', error.message || 'Could not generate keys.', 'error');
  }
});

$('download-public').addEventListener('click', () => {
  if (!generatedKeys) return;
  downloadJson('kybershare-public-key.json', {
    algorithm: 'ML-KEM-768',
    format: 1,
    key: toBase64(generatedKeys.publicKey)
  });
});

$('download-private').addEventListener('click', () => {
  if (!generatedKeys) return;
  downloadJson('kybershare-private-key-KEEP-SECRET.json', {
    algorithm: 'ML-KEM-768',
    format: 1,
    key: toBase64(generatedKeys.secretKey)
  });
  setStatus('key-status', 'Private key downloaded. Keep it secret; do not send it to the sender or upload it.', 'success');
});

$('encrypt-upload').addEventListener('click', async () => {
  const button = $('encrypt-upload');
  button.disabled = true;
  try {
    validateBrowserCrypto();
    const publicFile = $('recipient-public').files[0];
    const plainFile = $('plain-file').files[0];
    if (!publicFile || !plainFile) throw new Error('Select the recipient public-key JSON and a file first.');
    if (plainFile.size > MAX_FILE_BYTES) throw new Error('Choose a file smaller than 25 MB.');
    setStatus('upload-status', 'Encrypting in your browser…');

    const publicKey = await readJsonFile(publicFile);
    if (publicKey.length !== ml_kem768.publicKeyLen) throw new Error('Public key has an unexpected length.');
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveAesKey(sharedSecret, salt);
    const plaintext = await plainFile.arrayBuffer();
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesKey, plaintext);

    const metadata = {
      kemCiphertext: toBase64(cipherText),
      iv: toBase64(iv),
      salt: toBase64(salt),
      originalName: plainFile.name,
      contentType: plainFile.type || 'application/octet-stream'
    };
    const form = new FormData();
    form.append('file', new Blob([encrypted], { type: 'application/octet-stream' }), 'encrypted.bin');
    form.append('metadata', JSON.stringify(metadata));

    setStatus('upload-status', 'Uploading encrypted bytes only…');
    const response = await fetch('/api/files', { method: 'POST', body: form });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Upload failed.');
    $('share-id').value = result.id;
    const shareResult = $('share-result');
    shareResult.hidden = false;
    shareResult.replaceChildren();
    const label = document.createElement('div');
    label.textContent = 'Share ID: ' + result.id;
    const copyButton = document.createElement('button');
    copyButton.className = 'button button-quiet';
    copyButton.type = 'button';
    copyButton.textContent = 'Copy share ID';
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(result.id);
        copyButton.textContent = 'Copied';
      } catch {
        copyButton.textContent = 'Select and copy the ID above';
      }
    });
    shareResult.append(label, copyButton);
    setStatus('upload-status', 'Encrypted file uploaded successfully. Share the ID and public information with the recipient, but never share your private key.', 'success');
  } catch (error) {
    setStatus('upload-status', error.message || 'Encryption/upload failed.', 'error');
  } finally {
    button.disabled = false;
  }
});

$('decrypt-download').addEventListener('click', async () => {
  const button = $('decrypt-download');
  button.disabled = true;
  try {
    validateBrowserCrypto();
    const id = $('share-id').value.trim();
    const privateFile = $('recipient-private').files[0];
    if (!id) throw new Error('Enter the share ID.');
    if (!privateFile) throw new Error('Select the recipient private-key JSON.');
    setStatus('download-status', 'Fetching encrypted file…');

    const metadataResponse = await fetch('/api/files/' + encodeURIComponent(id));
    const metadata = await metadataResponse.json();
    if (!metadataResponse.ok) throw new Error(metadata.error || 'Could not find this share.');
    const secretKey = await readJsonFile(privateFile);
    if (secretKey.length !== 2400) throw new Error('Private key has an unexpected length.');
    const blobResponse = await fetch('/api/files/' + encodeURIComponent(id) + '/blob');
    if (!blobResponse.ok) throw new Error('Could not download encrypted file.');
    const encrypted = await blobResponse.arrayBuffer();

    setStatus('download-status', 'Decapsulating key and decrypting locally…');
    const sharedSecret = ml_kem768.decapsulate(fromBase64(metadata.kemCiphertext), secretKey);
    const aesKey = await deriveAesKey(sharedSecret, fromBase64(metadata.salt));
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(metadata.iv), tagLength: 128 },
      aesKey,
      encrypted
    );
    const blob = new Blob([plaintext], { type: metadata.contentType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = metadata.originalName || 'decrypted-file';
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    setStatus('download-status', 'Decryption succeeded. Your file was saved by the browser.', 'success');
  } catch (error) {
    setStatus('download-status', error.name === 'OperationError'
      ? 'Decryption failed: wrong private key or the encrypted data was modified.'
      : (error.message || 'Download/decryption failed.'), 'error');
  } finally {
    button.disabled = false;
  }
});

fetch('/api/health')
  .then((response) => response.json())
  .then((data) => {
    if (data.ok) console.info('KyberShare API connected.');
  })
  .catch(() => setStatus('upload-status', 'API is not reachable yet. Start the project with npm run dev.', 'error'));
