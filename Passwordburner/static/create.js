async function generateKey() {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  return { key, raw };
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function encrypt(plainText, key) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plainText));
  return { iv, cipher: new Uint8Array(cipherBuf) };
}

document.getElementById('createBtn').addEventListener('click', async () => {
  const secret = document.getElementById('secret').value;
  const ttl = parseInt(document.getElementById('ttl').value, 10);
  const errorEl = document.getElementById('error');
  errorEl.hidden = true;
  if (!secret.trim()) {
    errorEl.textContent = 'Please enter a secret.';
    errorEl.hidden = false;
    return;
  }
  if (secret.length > 16000) {
    errorEl.textContent = 'Secret too large.';
    errorEl.hidden = false;
    return;
  }
  try {
    const { key, raw } = await generateKey();
    const { iv, cipher } = await encrypt(secret, key);
    const payload = {
      ciphertext: b64url(cipher),
      nonce: b64url(iv),
      ttl
    };
    const res = await fetch('/api/secrets', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || 'Failed to store secret');
    }
    const { id, auth_token } = await res.json();
    const link = `${location.origin}/s/${encodeURIComponent(id)}#${b64url(raw)}.${auth_token}`;
    const resultSec = document.getElementById('result');
    resultSec.hidden = false;
    const linkInput = document.getElementById('link');
    linkInput.value = link;
    linkInput.select();
  } catch (err) {
    errorEl.textContent = err.message || String(err);
    errorEl.hidden = false;
  }
});