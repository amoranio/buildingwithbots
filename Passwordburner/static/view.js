function parseFragment() {
  const frag = location.hash.slice(1);
  if (!frag.includes('.')) return {};
  const [keyPart, token] = frag.split('.', 2);
  return { keyPart, token };
}

function decodeB64url(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function importKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
}

async function decryptData(cipher, nonce, key) {
  const plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, cipher);
  return new TextDecoder().decode(new Uint8Array(plaintextBuf));
}

(async () => {
  const errorEl = document.getElementById('error');
  const stateEl = document.getElementById('state');
  const secretEl = document.getElementById('secret');
  const burnBtn = document.getElementById('burn');
  const loadingEl = document.getElementById('loading');
  try {
    const { keyPart, token } = parseFragment();
    const id = decodeURIComponent(location.pathname.split('/').pop() || '');
    if (!keyPart || !token || !id) {
      throw new Error('Invalid or incomplete link.');
    }
    const res = await fetch('/api/consume', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id, token })
    });
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || 'Secret not found or already consumed.');
    }
    const { ciphertext, nonce } = await res.json();
    const key = await importKey(decodeB64url(keyPart));
    const plain = await decryptData(decodeB64url(ciphertext), decodeB64url(nonce), key);
    loadingEl.hidden = true;
    secretEl.textContent = plain;
    secretEl.hidden = false;
    stateEl.textContent = 'This secret has now been burned. Copy it if you need it — it won’t be retrievable again.';
    stateEl.hidden = false;
    window.addEventListener('beforeunload', () => {
      try {
        navigator.sendBeacon('/api/burn', new Blob([JSON.stringify({ id, token })], { type: 'application/json' }));
      } catch {}
    });
    burnBtn.hidden = false;
    burnBtn.addEventListener('click', async () => {
      await fetch('/api/burn', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, token }) });
      stateEl.textContent = 'Secret burned.';
      burnBtn.disabled = true;
    });
  } catch (err) {
    loadingEl.hidden = true;
    errorEl.textContent = err.message || String(err);
    errorEl.hidden = false;
  }
})();