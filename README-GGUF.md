# ShredderVault GGUF module

`gguf-vault.mjs` stores ShredderVault records in a metadata-only GGUF v3 container. `gguf-vault.html` is a local browser editor for creating, decrypting, editing, rechunking, and re-encrypting those containers.

This is a GGUF container, **not an LLM model, tokenizer, or llama.cpp inference file**. The vault data is kept in namespaced GGUF metadata keys:

- `general.architecture = "shredder_vault"`
- `general.name`
- `shredder.format = "ShredderVault-GGUF"`
- `shredder.vault_json` (vault-level metadata)
- `shredder.records` (array of JSON-encoded encrypted records)

Each record has an index, byte length, bit count, SHA-256 digest, PBKDF2-SHA256 parameters, random salt and IV, and AES-256-GCM ciphertext. Per-record authentication and hash checks are performed on decryption. Rebuilding after edits uses fresh salts and IVs. PBKDF2 is set to 250,000 iterations by default.

## Browser preview

Serve the repository directory over HTTP (ES modules and Web Crypto need a secure context; `localhost` is supported):

```sh
python3 -m http.server 8080
```

Open <http://localhost:8080/gguf-vault.html>.

The editor accepts payload bytes as hex, then downloads a `.gguf`. To edit, upload that vault, enter its passphrase, decrypt, edit the hex payload and/or chunk size, then re-encrypt and download. The passphrase is never saved by the module or page. Keep a backup of the original vault; a new download contains new ciphertext and replaces the old file only if you choose to do so.

## Module API

```js
import { createVault, decryptVault, rebuildVault, encodeGGUF, decodeGGUF } from './gguf-vault.mjs';

const vault = await createVault({
  bytes: new Uint8Array([0x48, 0x69]),
  fileName: 'example.bin',
  mimeType: 'application/octet-stream',
  chunkBytes: 4,
  passphrase: 'choose-a-strong-passphrase',
});
const fileBlob = encodeGGUF(vault);
const parsed = await decodeGGUF(fileBlob);
const plaintext = await decryptVault(parsed, 'choose-a-strong-passphrase');
const editedVault = await rebuildVault(parsed, {
  bytes: plaintext,
  chunkBytes: 16,
  passphrase: 'choose-a-strong-passphrase',
});
```

`decodeGGUF` intentionally accepts this module's metadata-only, zero-tensor vault files; it rejects model GGUFs and unsupported versions. An external decrypter/model can integrate through the documented binary framing or use the module APIs. Decryption must occur before editing; ciphertext cannot be safely edited as if it were plaintext. This module does not run or connect to a language model.

## Security notes

- Use a unique, strong passphrase; the passphrase is not included in the container.
- Web Crypto requires HTTPS or localhost in browsers.
- AES-GCM detects ciphertext tampering. SHA-256 is an additional content-integrity check, not a password-strength mechanism.
- The GGUF metadata records are base64-encoded and not hidden beyond AES-GCM encryption. Filenames, MIME type, sizes, timestamps, and hashes remain visible as metadata.
- Editing decrypted bytes necessarily exposes them in browser memory and the editor. Do not open sensitive vaults on an untrusted device.
