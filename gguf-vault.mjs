const MAGIC = new Uint8Array([0x47, 0x47, 0x55, 0x46]); // GGUF
const VERSION = 3;
const TYPE_UINT32 = 4;
const TYPE_UINT64 = 10;
const TYPE_STRING = 8;
const TYPE_ARRAY = 9;
const DEFAULT_ITERATIONS = 250_000;
const MAX_RECORDS = 1_000_000;
const MAX_METADATA_BYTES = 64 * 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new TypeError('Expected Uint8Array or ArrayBuffer.');
}

function base64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(out);
}

function unbase64(value) {
  assert(typeof value === 'string' && value.length <= MAX_METADATA_BYTES * 2, 'Invalid or oversized base64 field.');
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', toBytes(bytes));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function deriveKey(passphrase, salt, iterations = DEFAULT_ITERATIONS) {
  assert(typeof passphrase === 'string' && passphrase.length > 0, 'A non-empty passphrase is required.');
  assert(Number.isInteger(iterations) && iterations >= 100_000 && iterations <= 2_000_000, 'PBKDF2 iteration count is outside the supported range.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptRecord(bytes, passphrase, index, iterations = DEFAULT_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, iterations);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, bytes);
  return {
    index,
    bytes: bytes.length,
    bitCount: bytes.length * 8,
    sha256: await sha256Hex(bytes),
    algorithm: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: base64(salt),
    iv: base64(iv),
    ciphertext: base64(new Uint8Array(encrypted)),
  };
}

async function decryptRecord(record, passphrase) {
  assert(record && record.algorithm === 'AES-256-GCM' && record.kdf === 'PBKDF2-SHA256', `Unsupported encryption metadata at record ${record?.index}.`);
  const salt = unbase64(record.salt);
  const iv = unbase64(record.iv);
  assert(salt.length === 16 && iv.length === 12, `Invalid salt or IV at record ${record.index}.`);
  const key = await deriveKey(passphrase, salt, record.iterations);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, unbase64(record.ciphertext)));
  } catch {
    throw new Error(`Could not decrypt record ${record.index}: wrong passphrase or damaged ciphertext.`);
  }
  assert(plain.length === record.bytes, `Record ${record.index} has an unexpected plaintext length.`);
  assert(await sha256Hex(plain) === record.sha256, `Record ${record.index} failed its SHA-256 integrity check.`);
  return plain;
}

function splitBytes(bytes, chunkBytes, maxRecords) {
  assert(Number.isInteger(chunkBytes) && chunkBytes >= 1 && chunkBytes <= 64 * 1024 * 1024, 'Chunk size must be from 1 byte to 64 MiB.');
  assert(Number.isInteger(maxRecords) && maxRecords >= 1 && maxRecords <= MAX_RECORDS, `Record limit must be from 1 to ${MAX_RECORDS}.`);
  const chunks = [];
  for (let offset = 0; offset < bytes.length && chunks.length < maxRecords; offset += chunkBytes) {
    chunks.push(bytes.slice(offset, Math.min(offset + chunkBytes, bytes.length)));
  }
  if (!chunks.length) chunks.push(new Uint8Array());
  return chunks;
}

/** Create a GGUF v3 ShredderVault from plaintext bytes. */
export async function createVault({ bytes, fileName = 'payload.bin', mimeType = 'application/octet-stream', chunkBytes = 4, maxRecords = MAX_RECORDS, passphrase, iterations = DEFAULT_ITERATIONS }) {
  const plain = toBytes(bytes);
  const chunks = splitBytes(plain, chunkBytes, maxRecords);
  const records = [];
  for (let index = 0; index < chunks.length; index += 1) {
    records.push(await encryptRecord(chunks[index], passphrase, index, iterations));
  }
  return {
    format: 'ShredderVault-GGUF',
    version: 1,
    createdAt: new Date().toISOString(),
    fileName: String(fileName),
    mimeType: String(mimeType),
    originalSizeBytes: plain.length,
    originalSha256: await sha256Hex(plain),
    chunkBytes,
    maxRecords,
    recordCount: records.length,
    truncated: plain.length > records.reduce((sum, record) => sum + record.bytes, 0),
    records,
  };
}

/** Decrypt and integrity-check all records, then verify the source digest when unmodified. */
export async function decryptVault(vault, passphrase) {
  validateVault(vault);
  const parts = [];
  for (const record of vault.records) parts.push(await decryptRecord(record, passphrase));
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const plaintext = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { plaintext.set(part, offset); offset += part.length; }
  if (!vault.truncated && total === vault.originalSizeBytes) {
    assert(await sha256Hex(plaintext) === vault.originalSha256, 'Vault payload failed its SHA-256 integrity check.');
  }
  return plaintext;
}

/** Rechunk edited plaintext and re-encrypt every record with fresh salt and IV values. */
export async function rebuildVault(vault, { bytes, chunkBytes = vault.chunkBytes, maxRecords = vault.maxRecords, passphrase, iterations = DEFAULT_ITERATIONS }) {
  validateVault(vault);
  return createVault({ bytes, fileName: vault.fileName, mimeType: vault.mimeType, chunkBytes, maxRecords, passphrase, iterations });
}

function validateVault(vault) {
  assert(vault && vault.format === 'ShredderVault-GGUF' && vault.version === 1, 'Unsupported ShredderVault format or version.');
  assert(Array.isArray(vault.records) && vault.records.length > 0 && vault.records.length <= MAX_RECORDS, 'Invalid record list.');
  assert(vault.recordCount === vault.records.length, 'Record count does not match the record list.');
  vault.records.forEach((record, index) => {
    assert(record.index === index, `Record ordering/index mismatch at ${index}.`);
    assert(Number.isInteger(record.bytes) && record.bytes >= 0, `Invalid byte length at record ${index}.`);
    assert(/^[a-f0-9]{64}$/i.test(record.sha256), `Invalid SHA-256 at record ${index}.`);
  });
}

function writeU32(view, offset, value) { view.setUint32(offset, value, true); }
function writeU64(view, offset, value) {
  assert(Number.isSafeInteger(value) && value >= 0, 'GGUF size exceeds JavaScript safe integer range.');
  view.setBigUint64(offset, BigInt(value), true);
}
function writeString(parts, value) {
  const bytes = encoder.encode(value);
  const length = new Uint8Array(8);
  writeU64(new DataView(length.buffer), 0, bytes.length);
  parts.push(length, bytes);
}
function writeKVString(parts, key, value) {
  writeString(parts, key);
  const type = new Uint8Array(4);
  writeU32(new DataView(type.buffer), 0, TYPE_STRING);
  parts.push(type);
  writeString(parts, value);
}
function writeKVStringArray(parts, key, values) {
  writeString(parts, key);
  const header = new Uint8Array(16);
  const view = new DataView(header.buffer);
  writeU32(view, 0, TYPE_ARRAY);
  writeU32(view, 4, TYPE_STRING);
  writeU64(view, 8, values.length);
  parts.push(header);
  for (const value of values) writeString(parts, value);
}

/** Encode a vault as a GGUF v3 file with ShredderVault data in namespaced metadata. */
export function encodeGGUF(vault) {
  validateVault(vault);
  const parts = [MAGIC];
  const header = new Uint8Array(16);
  const view = new DataView(header.buffer);
  writeU32(view, 0, VERSION);
  writeU64(view, 4, 0); // metadata-only container; there are no model tensors.
  writeU64(view, 12, 4); // actual header storage is 20 bytes; allocate corrected below.
  // Header is 4-byte version, 8-byte tensor count, 8-byte metadata count.
  const properHeader = new Uint8Array(20);
  const properView = new DataView(properHeader.buffer);
  writeU32(properView, 0, VERSION);
  writeU64(properView, 4, 0);
  writeU64(properView, 12, 4);
  parts.push(properHeader);
  writeKVString(parts, 'general.architecture', 'shredder_vault');
  writeKVString(parts, 'general.name', vault.fileName || 'ShredderVault');
  writeKVString(parts, 'shredder.format', vault.format);
  writeKVString(parts, 'shredder.vault_json', JSON.stringify({ ...vault, records: undefined }));
  writeKVStringArray(parts, 'shredder.records', vault.records.map(record => JSON.stringify(record)));
  return new Blob(parts, { type: 'application/octet-stream' });
}

class Reader {
  constructor(bytes) { this.bytes = toBytes(bytes); this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength); this.offset = 0; }
  take(length) {
    assert(Number.isSafeInteger(length) && length >= 0 && length <= this.bytes.length - this.offset, 'Malformed or truncated GGUF file.');
    const result = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return result;
  }
  u32() { const n = this.view.getUint32(this.offset, true); this.offset += 4; return n; }
  u64() {
    const value = this.view.getBigUint64(this.offset, true); this.offset += 8;
    assert(value <= BigInt(Number.MAX_SAFE_INTEGER), 'GGUF value exceeds JavaScript safe integer range.');
    return Number(value);
  }
  string() { const length = this.u64(); assert(length <= MAX_METADATA_BYTES, 'GGUF metadata string is too large.'); return decoder.decode(this.take(length)); }
  skip(type) {
    const sizes = new Map([[0, 1], [1, 1], [2, 2], [3, 2], [4, 4], [5, 4], [6, 4], [7, 1], [10, 8], [11, 8], [12, 8]]);
    if (type === TYPE_STRING) { this.string(); return; }
    if (type === TYPE_ARRAY) {
      const elementType = this.u32(); const count = this.u64();
      assert(count <= MAX_RECORDS, 'GGUF array is too large.');
      if (elementType === TYPE_STRING) { for (let i = 0; i < count; i += 1) this.string(); return; }
      assert(sizes.has(elementType), 'Unsupported GGUF array type.'); this.take(count * sizes.get(elementType)); return;
    }
    assert(sizes.has(type), 'Unsupported GGUF metadata type.'); this.take(sizes.get(type));
  }
}

/** Parse this module's metadata-only GGUF vault; unknown metadata values are skipped. */
export async function decodeGGUF(input) {
  const bytes = input instanceof Blob ? new Uint8Array(await input.arrayBuffer()) : toBytes(input);
  const reader = new Reader(bytes);
  assert(reader.take(4).every((byte, index) => byte === MAGIC[index]), 'Not a GGUF file.');
  const version = reader.u32();
  assert(version === VERSION, `Unsupported GGUF version ${version}; expected version ${VERSION}.`);
  const tensorCount = reader.u64();
  const metadataCount = reader.u64();
  assert(tensorCount === 0, 'This reader expects a metadata-only ShredderVault GGUF (zero tensors).');
  assert(metadataCount <= 10_000, 'GGUF metadata count is unreasonable.');
  const metadata = new Map();
  for (let i = 0; i < metadataCount; i += 1) {
    const key = reader.string();
    const type = reader.u32();
    if (key === 'shredder.vault_json' && type === TYPE_STRING) metadata.set(key, reader.string());
    else if (key === 'shredder.records' && type === TYPE_ARRAY) {
      const elementType = reader.u32(); const count = reader.u64();
      assert(elementType === TYPE_STRING && count > 0 && count <= MAX_RECORDS, 'Invalid ShredderVault records array.');
      const records = [];
      for (let j = 0; j < count; j += 1) records.push(JSON.parse(reader.string()));
      metadata.set(key, records);
    } else reader.skip(type);
  }
  assert(reader.offset === bytes.length, 'Unexpected trailing data after GGUF metadata.');
  const metadataJson = metadata.get('shredder.vault_json');
  const records = metadata.get('shredder.records');
  assert(metadataJson && records, 'GGUF is missing ShredderVault metadata or records.');
  const vault = JSON.parse(metadataJson);
  vault.records = records;
  vault.recordCount = records.length;
  validateVault(vault);
  return vault;
}

export { DEFAULT_ITERATIONS };
