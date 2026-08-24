import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/**
 * Single-use nonce store persisted to a JSON file with atomic writes.
 * Only SHA-256 hashes of nonces are stored on disk.
 * Issue/consume are safe under concurrency within one process:
 * the check-and-delete critical section is fully synchronous.
 */
export async function createNonceStore(path, { ttlMs = 10 * 60 * 1000 } = {}) {
  const ttl = ttlMs;
  await mkdir(dirname(path), { recursive: true }).catch(() => {});
  let map = {};
  try {
    map = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    /* first boot */
  }

  async function flush() {
    const tmp = `${path}.tmp`;
    await writeFile(tmp, JSON.stringify(map));
    await rename(tmp, path); // atomic swap — crash-safe
  }

  function sweep() {
    const now = Date.now();
    for (const k of Object.keys(map)) if (map[k] < now) delete map[k];
  }

  return {
    /** Mint a fresh single-use nonce. */
    async issue() {
      sweep();
      const nonce = randomBytes(32).toString('hex');
      map[sha256(nonce)] = Date.now() + ttlMs;
      await flush();
      return nonce;
    },

    /** Atomically consume a nonce. Returns false if missing, used, or expired. */
    async consume(nonce) {
      sweep();
      const h = sha256(String(nonce));
      if (!map[h] || map[h] < Date.now()) return false;
      delete map[h];
      await flush();
      return true;
    },

    /**
     * Atomically claim a client-supplied single-use id (e.g. NIP-98 event id).
     * First claim wins; the id is then burned for ttl.
     */
    async claim(id) {
      sweep();
      const h = sha256(`claim:${String(id)}`);
      if (map[h]) return false;
      map[h] = Date.now() + ttl;
      await flush();
      return true;
    },

    _size: () => Object.keys(map).length,
  };
}
