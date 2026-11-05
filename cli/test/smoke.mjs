import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, stat, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { argon2id } from 'hash-wasm';
import * as crypt from '../dist/crypto.js';
import { Client, ApiError } from '../dist/api.js';
import { generateSecret, generatePassphrase } from '../dist/generate.js';
import { normaliseUrl } from '../dist/config.js';

// Run after `npm run build`. All HTTP and token fixtures stay on loopback.
const root = join(import.meta.dirname, '..');
const { version } = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const temp = await mkdtemp(join(tmpdir(), 'esecrets-smoke-'));
const originalToken = process.env.ESECRETS_TOKEN;
// Protocol parameters are deliberately independent of the implementation under test.
const protocolArgon2 = { parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32 };
const seen = [];
const uploadParts = new Map();
let lastInit;
let partCounter = 0;
const server = createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/v1/admin/')) assert.equal(req.headers['cf-access-jwt-assertion'], 'synthetic.local.token');
    // Upload bytes live in uploadParts; retaining them twice would inflate memory usage.
    seen.push({ method: req.method, path: url.pathname, body: url.pathname.endsWith('/part') ? undefined : body });
    res.setHeader('Content-Type', 'application/json');
    if (url.pathname === '/api/v1/admin/secrets') {
      res.end(JSON.stringify(req.method === 'GET' ? { secrets: [] } : { ok: true }));
    } else if (url.pathname === '/api/v1/admin/links') {
      res.end(JSON.stringify({ id: 'local-link', shortUrl: 'https://example.invalid/s/local-link' }));
    } else if (url.pathname === '/api/v1/admin/files/init') {
      lastInit = JSON.parse(body);
      partCounter = 0;
      uploadParts.clear();
      res.end(JSON.stringify({ key: 'local-key', uploadId: 'local-upload', fileId: lastInit.id ?? 'local-file' }));
    } else if (url.pathname === '/api/v1/admin/files/part') {
      partCounter++;
      uploadParts.set(Number(url.searchParams.get('num')), body);
      res.end(JSON.stringify({ partNumber: Number(url.searchParams.get('num')), etag: 'local-etag' }));
    } else if (url.pathname === '/api/v1/admin/files/complete') {
      res.end(JSON.stringify({ ok: true }));
    } else if (url.pathname === '/api/v1/admin/stats') {
      res.end(JSON.stringify({ used: 0, limit: 1024, maxUpload: 1024, files: [] }));
    } else if (url.pathname === '/ui/words-eff.v1.txt') {
      res.end(Array.from({ length: 7776 }, (_, i) => `word${i}`).join('\n'));
    } else if (url.pathname === '/ui/words-bip39.v1.txt') {
      res.end(Array.from({ length: 2048 }, (_, i) => `word${i}`).join('\n'));
    } else if (url.pathname.endsWith('/missing')) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'NOT_FOUND' }));
    } else if (req.method === 'DELETE') {
      res.end(JSON.stringify({ ok: true }));
    } else {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'UNEXPECTED_TEST_ROUTE' }));
    }
  } catch (e) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: e.message }));
  }
});
let baseUrl;

function cli(args, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--throw-deprecation', join(root, 'dist/index.js'), ...args], {
      env: { ...process.env, ESECRETS_CONFIG_DIR: join(temp, 'config'), ESECRETS_URL: baseUrl, ESECRETS_TOKEN: 'synthetic.local.token', NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 120_000,
      killSignal: 'SIGKILL',
    });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve({ stdout, stderr }) : reject(new Error(`CLI ${args[0]} exit ${code}: ${stderr}`)));
    child.stdin.end(input);
  });
}

async function decrypt(bytes, iv, passphrase, id) {
  const raw = await argon2id({ password: new TextEncoder().encode(passphrase), salt: new TextEncoder().encode(id), outputType: 'binary', ...protocolArgon2 });
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, bytes));
}

async function expectedVerifier(passphrase, id) {
  const raw = await argon2id({
    password: new TextEncoder().encode(passphrase),
    salt: new TextEncoder().encode(`${id}_v`),
    outputType: 'binary',
    ...protocolArgon2,
  });
  return Buffer.from(raw).toString('base64');
}

let passed = 0;
async function test(name, body) { await body(); passed++; console.log(`PASS ${name}`); }

try {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  process.env.ESECRETS_TOKEN = 'synthetic.local.token';

  await test('ESM CLI startup/help/version', async () => {
    assert.equal((await cli(['version'])).stdout.trim(), version);
    assert.match((await cli(['help'])).stderr, /USAGE/);
  });
  await test('profile config read/write in isolated directory', async () => {
    await cli(['config', 'add', 'local', baseUrl]);
    const config = JSON.parse((await cli(['config', 'list', '--json'])).stdout);
    assert.equal(config.profiles.local.url, baseUrl);
    assert.equal((await stat(join(temp, 'config/config.json'))).mode & 0o777, 0o600);
  });
  await test('URL parsing and synthetic token decode', async () => {
    assert.equal(normaliseUrl('example.invalid/path'), 'https://example.invalid');
    assert.equal(normaliseUrl(baseUrl), baseUrl);
    assert.throws(() => normaliseUrl('http://example.invalid'));
    const who = JSON.parse((await cli(['who', '--json'])).stdout);
    assert.equal(who.signedIn, true);
    assert.equal(who.deployment, baseUrl);
  });
  await test('Argon2id WASM and AES-GCM unicode secret roundtrip', async () => {
    const id = 'be5b6e81-88f8-4946-96b9-8e5f5d6c4f43', pass = 'synthetic-passphrase', plain = 'Zażółć gęślą jaźń 🔐\n';
    const enc = JSON.parse(await crypt.encryptSecret(plain, pass, id));
    const dec = await decrypt(Buffer.from(enc.d, 'base64'), Buffer.from(enc.iv, 'base64'), pass, id);
    assert.equal(new TextDecoder().decode(dec), plain);
    assert.equal((await crypt.deriveVerifier(pass, id)).length, 44);
    assert.deepEqual(crypt.ARGON2_PARAMS, protocolArgon2);
    assert.equal(crypt.ALGO_VERSION, 'argon2id-v1');
    assert.equal(await crypt.deriveVerifier(pass, id), await expectedVerifier(pass, id));
  });
  await test('all five generators with loopback wordlists', async () => {
    assert.equal(generatePassphrase().length, 20);
    assert.equal((await generateSecret('nist', baseUrl)).value.length, 20);
    assert.equal((await generateSecret('legacy', baseUrl)).value.length, 12);
    assert.equal(Buffer.from((await generateSecret('api', baseUrl)).value, 'base64').length, 32);
    assert.equal((await generateSecret('eff', baseUrl)).value.split('-').length, 6);
    assert.equal((await generateSecret('bip39', baseUrl)).value.split('-').length, 12);
  });
  await test('fetch authenticated GET/POST/DELETE and error decoding', async () => {
    assert.deepEqual(JSON.parse((await cli(['ls', '--json'])).stdout), []);
    assert.equal(JSON.parse((await cli(['link', 'https://example.invalid', '--json'])).stdout).id, 'local-link');
    assert.equal(JSON.parse((await cli(['rm', 'local-secret', '--json'])).stdout).revoked, true);
    const client = new Client(baseUrl);
    await assert.rejects(() => client.getJson('/missing'), e => e instanceof ApiError && e.status === 404 && e.code === 'NOT_FOUND');
  });
  await test('secret stdin CLI creation and recipient decryption', async () => {
    const plain = 'synthetic secret 🔐';
    const created = JSON.parse((await cli(['put', '--json', '--ttl', '30m'], `${plain}\n`)).stdout);
    const body = JSON.parse(seen.findLast(r => r.path === '/api/v1/admin/secrets' && r.method === 'POST').body);
    const envelope = JSON.parse(body.encryptedData);
    const pass = decodeURIComponent(new URL(created.link).hash.slice(1));
    const dec = await decrypt(Buffer.from(envelope.d, 'base64'), Buffer.from(envelope.iv, 'base64'), pass, created.id);
    assert.equal(new TextDecoder().decode(dec), plain);
    assert.equal(body.verifier, await expectedVerifier(pass, created.id));
    assert.equal(body.ttl, 1800);
  });
  const file = join(temp, 'fixture.bin');
  const content = Buffer.alloc(50 * 1024 * 1024 + 123, 0x5a);
  content.write('synthetic local upload');
  await writeFile(file, content);
  await test('multipart file upload through Node fetch preserves exact bytes', async () => {
    const created = JSON.parse((await cli(['file', file, '--json'])).stdout);
    assert.equal(created.encrypted, false);
    assert.equal(partCounter, 2);
    assert.deepEqual(Buffer.concat([...uploadParts.keys()].sort((a,b) => a-b).map(n => uploadParts.get(n))), content);
  });
  await test('encrypted multipart upload and recipient decryption', async () => {
    const created = JSON.parse((await cli(['file', file, '--e2ee', '--json'])).stdout);
    assert.equal(created.encrypted, true);
    assert.equal(partCounter, 2);
    const encrypted = Buffer.concat([...uploadParts.keys()].sort((a,b) => a-b).map(n => uploadParts.get(n)));
    const pass = decodeURIComponent(new URL(created.link).hash.slice(1));
    assert.equal(lastInit.verifier, await expectedVerifier(pass, created.id));
    const dec = await decrypt(encrypted.subarray(12), encrypted.subarray(0,12), pass, created.id);
    assert.deepEqual(Buffer.from(dec), content);
  });
  console.log(JSON.stringify({ version, node: process.version, testsPassed: passed, httpRequests: seen.length, result: 'PASS' }));
} finally {
  if (originalToken === undefined) delete process.env.ESECRETS_TOKEN;
  else process.env.ESECRETS_TOKEN = originalToken;
  try {
    if (server.listening) {
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

