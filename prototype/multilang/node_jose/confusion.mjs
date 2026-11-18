// Cross-language — Node panva/jose v5 algorithm confusion (RS256->HS256).
// jose is strict-by-design: jwtVerify requires you to pass a key of the right type.
// We attempt the classic confusion (attacker uses RSA public key as HMAC secret)
// and report whether the forged admin token is accepted.
import { generateKeyPair, exportSPKI, SignJWT, jwtVerify, importSPKI } from 'jose';
import { createHmac } from 'node:crypto';

function b64url(x){ return Buffer.from(x).toString('base64url'); }
const ver = (await import('jose/package.json', { with: { type: 'json' } })).default.version;

const { publicKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
const spki = await exportSPKI(publicKey);        // PEM string (public, attacker has it)

// forged HS256 token: HMAC secret = the SPKI PEM bytes, role=admin
const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
const payload = b64url(JSON.stringify({ role: 'admin', iss: 'real-issuer' }));
const sig = createHmac('sha256', spki).update(`${header}.${payload}`).digest('base64url');
const forged = `${header}.${payload}.${sig}`;

console.log('='.repeat(70));
console.log(`panva/jose ${ver} — algorithm confusion (RS256->HS256)`);
console.log('='.repeat(70));

let tp = 0;
// (1) verifier holds the RSA public key object; jose picks alg from the key/opts
try {
  const { payload: p } = await jwtVerify(forged, publicKey);
  const admin = p.role === 'admin'; tp = tp || (admin ? 1 : 0);
  console.log(`  [${admin?'A':'?'}] verify(publicKey object)            ACCEPT role=${p.role}`);
} catch (e) { console.log(`  [OK] verify(publicKey object)            REJECT ${e.code || e.name}`); }

// (2) attacker also tries importing the PEM as an HMAC-usable key path via createSecretKey-like misuse
try {
  const { payload: p } = await jwtVerify(forged, await importSPKI(spki, 'RS256'));
  const admin = p.role === 'admin'; tp = tp || (admin ? 1 : 0);
  console.log(`  [${admin?'A':'?'}] verify(importSPKI RS256)            ACCEPT role=${p.role}`);
} catch (e) { console.log(`  [OK] verify(importSPKI RS256)            REJECT ${e.code || e.name}`); }

console.log('-'.repeat(70));
console.log(`RESULT\tpanva/jose ${ver}\tconfusion_TP=${tp}`);
