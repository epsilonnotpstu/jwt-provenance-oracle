// scale30 Node adapter — ৬টা library, PREREG §3 contract।
// ব্যবহার: node run.mjs <cases.json> <outdir> [impl ...]
// load(case) → key (stage=keyload); verify(token, key, algs) → claims (stage=verify)।
// config = README-র নিরাপদ ব্যবহার: allow-list পিন, key টাইপ করা। truth.json কখনো পড়া হয় না।
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createSecretKey, createPublicKey } from "node:crypto";
import * as jose from "jose";
const require = createRequire(import.meta.url);
const ver = (p) => require(`./node_modules/${p}/package.json`).version;

const secret = (c) => Buffer.from(c.key.secret_hex, "hex");
const isH = (c) => c.key.kind === "hmac";

const IMPLS = {
  // panva/jose: jwtVerify(token, KeyObject, { algorithms })
  jose: { pkg: "jose", backend: "node:crypto",
    load: (c) => (isH(c) ? createSecretKey(secret(c)) : createPublicKey(c.key.pem)),
    verify: async (t, k, algs) => (await jose.jwtVerify(t, k, { algorithms: algs })).payload },
  // jsonwebtoken: verify(token, key, { algorithms })
  jsonwebtoken: { pkg: "jsonwebtoken", backend: "node:crypto(jws)",
    load: (c) => (isH(c) ? secret(c) : c.key.pem),
    verify: (t, k, algs) => require("jsonwebtoken").verify(t, k, { algorithms: algs }) },
  // fast-jwt: createVerifier({ key, algorithms })(token)
  "fast-jwt": { pkg: "fast-jwt", backend: "node:crypto",
    load: (c) => (isH(c) ? secret(c) : c.key.pem),
    verify: (t, k, algs) => require("fast-jwt").createVerifier({ key: k, algorithms: algs })(t) },
  // jsrsasign: KJUR.jws.JWS.verifyJWT(token, key, { alg }) → bool (exp যাচাই করে)
  jsrsasign: { pkg: "jsrsasign", backend: "pure-js",
    load: (c) => (isH(c) ? { hex: c.key.secret_hex } : require("jsrsasign").KEYUTIL.getKey(c.key.pem)),
    verify: (t, k, algs) => {
      const { KJUR, b64utoutf8 } = require("jsrsasign");
      if (!KJUR.jws.JWS.verifyJWT(t, k, { alg: algs })) throw new Error("verifyJWT returned false");
      return JSON.parse(b64utoutf8(t.split(".")[1]));
    } },
  // njwt: verify(token, key, alg) — একটাই alg নেয়; নিরাপদ ব্যবহার = pin allowed_algs[0]
  njwt: { pkg: "njwt", backend: "node:crypto",
    load: (c) => (isH(c) ? secret(c) : c.key.pem),
    verify: (t, k, algs) => require("njwt").verify(t, k, algs[0]).body },
  // node-jose: JWS.createVerify(JWK, { algorithms }).verify(token) — শুধু JWS, exp যাচাই নেই
  "node-jose": { pkg: "node-jose", backend: "node:crypto/forge",
    load: async (c) => require("node-jose").JWK.asKey(c.key.jwk),
    verify: async (t, k, algs) => {
      const r = await require("node-jose").JWS.createVerify(k, { algorithms: algs }).verify(t);
      return JSON.parse(r.payload.toString());
    } },
  // ── reserve (PREREG §2): শুধু কোনো প্রার্থী বাদ পড়লে, এই ক্রমে ──
  // jwt-simple: decode(token, key, noVerify=false, algorithm) — pin allowed_algs[0]
  "jwt-simple": { pkg: "jwt-simple", backend: "node:crypto",
    load: (c) => (isH(c) ? secret(c) : c.key.pem),
    verify: (t, k, algs) => require("jwt-simple").decode(t, k, false, algs[0]) },
  // @tsndr/cloudflare-worker-jwt: verify(token, JWK, { algorithm, throwError }) — pin allowed_algs[0]
  "cloudflare-worker-jwt": { pkg: "@tsndr/cloudflare-worker-jwt", backend: "WebCrypto",
    load: (c) => c.key.jwk,
    verify: async (t, k, algs) => {
      const r = await require("@tsndr/cloudflare-worker-jwt").verify(t, k, { algorithm: algs[0], throwError: true });
      if (!r) throw new Error("verify returned undefined");
      return r.payload;
    } },
};

const err = (e) => `${e?.name ?? "Error"}: ${e?.message ?? e}`.slice(0, 200);

async function runOne(name, cases, out) {
  const I = IMPLS[name];
  const base = { impl: `node/${name}`, version: ver(I.pkg), lang: "node", backend: I.backend };
  const lines = [];
  for (const [i, c] of cases.entries()) {
    const r = { ...base, case: c.id, accepted: false, claims: {}, error: "", stage: "", ns: 0 };
    let k;
    try { k = await I.load(c); } catch (e) { r.stage = "keyload"; r.error = err(e); lines.push(JSON.stringify(r)); continue; }
    const once = async () => {
      const t0 = process.hrtime.bigint();
      try { const cl = await I.verify(c.token, k, c.allowed_algs); return [cl, null, process.hrtime.bigint() - t0]; }
      catch (e) { return [null, e, process.hrtime.bigint() - t0]; }
    };
    let [cl, e, dt] = await once();
    if (i === 0) [cl, e, dt] = await once();              // প্রথম call-এ lazy init — আবার মাপা
    r.ns = Number(dt);
    if (e) { r.stage = "verify"; r.error = err(e); }
    else if (cl && typeof cl === "object" && !Array.isArray(cl)) { r.accepted = true; r.claims = cl; r.stage = "verify"; }
    else { r.stage = "claims"; r.error = `non-object claims: ${typeof cl}`; }
    lines.push(JSON.stringify(r));
  }
  writeFileSync(out, lines.join("\n") + "\n");
}

const [, , casesPath, outdir, ...only] = process.argv;
const cases = JSON.parse(readFileSync(casesPath, "utf8")).cases;
mkdirSync(outdir, { recursive: true });
for (const name of only.length ? only : Object.keys(IMPLS)) {
  await runOne(name, cases, `${outdir}/node__${name}.jsonl`);
  console.error("done", name);
}
