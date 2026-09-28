// Independent verification of docs/test-vectors.json using only Node.js built-ins.
// Usage: node tests/interop/verify_vectors.mjs docs/test-vectors.json
// Prints "ok <n> checks" and exits 0, or prints the first failure and exits 1.
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";

// RFC 8785 JSON Canonicalization Scheme, written from the RFC (not ported from the Python code):
// JSON.stringify already produces ECMAScript number and string serialisation; object members are
// sorted by UTF-16 code units, which is what Array.prototype.sort does for strings.
function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]))
      .join(",") +
    "}"
  );
}

function withoutKeys(doc, keys) {
  const copy = { ...doc };
  for (const k of keys) delete copy[k];
  return copy;
}

function ed25519Verify(publicKeyHex, message, signatureHex) {
  const key = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKeyHex, "hex").toString("base64url") },
    format: "jwk",
  });
  return verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signatureHex, "hex"));
}

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
let checks = 0;
function expect(condition, label) {
  checks += 1;
  if (!condition) {
    console.error("FAIL:", label);
    process.exit(1);
  }
}

for (const [i, c] of vectors.jcs.entries()) {
  expect(canonicalize(c.input) === c.canonical, `jcs case ${i}`);
}

for (const name of ["manifest", "rotated_manifest", "request", "reply"]) {
  const v = vectors[name];
  const payload = canonicalize(withoutKeys(v.document, ["signature"]));
  expect(payload === v.signing_payload, `${name} signing payload`);
  const signer = name === "request" ? vectors.keys.agent.public_key : vectors.keys.domain.public_key;
  expect(ed25519Verify(signer, payload, v.signature), `${name} signature`);
  expect(!ed25519Verify(signer, payload + " ", v.signature), `${name} tamper detection`);
}

const rotated = vectors.rotated_manifest;
const endorsementPayload = canonicalize(withoutKeys(rotated.document, ["signature", "key_endorsements"]));
expect(endorsementPayload === rotated.endorsement_payload, "endorsement payload");
const previous = vectors.keys.previous_domain_key.public_key;
expect(ed25519Verify(previous, endorsementPayload, rotated.document.key_endorsements[previous]), "endorsement");

const pow = vectors.proof_of_work;
const digest = createHash("sha256").update(pow.seed + pow.nonce, "utf8").digest("hex");
expect(digest === pow.digest, "proof-of-work digest");
expect(digest.startsWith("0".repeat(pow.difficulty)), "proof-of-work difficulty");

console.log(`ok ${checks} checks`);
