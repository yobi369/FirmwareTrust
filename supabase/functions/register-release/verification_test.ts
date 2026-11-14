import { assert, assertEquals, assertNotEquals } from "jsr:@std/assert@1";
import { canonical, verifyEd25519Manifest } from "./verification.ts";

function pemFromDer(der: ArrayBuffer): string {
  const bytes = new Uint8Array(der);
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  const base64 = btoa(binary).match(/.{1,64}/g)?.join("\n") ?? "";
  return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
}

async function signedFixture() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicDer = await crypto.subtle.exportKey("spki", pair.publicKey);
  const manifest: Record<string, unknown> = {
    artifact: { filename: "controller.bin", digest_algorithm: "sha256", digest: "a".repeat(64), size_bytes: 1024 },
    trust_registry: {
      provider: "firmwaretrust",
      organization_id: "f1000000-0000-4000-8000-000000000001",
      project_id: "f2000000-0000-4000-8000-000000000001",
    },
    signature: { algorithm: "Ed25519", key_id: "0123456789abcdef", value: "" },
  };
  const payload = JSON.parse(JSON.stringify(manifest)) as Record<string, unknown>;
  delete (payload.signature as Record<string, unknown>).value;
  const bytes = new TextEncoder().encode(canonical(payload));
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, bytes);
  (manifest.signature as Record<string, unknown>).value = btoa(Array.from(new Uint8Array(signature), (byte) => String.fromCharCode(byte)).join(""));
  return { manifest, publicKeyPem: pemFromDer(publicDer) };
}

Deno.test("valid Ed25519 manifest produces stable verification digests", async () => {
  const fixture = await signedFixture();
  const result = await verifyEd25519Manifest(fixture.manifest, fixture.publicKeyPem);
  assertEquals(result.valid, true);
  assertEquals(result.manifestSha256.length, 64);
  assertEquals(result.signatureSha256.length, 64);
  assertNotEquals(result.manifestSha256, result.signatureSha256);
});

Deno.test("tampered manifest payload fails Ed25519 verification", async () => {
  const fixture = await signedFixture();
  (fixture.manifest.artifact as Record<string, unknown>).digest = "b".repeat(64);
  const result = await verifyEd25519Manifest(fixture.manifest, fixture.publicKeyPem);
  assertEquals(result.valid, false);
});

Deno.test("tampered signature bytes fail Ed25519 verification", async () => {
  const fixture = await signedFixture();
  const signature = fixture.manifest.signature as Record<string, unknown>;
  const bytes = Uint8Array.from(atob(String(signature.value)), (character) => character.charCodeAt(0));
  bytes[0] ^= 0xff;
  signature.value = btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));
  const result = await verifyEd25519Manifest(fixture.manifest, fixture.publicKeyPem);
  assertEquals(result.valid, false);
});

Deno.test("malformed Ed25519 signature is rejected", async () => {
  const fixture = await signedFixture();
  (fixture.manifest.signature as Record<string, unknown>).value = btoa("short");
  let threw = false;
  try { await verifyEd25519Manifest(fixture.manifest, fixture.publicKeyPem); } catch { threw = true; }
  assert(threw);
});
