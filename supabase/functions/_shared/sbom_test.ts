import {
  affectedRange,
  deduplicateComponents,
  normalizeCycloneDx,
  normalizeSpdx,
  purlHasVersion,
  severityOf
} from "./sbom.ts";

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
function assertEqual(actual: unknown, expected: unknown, message: string) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  assert(actualJson === expectedJson, message + ": expected " + expectedJson + ", received " + actualJson);
}

Deno.test("CycloneDX normalization includes metadata root and nested components", () => {
  const normalized = normalizeCycloneDx({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    metadata: { component: { name: "firmware-root", version: "1.0.0", purl: "pkg:generic/root@1.0.0" } },
    components: [{
      name: "lib-a", version: "2.1.0", purl: "pkg:npm/lib-a@2.1.0",
      licenses: [{ license: { id: "MIT" } }],
      hashes: [{ alg: "SHA-256", content: "abcd" }],
      components: [{ name: "nested-lib", version: "3.0.0" }]
    }]
  });
  assertEqual(normalized.format, "cyclonedx", "format");
  assertEqual(normalized.specVersion, "1.6", "spec version");
  assertEqual(normalized.components.length, 3, "component count");
  assertEqual(normalized.components[1].license_expression, "MIT", "license expression");
  assertEqual(normalized.components[1].hashes["SHA-256"], "abcd", "component hash");
});

Deno.test("SPDX normalization extracts PURL references and checksums", () => {
  const normalized = normalizeSpdx({
    spdxVersion: "SPDX-2.3",
    packages: [{
      name: "openssl", versionInfo: "3.2.1", licenseDeclared: "Apache-2.0",
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:generic/openssl@3.2.1" }],
      checksums: [{ algorithm: "SHA256", checksumValue: "deadbeef" }]
    }, { versionInfo: "no-name" }]
  });
  assertEqual(normalized.format, "spdx", "format");
  assertEqual(normalized.components.length, 1, "unnamed package skipped");
  assertEqual(normalized.components[0].purl, "pkg:generic/openssl@3.2.1", "PURL");
  assertEqual(normalized.components[0].license_expression, "Apache-2.0", "license");
  assertEqual(normalized.components[0].hashes.SHA256, "deadbeef", "checksum");
});

Deno.test("PURL version detection handles scoped npm packages", () => {
  assert(purlHasVersion("pkg:npm/@scope/name@1.2.3"), "scoped package version should be detected");
  assert(!purlHasVersion("pkg:npm/@scope/name"), "unversioned scoped package should not be detected");
  assert(purlHasVersion("pkg:pypi/demo@2.0.0?source=lockfile"), "version before qualifiers should be detected");
});

Deno.test("component deduplication uses PURL, name and version", () => {
  const rows = normalizeCycloneDx({ components: [
    { name: "a", version: "1", purl: "pkg:npm/a@1" },
    { name: "a", version: "1", purl: "pkg:npm/a@1" },
    { name: "a", version: "2", purl: "pkg:npm/a@2" }
  ] }).components;
  assertEqual(deduplicateComponents(rows).length, 2, "unique component count");
});

Deno.test("severity mapping preserves recognized labels and numeric CVSS scores", () => {
  assertEqual(severityOf({ database_specific: { severity: "CRITICAL" } }), "critical", "critical label");
  assertEqual(severityOf({ severity: [{ score: "8.1" }] }), "high", "numeric score");
  assertEqual(severityOf({ severity: [{ score: "CVSS:3.1/AV:N" }] }), null, "unrecognized vector is not guessed");
});

Deno.test("affected range extracts introduced and fixed events", () => {
  const result = affectedRange({ affected: [{ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.4" }] }] }] });
  assertEqual(result.fixed, "1.2.4", "fixed version");
  assertEqual(result.range, "ECOSYSTEM: introduced 0, fixed 1.2.4", "affected range");
});
