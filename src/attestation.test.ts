import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { encodePacked, keccak256, toHex } from "viem";
import { deriveRequestHash, verifyAttestation } from "./attestation.ts";

const signer = privateKeyToAccount(`0x${"01".padStart(64,"0")}`);
const request = { operation: "getCves", parameters: { cveId: "CVE-2021-44228" }, responseProjection: { score: "/vulnerabilities/0/cve/metrics/cvssMetricV31/0/cvssData/baseScore" } };
const hash = deriveRequestHash(request);
async function evidence() {
  const response = { airnode: signer.address, requestHash: hash, timestamp: "1800000000", data: '{"score":9.8}', signature: "0x" as `0x${string}` };
  response.signature = await signer.signMessage({ message: { raw: keccak256(encodePacked(["bytes32","uint256","bytes"],[hash,BigInt(response.timestamp),toHex(response.data)])) } });
  return response;
}

test("canonical request hash covers parameters and projection independent of key order", () => {
  assert.equal(hash, deriveRequestHash({ responseProjection: request.responseProjection, parameters: request.parameters, operation: request.operation }));
  assert.notEqual(hash, deriveRequestHash({ ...request, parameters: { cveId: "CVE-2024-3094" } }));
});
test("valid signed CVSS response is accepted against pinned signer and exact request", async () => {
  const result = await verifyAttestation(await evidence(), signer.address, hash, 1800000001, 600);
  assert.equal(result.score, 9.8);
});
test("tampered data, wrong request, wrong signer, stale and future data are rejected", async () => {
  const original = await evidence();
  await assert.rejects(verifyAttestation({ ...original, data:'{"score":0}' }, signer.address, hash,1800000001,600));
  await assert.rejects(verifyAttestation({ ...original, requestHash: keccak256(toHex("wrong")) }, signer.address,hash,1800000001,600));
  await assert.rejects(verifyAttestation(original, `0x${"2".repeat(40)}`,hash,1800000001,600));
  await assert.rejects(verifyAttestation(original,signer.address,hash,1800000601,600));
  await assert.rejects(verifyAttestation(original,signer.address,hash,1799999969,600));
});
