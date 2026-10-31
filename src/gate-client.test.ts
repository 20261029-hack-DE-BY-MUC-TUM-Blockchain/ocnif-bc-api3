import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { encodePacked, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  deriveGatePolicy,
  gateArtifact,
  gateDeployment,
  gateSubmission,
  matchesGateRuntime,
} from "../client/index.ts";

test("wallet deployment artifact binds exact policy and runtime bytecode", () => {
  const policy = deriveGatePolicy(
    {
      operation: "getCve",
      parameters: { cveId: "CVE-2021-44228" },
      responseProjection: { score: "/score" },
    },
    { signer: `0x${"11".repeat(20)}`, maximumAge: 600, thresholdTenths: 70 },
  );
  assert.deepEqual(gateDeployment(policy).args, [policy.signer, policy.requestHash, 600n, 70n]);
  assert.equal(
    createHash("sha256")
      .update(Buffer.from(gateArtifact.bytecode.slice(2), "hex"))
      .digest("hex"),
    gateArtifact.bytecodeSha256,
  );
  assert.ok(matchesGateRuntime(gateArtifact.runtimeBytecode as `0x${string}`));
  assert.equal(
    matchesGateRuntime(("0xff" + gateArtifact.runtimeBytecode.slice(4)) as `0x${string}`),
    false,
  );
  assert.throws(() => gateDeployment({ ...policy, thresholdTenths: 101 }));
});
test("wallet submission preserves signed data bytes and rejects stale or altered evidence", async () => {
  const signer = privateKeyToAccount(`0x${"01".padStart(64, "0")}`);
  const policy = deriveGatePolicy(
    { operation: "getCve", parameters: { cveId: "CVE-2021-44228" } },
    { signer: signer.address, maximumAge: 600, thresholdTenths: 70 },
  );
  const evidence = {
    airnode: signer.address,
    requestHash: policy.requestHash,
    timestamp: "1800000000",
    data: '{ "score": 9.8 }',
    signature: "0x" as `0x${string}`,
  };
  evidence.signature = await signer.signMessage({
    message: {
      raw: keccak256(
        encodePacked(
          ["bytes32", "uint256", "bytes"],
          [policy.requestHash, BigInt(evidence.timestamp), toHex(evidence.data)],
        ),
      ),
    },
  });
  const call = await gateSubmission(evidence, policy, 1800000001);
  assert.equal(call.args[1], toHex(evidence.data));
  await assert.rejects(gateSubmission({ ...evidence, data: '{"score":0}' }, policy, 1800000001));
  await assert.rejects(gateSubmission(evidence, policy, 1800000601));
});
