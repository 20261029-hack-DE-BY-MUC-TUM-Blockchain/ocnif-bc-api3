import { isAddress, toHex, type Abi, type Address, type Hex } from "viem";
import {
  deriveRequestHash,
  verifyAttestation,
  type AirnodeRequest,
  type SignedResponse,
} from "../src/attestation.ts";
import artifact from "./gate-artifact.json" with { type: "json" };
import nvdConfig from "./nvd-config.json" with { type: "json" };
export { deriveRequestHash, verifyAttestation };
export type { AirnodeRequest, SignedResponse };
export const gateArtifact = artifact;
export const gateAbi = artifact.abi as Abi;
export const deploymentChainId = 84532;
export const reviewedNvdConfig = nvdConfig;
export function nvdRequest(cveId: string): AirnodeRequest {
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) throw new Error("invalid_cve_id");
  return {
    operation: nvdConfig.operation,
    parameters: { cveId },
    responseProjection: { score: nvdConfig.scorePointer },
  };
}
export interface GatePolicy {
  signer: Address;
  requestHash: Hex;
  maximumAge: number;
  thresholdTenths: number;
}

function validatePolicy(policy: GatePolicy): void {
  if (
    !isAddress(policy.signer) ||
    /^0x0{40}$/i.test(policy.signer) ||
    !/^0x[0-9a-f]{64}$/i.test(policy.requestHash) ||
    /^0x0{64}$/i.test(policy.requestHash)
  )
    throw new Error("invalid_gate_identity");
  if (
    !Number.isSafeInteger(policy.maximumAge) ||
    policy.maximumAge < 1 ||
    !Number.isSafeInteger(policy.thresholdTenths) ||
    policy.thresholdTenths < 0 ||
    policy.thresholdTenths > 100
  )
    throw new Error("invalid_gate_policy");
}
export function deriveGatePolicy(
  request: AirnodeRequest,
  policy: Omit<GatePolicy, "requestHash">,
): GatePolicy {
  const result = { ...policy, requestHash: deriveRequestHash(request) };
  validatePolicy(result);
  return result;
}
export function gateDeployment(policy: GatePolicy) {
  validatePolicy(policy);
  return {
    abi: gateAbi,
    bytecode: artifact.bytecode as Hex,
    args: [
      policy.signer,
      policy.requestHash,
      BigInt(policy.maximumAge),
      BigInt(policy.thresholdTenths),
    ] as const,
  };
}
export async function gateSubmission(
  evidence: SignedResponse,
  policy: GatePolicy,
  now = Math.floor(Date.now() / 1000),
) {
  validatePolicy(policy);
  await verifyAttestation(evidence, policy.signer, policy.requestHash, now, policy.maximumAge);
  return {
    abi: gateAbi,
    functionName: "submitResponse" as const,
    args: [BigInt(evidence.timestamp), toHex(evidence.data), evidence.signature] as const,
  };
}
/** Pair this byte-for-byte code check with the four immutable getter checks. */
export function matchesGateRuntime(code: Hex): boolean {
  const expected = artifact.runtimeBytecode.toLowerCase();
  let actual = code.toLowerCase();
  if (!/^0x[0-9a-f]+$/.test(actual) || actual.length !== expected.length) return false;
  for (const locations of Object.values(artifact.immutableReferences))
    for (const { start, length } of locations) {
      const offset = 2 + start * 2;
      actual = actual.slice(0, offset) + "0".repeat(length * 2) + actual.slice(offset + length * 2);
    }
  return actual === expected;
}
