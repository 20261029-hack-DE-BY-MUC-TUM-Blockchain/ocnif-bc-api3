import {
  type Address,
  type Hex,
  encodePacked,
  keccak256,
  recoverMessageAddress,
  toHex,
} from "viem";

export interface AirnodeRequest {
  operation: string;
  parameters: Record<string, unknown>;
  responseProjection?: Record<string, string>;
}
export interface SignedResponse {
  airnode: Address;
  requestHash: Hex;
  timestamp: string;
  data: string;
  signature: Hex;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value === null || typeof value !== "object") return value;
  return Object.entries(value)
    .sort(([a], [b]) => {
      const left = new TextEncoder().encode(a),
        right = new TextEncoder().encode(b);
      for (let i = 0; i < Math.min(left.length, right.length); i++) {
        if (left[i] !== right[i]) return left[i]! - right[i]!;
      }
      return left.length - right.length;
    })
    .map(([key, nested]) => [key, canonical(nested)]);
}
export function deriveRequestHash(request: AirnodeRequest): Hex {
  const tuple = [request.operation, canonical(request.parameters)];
  if (request.responseProjection) tuple.push(canonical(request.responseProjection) as never);
  return keccak256(toHex(JSON.stringify(tuple)));
}

export async function verifyAttestation(
  response: SignedResponse,
  signer: Address,
  requestHash: Hex,
  now: number,
  maxAge: number,
): Promise<{ score: number; evidence: SignedResponse }> {
  if (response.requestHash.toLowerCase() !== requestHash.toLowerCase())
    throw new Error("wrong_request");
  if (!/^\d+$/.test(response.timestamp)) throw new Error("invalid_timestamp");
  const timestamp = Number(response.timestamp);
  if (!Number.isSafeInteger(timestamp) || timestamp > now + 30) throw new Error("future_response");
  if (timestamp < now - maxAge) throw new Error("stale_response");
  const recovered = await recoverMessageAddress({
    message: {
      raw: keccak256(
        encodePacked(
          ["bytes32", "uint256", "bytes"],
          [requestHash, BigInt(response.timestamp), toHex(response.data)],
        ),
      ),
    },
    signature: response.signature,
  });
  if (
    recovered.toLowerCase() !== signer.toLowerCase() ||
    response.airnode.toLowerCase() !== signer.toLowerCase()
  ) {
    throw new Error("wrong_signer_or_tampered_response");
  }
  const data: unknown = JSON.parse(response.data);
  const score = (data as Record<string, unknown>)?.score;
  if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 10)
    throw new Error("invalid_cvss_score");
  return { score, evidence: response };
}
