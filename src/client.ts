import { deriveRequestHash, verifyAttestation, type SignedResponse } from "./attestation.ts";
import type { Config } from "./config.ts";

export async function getVulnerability(cveId: string, config: Config, fetcher: typeof fetch = fetch) {
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) throw new Error("invalid_cve_id");
  const request = { operation: config.operation, parameters: { cveId }, responseProjection: { score: config.scorePointer } };
  const requestHash = deriveRequestHash(request);
  const response = await fetcher(config.url, { method: "POST", headers: { "Content-Type":"application/json", "User-Agent":"Ocnif/0.1" }, body:JSON.stringify(request), signal:AbortSignal.timeout(20_000) });
  if (response.status === 402) return { status:"payment_required" as const, cveId, request, requestHash,
    paymentRequired:response.headers.get("PAYMENT-REQUIRED"), provider:config.url, verified:false };
  if (!response.ok) throw new Error(`airnode_http_${response.status}`);
  const body = await response.text();
  if (body.length > 65_536) throw new Error("airnode_response_too_large");
  const evidence = JSON.parse(body) as SignedResponse;
  const verified = await verifyAttestation(evidence,config.signer,requestHash,Math.floor(Date.now()/1000),config.maxAge);
  return { status:"verified" as const, cveId, request, requestHash, ...verified, verified:true };
}
