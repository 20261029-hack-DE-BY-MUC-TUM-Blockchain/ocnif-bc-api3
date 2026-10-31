import test from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount } from "viem/accounts";
import { encodePacked, keccak256, toHex } from "viem";
import { getVulnerability } from "./client.ts";
import { deriveRequestHash } from "./attestation.ts";
import type { Config } from "./config.ts";

const signer = privateKeyToAccount(`0x${"01".padStart(64, "0")}`);
const config: Config = {
  url: "https://airnode.example/",
  signer: signer.address,
  operation: "getCve",
  scorePointer: "/score",
  maxAge: 600,
  host: "127.0.0.1",
  port: 8095,
  token: "test-only-local-token-with-32-characters",
};
test("payment headers are forwarded once while every paid response still requires the pinned attestation", async () => {
  const request = {
    operation: config.operation,
    parameters: { cveId: "CVE-2021-44228" },
    responseProjection: { score: config.scorePointer },
  };
  const hash = deriveRequestHash(request);
  const body = {
    airnode: signer.address,
    requestHash: hash,
    timestamp: String(Math.floor(Date.now() / 1000)),
    data: '{"score":9.8}',
    signature: "0x",
  };
  body.signature = await signer.signMessage({
    message: {
      raw: keccak256(
        encodePacked(
          ["bytes32", "uint256", "bytes"],
          [hash, BigInt(body.timestamp), toHex(body.data)],
        ),
      ),
    },
  });
  let calls = 0;
  let tamper = false;
  let forwarded: Record<string, string> = {};
  const fetcher: typeof fetch = async (_url, options) => {
    calls++;
    assert.equal(new Headers(options?.headers).get("PAYMENT-SIGNATURE"), "c2lnbmVk");
    assert.deepEqual(JSON.parse(String(options?.body)), request);
    return new Response(JSON.stringify({ ...body, ...(tamper ? { data: '{"score":0}' } : {}) }), {
      headers: { "PAYMENT-RESPONSE": "cmVjZWlwdA==" },
    });
  };
  const result = await getVulnerability("CVE-2021-44228", config, {
    fetcher,
    paymentSignature: "c2lnbmVk",
    onPaymentHeaders: (h) => {
      forwarded = h;
    },
  });
  assert.equal(result.verified, true);
  assert.equal(calls, 1);
  assert.equal(forwarded["PAYMENT-RESPONSE"], "cmVjZWlwdA==");
  tamper = true;
  await assert.rejects(
    getVulnerability("CVE-2021-44228", config, { fetcher, paymentSignature: "c2lnbmVk" }),
    /wrong_signer_or_tampered/,
  );
  await assert.rejects(
    getVulnerability("CVE-2021-44228", config, { fetcher, paymentSignature: "bad\r\nheader" }),
    /invalid_payment_signature/,
  );
  assert.equal(calls, 2);
});
test("unpaid challenge remains unverified and never triggers a payment attempt", async () => {
  let calls = 0;
  const result = await getVulnerability("CVE-2021-44228", config, {
    fetcher: async () => {
      calls++;
      return new Response(null, { status: 402, headers: { "PAYMENT-REQUIRED": "Y2hhbGxlbmdl" } });
    },
  });
  assert.equal(result.status, "payment_required");
  assert.equal(result.verified, false);
  assert.equal(calls, 1);
});
