import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { configFromEnv } from "./config.ts";
import { getVulnerability } from "./client.ts";

const config = configFromEnv();
const reply = (response: import("node:http").ServerResponse, status: number, body: unknown) => {
  response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  response.end(JSON.stringify(body));
};
const authorized = (value: string | undefined) => {
  const actual = Buffer.from(value ?? "");
  const expected = Buffer.from(`Bearer ${config.token}`);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};
createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health")
    return reply(response, 200, { status: "ok", service: "ocnif-bc-api3" });
  if (!authorized(request.headers.authorization))
    return reply(response, 401, { error: "unauthorized" });
  const match = request.url?.match(/^\/v1\/vulnerabilities\/(CVE-\d{4}-\d{4,})$/);
  if (request.method !== "GET" || !match) return reply(response, 404, { error: "not_found" });
  const proof = request.headers["payment-signature"];
  if (Array.isArray(proof)) return reply(response, 400, { error: "invalid_payment_signature" });
  try {
    const result = await getVulnerability(match[1]!, config, {
      paymentSignature: proof,
      onPaymentHeaders: (headers) => {
        for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
      },
    });
    reply(response, result.status === "payment_required" ? 402 : 200, result);
  } catch (error) {
    reply(response, 502, {
      error:
        error instanceof Error && /^[a-z0-9_]+$/.test(error.message)
          ? error.message
          : "attestation_unavailable",
    });
  }
}).listen(config.port, config.host);
