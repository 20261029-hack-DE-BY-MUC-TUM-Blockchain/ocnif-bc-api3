import type { Address } from "viem";

export function configFromEnv(env: NodeJS.ProcessEnv = process.env) {
  const required = (name: string) => { const value = env[name]?.trim(); if (!value) throw new Error(`${name} is required`); return value; };
  const url = new URL(required("AIRNODE_URL"));
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("AIRNODE_URL must be an HTTPS URL without credentials");
  const signer = required("AIRNODE_EXPECTED_SIGNER");
  if (!/^0x[0-9a-fA-F]{40}$/.test(signer)) throw new Error("Invalid AIRNODE_EXPECTED_SIGNER");
  const maxAge = Number(required("AIRNODE_MAX_AGE_SECONDS"));
  const port = Number(required("PORT"));
  const token = required("INTERNAL_TOKEN");
  if (!Number.isInteger(maxAge) || maxAge < 1 || !Number.isInteger(port) || port < 1 || port > 65535 || token.length < 32) throw new Error("Invalid service configuration");
  return { url: url.href, signer: signer as Address, operation: required("AIRNODE_OPERATION"), scorePointer: required("AIRNODE_SCORE_POINTER"), maxAge, port, host: required("HOST"), token };
}
export type Config = ReturnType<typeof configFromEnv>;
