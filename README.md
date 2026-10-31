# Ocnif API3 vulnerability evidence

## Setup / Instalación

This service obtains NVD CVSS evidence through AirnodeHub and verifies the configured Airnode signer, complete request hash and response age. `VulnerabilityGate.sol` uses the signed score to quarantine or release a security work order on-chain. The request hash fixes the operation, CVE and response projection.

Este servicio obtiene evidencia CVSS de NVD mediante AirnodeHub y verifica el firmante configurado, la solicitud completa y la antigüedad. El contrato usa la puntuación firmada para bloquear o liberar una orden de seguridad.

Requires Node.js26.13, npm and Foundry. Install the pinned packages and copy `.env.example` to ignored `.env`. Replace INTERNAL_TOKEN with a private random service token. The defaults record the official NVD Airnode configuration checked on October31,2026; verify the signer with the provider when changing endpoints.

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
forge test
npm start
```

`GET /health` checks the process. Authenticated `GET /v1/vulnerabilities/CVE-2021-44228` requires a Bearer INTERNAL_TOKEN. A signed response is verified before being returned. A priced operation returns HTTP402 and the provider's standard x402 requirements until a caller pays. No wallet key is accepted by this service. `npm run fetch -- CVE-2021-44228` calls the provider using the same verification path.

The authenticated application backend proxies this route for its signed-in user. An explicitly approved browser wallet payment can supply the standard `PAYMENT-SIGNATURE` header; the adapter forwards that exact proof once to the fixed Airnode operation and never creates a payment. It passes through bounded `PAYMENT-REQUIRED` and `PAYMENT-RESPONSE` headers. The paid response still must pass signer, request-hash, freshness and score validation. A payment receipt may accompany HTTP502 when a paid provider response fails validation; retain the receipt and investigate rather than paying again. Never expose the service's INTERNAL_TOKEN to the browser.

Una respuesta HTTP402 significa que falta pagar la operación; no representa evidencia verificada. El servicio nunca recibe claves privadas de billeteras.

## Contract / Contrato

Deploy `contracts/VulnerabilityGate.sol` with the expected Airnode address, the request hash returned by the client, maximum response age in seconds and CVSS threshold in tenths (70 means7.0). Submit the exact response timestamp, UTF-8 data bytes and signature to `submitResponse`. The contract rejects edited data, stale responses, wrong requests, wrong signers, future timestamps, duplicate execution, old updates and out-of-range scores. Deployment requires a funded testnet wallet; the included tests use local synthetic signatures.

The audited source of the reused API3 libraries is recorded with its MIT license and checksums in `contracts/vendor/provenance.json`. A signature authenticates the provider's response, not the underlying claim's truth.

## Containers / Contenedores

Build the Dockerfile from this repository only. `docker-compose.yml` is for local development only; production deployment uses Terraform and Azure Container Apps. The service defaults to port8095 and stores no keys or payment balances. Run `gitleaks dir . --redact` before publishing; the installed pre-commit hook enforces scanning for staged changes.
