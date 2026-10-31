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

## Wallet deployment / Despliegue con billetera

`client/gate-artifact.json` contains the compiled `VulnerabilityGate` ABI, deployment/runtime bytecode, compiler settings, exact source hashes and deployment-bytecode SHA256. It was produced with pinned Solidity0.8.37, optimizer enabled and Cancun EVM target; no library linking is required. `client/index.ts` exports browser-safe helpers with `viem`2.57.3. Vendor the artifact, helper and `src/attestation.ts` together from one immutable commit.

`client/nvd-config.json` is the centrally reviewed public provider configuration. `reviewedNvdConfig` exposes its pinned signer and600-second default; `nvdRequest(cveId)` constructs the exact NVD operation/projection. Compare its derived request hash with both the paid result and its signed evidence. Do not default the expected signer from arbitrary response data.

`deriveGatePolicy(request,{signer,maximumAge,thresholdTenths})` computes the exact canonical request hash. Use the configured official Airnode signer and the same complete request as the paid evidence. The user reviews those values; `maximumAge` is seconds and the CVSS threshold is tenths (`70` means7.0). `gateDeployment(policy)` returns the ABI, bytecode and constructor arguments for wallet deployment. The UI must require Base Sepolia chain84532, estimate gas and show the network fee before asking the connected wallet to deploy. The helper never submits a transaction itself.

After a successful deployment receipt, fetch contract code and require `matchesGateRuntime(code)`. Read `expectedAirnode`, `expectedRequestHash`, `maxResponseAge` and `thresholdTenths` and compare all four with the approved policy; immutable bytes are deliberately excluded from the template code comparison and must be checked through those getters. Save the actual chain, contract address and deployment transaction for this wallet session.

`await gateSubmission(evidence,policy)` revalidates the signed response and returns the `submitResponse(timestamp,data,signature)` call. It preserves the exact UTF-8 `data` bytes and rejects stale or altered evidence. Simulate/estimate this exact call, obtain wallet approval for its fee, then verify the successful transaction receipt, `VulnerabilityDecision` event and the resulting `lastScoreTenths`/`quarantined` state. Replays and out-of-order responses revert. A completed deployment or wallet signature alone is not a verified on-chain decision.

El usuario revisa el firmante, la solicitud CVE, la antigüedad máxima y el umbral antes de desplegar en Base Sepolia. La aplicación estima ambas comisiones, comprueba el código y sus cuatro parámetros, y solo afirma una decisión en cadena después de verificar el recibo y el estado del contrato. No se ha registrado un despliegue real en las pruebas locales de este paquete.

Una respuesta HTTP402 significa que falta pagar la operación; no representa evidencia verificada. El servicio nunca recibe claves privadas de billeteras.

## Contract / Contrato

Deploy `contracts/VulnerabilityGate.sol` with the expected Airnode address, the request hash returned by the client, maximum response age in seconds and CVSS threshold in tenths (70 means7.0). Submit the exact response timestamp, UTF-8 data bytes and signature to `submitResponse`. The contract rejects edited data, stale responses, wrong requests, wrong signers, future timestamps, duplicate execution, old updates and out-of-range scores. Deployment requires a funded testnet wallet; the included tests use local synthetic signatures.

The audited source of the reused API3 libraries is recorded with its MIT license and checksums in `contracts/vendor/provenance.json`. A signature authenticates the provider's response, not the underlying claim's truth.

## Containers / Contenedores

Build the Dockerfile from this repository only. `docker-compose.yml` is for local development only; production deployment uses Terraform and Azure Container Apps. The service defaults to port8095 and stores no keys or payment balances. Run `gitleaks dir . --redact` before publishing; the installed pre-commit hook enforces scanning for staged changes.
