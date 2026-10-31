import { configFromEnv } from "./config.ts";
import { getVulnerability } from "./client.ts";
const id=process.argv[2];
if(!id) throw new Error("Pass a CVE identifier after --");
console.log(JSON.stringify(await getVulnerability(id,configFromEnv()),null,2));
