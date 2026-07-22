import { rm } from "node:fs/promises";
import { resolve } from "node:path";

await rm(resolve(import.meta.dirname, "../dist"), { recursive: true, force: true });
