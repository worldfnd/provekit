import { resolve, sep } from "node:path";

const root = resolve(new URL("../dist", import.meta.url).pathname);
const port = Number.parseInt(process.env.PROVEKIT_BENCH_PORT ?? "4173", 10);

const mimeTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".pkp": "application/octet-stream",
  ".pkv": "application/octet-stream",
  ".wasm": "application/wasm",
};

function contentType(path: string): string {
  const extension = path.slice(path.lastIndexOf("."));
  return mimeTypes[extension] ?? "application/octet-stream";
}

export function startServer() {
  return Bun.serve({
    hostname: "127.0.0.1",
    port,
    async fetch(request) {
      const url = new URL(request.url);
      const relativePath = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
      const path = resolve(root, `.${relativePath}`);
      if (path !== root && !path.startsWith(`${root}${sep}`)) {
        return new Response("not found", { status: 404 });
      }
      const file = Bun.file(path);
      if (!(await file.exists())) return new Response("not found", { status: 404 });
      return new Response(file, {
        headers: {
          "Cache-Control": "no-store",
          "Content-Type": contentType(path),
          "Cross-Origin-Embedder-Policy": "require-corp",
          "Cross-Origin-Opener-Policy": "same-origin",
        },
      });
    },
  });
}

if (import.meta.main) {
  const server = startServer();
  console.log(`ProveKit V1 browser benchmark: ${server.url}`);
}
