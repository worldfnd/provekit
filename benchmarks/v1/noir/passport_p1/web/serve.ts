const root = new URL("./dist/", import.meta.url);
Bun.serve({
  hostname: "0.0.0.0",
  port: 4188,
  fetch(request) {
    const url = new URL(request.url);
    const path = new URL(url.pathname === "/" ? "index.html" : url.pathname.slice(1), root);
    return new Response(Bun.file(path), { headers: {
      "Content-Type": path.pathname.endsWith(".wasm") ? "application/wasm" : path.pathname.endsWith(".json") ? "application/json" : "text/javascript",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    }});
  },
});
console.log("http://0.0.0.0:4188/");
