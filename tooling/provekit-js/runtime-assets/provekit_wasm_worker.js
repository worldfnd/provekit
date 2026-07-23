function waitForMessage(target, type) {
  return new Promise((resolve) => {
    target.addEventListener("message", function onMessage({ data }) {
      if (data?.type !== type) return;
      target.removeEventListener("message", onMessage);
      resolve(data);
    });
  });
}

waitForMessage(self, "wasm_bindgen_worker_init").then(async ({ init, receiver, glueUrl }) => {
  const provekit = await import(/* @vite-ignore */ glueUrl);
  await provekit.default(init);
  postMessage({ type: "wasm_bindgen_worker_ready" });
  provekit.wbg_rayon_start_worker(receiver);
});
