import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: false,
    rollupOptions: {
      input: {
        runner: "src/runner.ts",
        worker: "src/worker.ts",
      },
      output: {
        entryFileNames: "[name].js",
      },
    },
  },
  worker: {
    format: "es",
  },
});
