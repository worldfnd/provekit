import js from "@eslint/js";
import tseslint from "typescript-eslint";

const browserGlobals = {
  console: "readonly",
  document: "readonly",
  fetch: "readonly",
  File: "readonly",
  HTMLElement: "readonly",
  HTMLButtonElement: "readonly",
  HTMLInputElement: "readonly",
  navigator: "readonly",
  performance: "readonly",
  setTimeout: "readonly",
  TextDecoder: "readonly",
  window: "readonly",
};

export default tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts", "tests/**/*.ts", "vitest.config.ts"],
    languageOptions: {
      globals: browserGlobals,
      parserOptions: {
        project: false,
      },
    },
    rules: {
      "no-console": "off",
    },
  },
  {
    ignores: ["dist/**", "node_modules/**"],
  },
);
