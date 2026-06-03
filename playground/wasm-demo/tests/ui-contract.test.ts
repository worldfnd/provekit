import { describe, expect, it } from "vitest";

import { builtInArtifactId } from "../src/app/artifact-loader";
import { targetsFor } from "../src/app/backend-comparison";
import { deriveStepVisualState } from "../src/app/status-visuals";
import { BUILT_IN_CIRCUITS } from "../src/app/types";
import { classifyUpload, isCustomReady } from "../src/app/upload-rules";

describe("upload rules", () => {
  it("classifies only the accepted custom upload files", () => {
    expect(classifyUpload("prover.pkp")).toBe("prover");
    expect(classifyUpload("verifier.pkv")).toBe("verifier");
    expect(classifyUpload("inputs.json")).toBe("inputs");
    expect(classifyUpload("Prover.toml")).toBe("inputs");
    expect(classifyUpload("witgen.wasm")).toBe("witgenWasm");
    expect(classifyUpload("ad.wasm")).toBe("adWasm");
    expect(classifyUpload("notes.txt")).toBeNull();
  });

  it("requires all three uploads and wasm readiness", () => {
    const mockFile = new File(["content"], "artifact.bin");

    expect(isCustomReady({}, true)).toBe(false);
    expect(isCustomReady({ prover: mockFile, verifier: mockFile, inputs: mockFile }, false)).toBe(false);
    expect(isCustomReady({ prover: mockFile, verifier: mockFile, inputs: mockFile }, true)).toBe(true);
  });
});

describe("built-in circuit names", () => {
  it("includes passkey and WebAuthn as first-class non-custom circuits", () => {
    expect(BUILT_IN_CIRCUITS).toEqual(["passkey", "webauthn"]);
  });

  it("routes built-in proving to patched-branch Mavros artifacts", () => {
    expect(builtInArtifactId("passkey")).toBe("passkey-mavros");
    expect(builtInArtifactId("webauthn")).toBe("webauthn-mavros");
  });
});

describe("backend comparison targets", () => {
  it("compares patched Mavros against distinct v1 Verity WASM artifacts", () => {
    expect(targetsFor("passkey")).toEqual([
      {
        backend: "mavros",
        label: "Mavros main",
        artifactId: "passkey-mavros",
      },
      {
        backend: "verity-v1",
        label: "ProveKit v1 ACIR (Verity WASM)",
        artifactId: "passkey-v1",
      },
    ]);

    expect(targetsFor("webauthn").map(({ artifactId }) => artifactId)).toEqual([
      "webauthn-mavros",
      "webauthn-v1",
    ]);
  });
});

describe("step visual state", () => {
  it("maps waiting, running, success, and failure text to the current UI contract", () => {
    expect(deriveStepVisualState("idle")).toEqual({
      containerClassName: "step-item",
      iconClassName: "step-icon",
      iconKind: "number",
      statusClassName: "step-status",
    });

    expect(deriveStepVisualState("running")).toEqual({
      containerClassName: "step-item active",
      iconClassName: "step-icon active",
      iconKind: "spinner",
      statusClassName: "step-status",
    });

    expect(deriveStepVisualState("success")).toEqual({
      containerClassName: "step-item success",
      iconClassName: "step-icon success",
      iconKind: "check",
      statusClassName: "step-status success-text",
    });

    expect(deriveStepVisualState("error")).toEqual({
      containerClassName: "step-item error",
      iconClassName: "step-icon error",
      iconKind: "cross",
      statusClassName: "step-status error-text",
    });
  });
});
