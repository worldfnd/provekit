export class Proof {
  readonly bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  static fromBytes(bytes: Uint8Array | ArrayBuffer | ArrayBufferView): Proof {
    if (bytes instanceof Uint8Array) {
      return new Proof(new Uint8Array(bytes));
    }
    if (bytes instanceof ArrayBuffer) {
      return new Proof(new Uint8Array(bytes));
    }
    return new Proof(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  }

  get size(): number {
    return this.bytes.byteLength;
  }

  json<T = unknown>(): T {
    const text = new TextDecoder().decode(this.bytes);
    return JSON.parse(text) as T;
  }

  text(): string {
    return new TextDecoder().decode(this.bytes);
  }
}
