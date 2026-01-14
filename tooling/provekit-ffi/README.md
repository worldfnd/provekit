# ProveKit FFI

This crate provides C-compatible FFI bindings for ProveKit, enabling integration with multiple programming languages and platforms including mobile (iOS, Android), desktop, web, and embedded systems.

## Features

- **C ABI Compatibility**: All functions use C-compatible types and calling conventions
- **Memory Management**: Safe buffer management with explicit allocation/deallocation
- **Multiple Output Formats**: Support for binary, JSON, and file outputs
- **Error Handling**: Comprehensive error codes and messages
- **Cross-Platform**: Can be compiled as a static library for mobile, desktop, and embedded platforms

## Building

### For Development (Host Platform)
```bash
cargo build --release -p provekit-ffi
```

### For Mobile Platforms

#### iOS
```bash
# Install iOS targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build for device (ARM64)
cargo build --release --target aarch64-apple-ios -p provekit-ffi

# Build for simulator (ARM64)
cargo build --release --target aarch64-apple-ios-sim -p provekit-ffi

# Build for simulator (x86_64, Intel Macs)
cargo build --release --target x86_64-apple-ios -p provekit-ffi
```

#### Android
```bash
# Install Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Build for ARM64
cargo build --release --target aarch64-linux-android -p provekit-ffi

# Build for ARM32
cargo build --release --target armv7-linux-androideabi -p provekit-ffi

# Build for x86_64
cargo build --release --target x86_64-linux-android -p provekit-ffi
```

### Create Platform-Specific Packages

#### iOS XCFramework
```bash
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libprovekit_ffi.a -headers tooling/provekit-ffi/include \
  -library target/aarch64-apple-ios-sim/release/libprovekit_ffi.a -headers tooling/provekit-ffi/include \
  -library target/x86_64-apple-ios/release/libprovekit_ffi.a -headers tooling/provekit-ffi/include \
  -output ProvekitFFI.xcframework
```

#### Android AAR (requires additional setup)
```bash
# Copy libraries to Android project structure
mkdir -p android/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}
cp target/aarch64-linux-android/release/libprovekit_ffi.a android/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libprovekit_ffi.a android/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libprovekit_ffi.a android/src/main/jniLibs/x86_64/
```

## Usage

### C/C++
```c
#include "provekit_ffi.h"

int main() {
    // Initialize the library
    if (pk_init() != PK_SUCCESS) {
        return 1;
    }
    
    // Option 1: Prove and write to file
    int result = pk_prove_to_file(
        "/path/to/scheme.pkp",
        "/path/to/input.toml",
        "/path/to/output.np"
    );
    
    if (result == PK_SUCCESS) {
        printf("Proof written to file successfully\n");
    }
    
    // Option 2: Prove and get JSON in memory
    PKBuf proof_buf;
    result = pk_prove_to_json(
        "/path/to/scheme.pkp",
        "/path/to/input.toml", 
        &proof_buf
    );
    
    if (result == PK_SUCCESS) {
        // Use proof_buf.ptr and proof_buf.len as JSON string
        printf("JSON proof generated: %zu bytes\n", proof_buf.len);
        printf("Proof JSON: %.*s\n", (int)proof_buf.len, proof_buf.ptr);
        
        // Free the buffer
        pk_free_buf(proof_buf);
    }
    
    return 0;
}
```

### Swift
```swift
import Foundation
import ProvekitFFI

// Initialize ProveKit
guard pk_init() == PK_SUCCESS else {
    fatalError("Failed to initialize ProveKit")
}

// Option 1: Prove and write to file
let fileResult = pk_prove_to_file(
    proverPath,
    inputPath,
    outputPath
)

guard fileResult == PK_SUCCESS else {
    fatalError("File proving failed with error: \(fileResult)")
}

// Option 2: Prove and get JSON in memory
var proofBuf = PKBuf(ptr: nil, len: 0)
let jsonResult = pk_prove_to_json(
    proverPath,
    inputPath,
    &proofBuf
)

guard jsonResult == PK_SUCCESS else {
    fatalError("JSON proving failed with error: \(jsonResult)")
}

// Convert to Swift String (JSON)
let jsonString = String(
    bytesNoCopy: proofBuf.ptr,
    length: proofBuf.len,
    encoding: .utf8,
    freeWhenDone: false
)

print("Proof JSON: \(jsonString ?? "Invalid UTF-8")")

// Free the buffer
pk_free_buf(proofBuf)
```

### Kotlin (Android)
```kotlin
// Load the native library
System.loadLibrary("provekit_ffi")

// Initialize ProveKit
if (pk_init() != PK_SUCCESS) {
    throw RuntimeException("Failed to initialize ProveKit")
}

// Option 1: Prove and write to file
val fileResult = pk_prove_to_file(
    proverPath,
    inputPath,
    outputPath
)

if (fileResult != PK_SUCCESS) {
    throw RuntimeException("File proving failed with error: $fileResult")
}

// Option 2: Prove and get JSON in memory
val proofBuf = PKBuf()
val jsonResult = pk_prove_to_json(
    proverPath,
    inputPath,
    proofBuf
)

if (jsonResult != PK_SUCCESS) {
    throw RuntimeException("JSON proving failed with error: $jsonResult")
}

// Convert to String (JSON)
val jsonBytes = ByteArray(proofBuf.len.toInt())
// Copy memory from native buffer to Java byte array
// (implementation depends on JNI wrapper)
val jsonString = String(jsonBytes, Charsets.UTF_8)
println("Proof JSON: $jsonString")

// Free the buffer
pk_free_buf(proofBuf)
```

### Python (via ctypes)
```python
import ctypes
from ctypes import Structure, c_char_p, c_int, c_size_t, POINTER

# Load the library
lib = ctypes.CDLL('./libprovekit_ffi.so')  # or .dylib on macOS, .dll on Windows

# Define structures
class PKBuf(Structure):
    _fields_ = [("ptr", POINTER(ctypes.c_uint8)), ("len", c_size_t)]

# Define function signatures
lib.pk_init.restype = c_int
lib.pk_prove_to_file.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pk_prove_to_file.restype = c_int
lib.pk_prove_to_json.argtypes = [c_char_p, c_char_p, POINTER(PKBuf)]
lib.pk_prove_to_json.restype = c_int
lib.pk_free_buf.argtypes = [PKBuf]

# Initialize ProveKit
if lib.pk_init() != 0:  # PK_SUCCESS = 0
    raise RuntimeError("Failed to initialize ProveKit")

# Option 1: Prove and write to file
file_result = lib.pk_prove_to_file(
    prover_path.encode('utf-8'),
    input_path.encode('utf-8'),
    output_path.encode('utf-8')
)

if file_result != 0:
    raise RuntimeError(f"File proving failed with error: {file_result}")

# Option 2: Prove and get JSON in memory
proof_buf = PKBuf()
json_result = lib.pk_prove_to_json(
    prover_path.encode('utf-8'),
    input_path.encode('utf-8'),
    ctypes.byref(proof_buf)
)

if json_result != 0:
    raise RuntimeError(f"JSON proving failed with error: {json_result}")

# Convert to string (JSON)
json_bytes = ctypes.string_at(proof_buf.ptr, proof_buf.len)
json_string = json_bytes.decode('utf-8')
print(f"Proof JSON: {json_string}")

# Free the buffer
lib.pk_free_buf(proof_buf)
```

## API Reference

### Functions

- `pk_init()` - Initialize the library (call once)
- `pk_prove_to_file()` - Generate proof and write to file
- `pk_prove_to_json()` - Generate proof and return as JSON string in memory buffer
- `pk_free_buf()` - Free buffers returned by ProveKit functions
- `pk_set_allocator()` - Set custom allocator functions for memory management (optional)

### Error Codes

- `PK_SUCCESS` (0) - Operation successful
- `PK_INVALID_INPUT` (1) - Invalid input parameters
- `PK_SCHEME_READ_ERROR` (2) - Failed to read scheme file
- `PK_WITNESS_READ_ERROR` (3) - Failed to read witness/input file
- `PK_PROOF_ERROR` (4) - Failed to generate proof
- `PK_SERIALIZATION_ERROR` (5) - Failed to serialize output
- `PK_UTF8_ERROR` (6) - UTF-8 conversion error
- `PK_FILE_WRITE_ERROR` (7) - File write error

## File Formats

### Input Files
- **Prover files**: `.pkp` (binary) or `.json` (JSON format) - prepared proof scheme
- **Witness files**: `.toml` (TOML format with input values)

### Output Files
- **Proof files**: `.np` (binary) or `.json` (JSON format)

## Memory Management

All buffers returned by ProveKit functions must be freed using `pk_free_buf()`. Failure to do so will result in memory leaks.

### Custom Allocator

By default, ProveKit uses the system allocator. To use a custom allocator (e.g., for iOS memory tracking), call `pk_set_allocator()` before any other ProveKit functions:

```c
void* my_alloc(size_t size, size_t align) {
    // Custom allocation logic
}

void my_dealloc(void* ptr, size_t size, size_t align) {
    // Custom deallocation logic
}

// Set custom allocator (call once, before pk_init)
pk_set_allocator(my_alloc, my_dealloc);
```

If `pk_set_allocator()` is not called, the system allocator is used.

## Thread Safety

The FFI functions are not guaranteed to be thread-safe. If you need to call ProveKit functions from multiple threads, ensure proper synchronization.


