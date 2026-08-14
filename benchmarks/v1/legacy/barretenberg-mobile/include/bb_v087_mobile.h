#ifndef PROVEKIT_V1_BB_V087_MOBILE_H
#define PROVEKIT_V1_BB_V087_MOBILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bb_v087_status {
    BB_V087_OK = 0,
    BB_V087_INVALID_ARGUMENT = 1,
    BB_V087_IO_ERROR = 2,
    BB_V087_BACKEND_ERROR = 3,
    BB_V087_VERSION_MISMATCH = 4
} bb_v087_status;

typedef struct bb_v087_buffer {
    uint8_t* data;
    size_t len;
} bb_v087_buffer;

typedef struct bb_v087_proof_bundle {
    bb_v087_buffer public_inputs;
    bb_v087_buffer proof;
    bb_v087_buffer verification_key;
} bb_v087_proof_bundle;

/** Returns the immutable backend version compiled into this adapter. */
const char* bb_v087_mobile_version(void);

/**
 * Initializes the global CRS from local files only.
 *
 * The upstream file factory is selected with allow_download=false. The caller
 * owns `error_out` on failure and must release it with bb_v087_free_error.
 */
bb_v087_status bb_v087_init_local_crs(const char* crs_directory, char** error_out);

/**
 * Generates a Poseidon2 UltraHonk proof from beta.11 bytecode and witness files.
 *
 * `output_directory` must be unique to this invocation. The caller owns all
 * buffers in `out` and must release them with bb_v087_free_proof_bundle.
 */
bb_v087_status bb_v087_prove(const char* circuit_path,
                             const char* witness_path,
                             const char* output_directory,
                             bb_v087_proof_bundle* out,
                             char** error_out);

/** Verifies a Poseidon2 UltraHonk proof. A malformed proof is a clean false. */
bb_v087_status bb_v087_verify(const char* public_inputs_path,
                              const char* proof_path,
                              const char* verification_key_path,
                              bool* verified_out,
                              char** error_out);

/** Releases a buffer returned by this adapter and zeroes its fields. */
void bb_v087_free_buffer(bb_v087_buffer* buffer);

/** Releases every owned buffer in a proof bundle and zeroes its fields. */
void bb_v087_free_proof_bundle(bb_v087_proof_bundle* bundle);

/** Releases an error string returned by this adapter. */
void bb_v087_free_error(char* error);

#ifdef __cplusplus
}
#endif

#endif
