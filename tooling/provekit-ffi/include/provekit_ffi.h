#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // =========================================================================
    // TYPES
    // =========================================================================

    typedef struct PKBuf
    {
        uint8_t *ptr;
        size_t len;
        size_t cap;
    } PKBuf;

    typedef enum
    {
        PK_SUCCESS = 0,
        PK_INVALID_INPUT = 1,
        PK_SCHEME_READ_ERROR = 2,
        PK_WITNESS_READ_ERROR = 3,
        PK_PROOF_ERROR = 4,
        PK_SERIALIZATION_ERROR = 5,
        PK_UTF8_ERROR = 6,
        PK_FILE_WRITE_ERROR = 7,
        PK_VERIFICATION_FAILED = 8,
        PK_VERIFIER_CONSUMED = 9,
        PK_DESERIALIZATION_ERROR = 10,
    } PKError;

    typedef struct ProverHandle ProverHandle;
    typedef struct VerifierHandle VerifierHandle;

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    int pk_init(void);

    // =========================================================================
    // PROVER (Handle-based API)
    // =========================================================================

    ProverHandle *pk_prover_load(
        const uint8_t *data,
        size_t len,
        char **error);

    ProverHandle *pk_prover_load_file(
        const char *path,
        char **error);

    int pk_prover_prove(
        ProverHandle *prover,
        const char *inputs_json,
        uint8_t **proof_out,
        size_t *proof_len,
        char **error);

    void pk_prover_free(ProverHandle *prover);

    // =========================================================================
    // VERIFIER (Handle-based API)
    // =========================================================================

    VerifierHandle *pk_verifier_load(
        const uint8_t *data,
        size_t len,
        char **error);

    VerifierHandle *pk_verifier_load_file(
        const char *path,
        char **error);

    int pk_verifier_verify(
        VerifierHandle *verifier,
        const uint8_t *proof,
        size_t proof_len,
        char **error);

    void pk_verifier_free(VerifierHandle *verifier);

    // =========================================================================
    // PROOF UTILITIES
    // =========================================================================

    int pk_proof_get_public_inputs(
        const uint8_t *proof,
        size_t proof_len,
        char **json_out,
        char **error);

    // =========================================================================
    // MEMORY MANAGEMENT
    // =========================================================================

    void pk_free_buf(PKBuf buf);
    void pk_free_string(char *str);
    void pk_free_bytes(uint8_t *bytes, size_t len);

    // =========================================================================
    // LEGACY FUNCTIONS (for backward compatibility)
    // =========================================================================

    int pk_prove_to_file(const char *prover_path, const char *input_path, const char *out_path);
    int pk_prove_to_json(const char *prover_path, const char *input_path, PKBuf *out_buf);

    void pk_set_allocator(void *(*_Nullable alloc_fn)(size_t size, size_t align),
                          void (*_Nullable dealloc_fn)(void *ptr, size_t size, size_t align));

    int pk_configure_memory(size_t ram_limit_bytes, bool use_file_backed, const char *_Nullable swap_file_path);
    int pk_get_memory_stats(size_t *_Nullable ram_used, size_t *_Nullable swap_used, size_t *_Nullable peak_ram);

#ifdef __cplusplus
}
#endif
