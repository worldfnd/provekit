#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /// Buffer structure for returning data from ProveKit functions.
    /// The caller is responsible for freeing buffers using pk_free_buf.
    typedef struct
    {
        /// Pointer to the data
        uint8_t *ptr;
        /// Length of the data in bytes
        size_t len;
        /// Capacity of the allocation (required for proper deallocation)
        size_t cap;
    } PKBuf;

    /// Status codes returned by ProveKit functions
    typedef enum
    {
        /// Success
        PK_SUCCESS = 0,
        /// Invalid input parameters (null pointers, etc.)
        PK_INVALID_INPUT = 1,
        /// Failed to read scheme file
        PK_SCHEME_READ_ERROR = 2,
        /// Failed to read witness/input file
        PK_WITNESS_READ_ERROR = 3,
        /// Failed to generate or verify proof
        PK_PROOF_ERROR = 4,
        /// Failed to serialize output
        PK_SERIALIZATION_ERROR = 5,
        /// UTF-8 conversion error
        PK_UTF8_ERROR = 6,
        /// File write error
        PK_FILE_WRITE_ERROR = 7,
        /// Circuit compilation error
        PK_COMPILATION_ERROR = 8,
    } PKStatus;

    /// Opaque handle to a compiled prover scheme.
    typedef struct PKProver PKProver;

    /// Opaque handle to a compiled verifier scheme.
    typedef struct PKVerifier PKVerifier;

    // -----------------------------------------------------------------------
    // Initialization & memory
    // -----------------------------------------------------------------------

    /// Initialize the ProveKit library.
    /// Must be called once before using any other ProveKit functions.
    ///
    /// @return PK_SUCCESS on success
    int pk_init(void);

    /// Configure the mmap-based memory allocator (MUST be called before pk_init).
    ///
    /// @param ram_limit_bytes Maximum RAM before using swap (must be > 0)
    /// @param use_file_backed Whether to use file-backed mmap for swap
    /// @param swap_file_path Directory for swap files (NULL = system temp)
    /// @return PK_SUCCESS or PK_INVALID_INPUT
    int pk_configure_memory(size_t ram_limit_bytes, bool use_file_backed,
                            const char *_Nullable swap_file_path);

    /// Get current memory statistics.
    ///
    /// @param ram_used Output pointer for current RAM usage (can be NULL)
    /// @param swap_used Output pointer for current swap usage (can be NULL)
    /// @param peak_ram Output pointer for peak RAM usage (can be NULL)
    /// @return PK_SUCCESS
    int pk_get_memory_stats(size_t *_Nullable ram_used, size_t *_Nullable swap_used,
                            size_t *_Nullable peak_ram);

    /// Get the error message from the most recent failing FFI call.
    /// Returns the message as UTF-8 bytes in out_buf. The error is cleared
    /// after this call.
    ///
    /// @param out_buf Output buffer (must be freed with pk_free_buf)
    /// @return PK_SUCCESS
    int pk_get_last_error(PKBuf *out_buf);

    // -----------------------------------------------------------------------
    // Prepare (compile circuit)
    // -----------------------------------------------------------------------

    /// Compile a Noir circuit into prover and verifier handles.
    ///
    /// @param circuit_path Path to the Noir circuit JSON file
    /// @param out_prover Output prover handle (must be freed with pk_free_prover)
    /// @param out_verifier Output verifier handle (must be freed with pk_free_verifier)
    /// @return PK_SUCCESS or error code
    int pk_prepare(const char *circuit_path,
                   PKProver **out_prover, PKVerifier **out_verifier);

    // -----------------------------------------------------------------------
    // Load from file
    // -----------------------------------------------------------------------

    /// Load a prover scheme from a .pkp file.
    ///
    /// @param path Path to the .pkp file
    /// @param out Output prover handle (must be freed with pk_free_prover)
    /// @return PK_SUCCESS or error code
    int pk_load_prover(const char *path, PKProver **out);

    /// Load a verifier scheme from a .pkv file.
    ///
    /// @param path Path to the .pkv file
    /// @param out Output verifier handle (must be freed with pk_free_verifier)
    /// @return PK_SUCCESS or error code
    int pk_load_verifier(const char *path, PKVerifier **out);

    // -----------------------------------------------------------------------
    // Load from bytes
    // -----------------------------------------------------------------------

    /// Load a prover scheme from bytes (same format as .pkp files).
    ///
    /// @param ptr Pointer to the byte data
    /// @param len Length of the byte data
    /// @param out Output prover handle (must be freed with pk_free_prover)
    /// @return PK_SUCCESS or error code
    int pk_load_prover_bytes(const uint8_t *ptr, size_t len, PKProver **out);

    /// Load a verifier scheme from bytes (same format as .pkv files).
    ///
    /// @param ptr Pointer to the byte data
    /// @param len Length of the byte data
    /// @param out Output verifier handle (must be freed with pk_free_verifier)
    /// @return PK_SUCCESS or error code
    int pk_load_verifier_bytes(const uint8_t *ptr, size_t len, PKVerifier **out);

    // -----------------------------------------------------------------------
    // Save to file
    // -----------------------------------------------------------------------

    /// Save a prover scheme to a .pkp file.
    ///
    /// @param prover Valid prover handle
    /// @param path Output file path (must end in .pkp)
    /// @return PK_SUCCESS or error code
    int pk_save_prover(const PKProver *prover, const char *path);

    /// Save a verifier scheme to a .pkv file.
    ///
    /// @param verifier Valid verifier handle
    /// @param path Output file path (must end in .pkv)
    /// @return PK_SUCCESS or error code
    int pk_save_verifier(const PKVerifier *verifier, const char *path);

    // -----------------------------------------------------------------------
    // Serialize to bytes
    // -----------------------------------------------------------------------

    /// Serialize a prover scheme to bytes (same format as .pkp files).
    ///
    /// @param prover Valid prover handle
    /// @param out_buf Output buffer (must be freed with pk_free_buf)
    /// @return PK_SUCCESS or error code
    int pk_serialize_prover(const PKProver *prover, PKBuf *out_buf);

    /// Serialize a verifier scheme to bytes (same format as .pkv files).
    ///
    /// @param verifier Valid verifier handle
    /// @param out_buf Output buffer (must be freed with pk_free_buf)
    /// @return PK_SUCCESS or error code
    int pk_serialize_verifier(const PKVerifier *verifier, PKBuf *out_buf);

    // -----------------------------------------------------------------------
    // Prove
    // -----------------------------------------------------------------------

    /// Prove using a prover handle and a TOML input file.
    ///
    /// @param prover Valid prover handle
    /// @param toml_path Path to the witness/input TOML file
    /// @param out_proof Output proof bytes in .np format (must be freed with pk_free_buf)
    /// @return PK_SUCCESS or error code
    int pk_prove_toml(const PKProver *prover, const char *toml_path, PKBuf *out_proof);

    /// Prove using a prover handle and a JSON string of inputs.
    /// Example JSON: {"x": "5", "y": "10"}
    ///
    /// @param prover Valid prover handle
    /// @param inputs_json JSON string matching the circuit ABI
    /// @param out_proof Output proof bytes in .np format (must be freed with pk_free_buf)
    /// @return PK_SUCCESS or error code
    int pk_prove_json(const PKProver *prover, const char *inputs_json, PKBuf *out_proof);

    // -----------------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------------

    /// Verify a proof using a verifier handle.
    ///
    /// @param verifier Valid verifier handle
    /// @param proof_ptr Pointer to proof bytes (.np format)
    /// @param proof_len Length of proof bytes
    /// @return PK_SUCCESS if valid, PK_PROOF_ERROR if invalid
    int pk_verify(const PKVerifier *verifier, const uint8_t *proof_ptr, size_t proof_len);

    // -----------------------------------------------------------------------
    // Cleanup
    // -----------------------------------------------------------------------

    /// Free a prover handle.
    void pk_free_prover(PKProver *prover);

    /// Free a verifier handle.
    void pk_free_verifier(PKVerifier *verifier);

    /// Free a buffer allocated by ProveKit FFI functions.
    void pk_free_buf(PKBuf buf);

    /// Set custom allocator functions for memory management.
    ///
    /// @param alloc_fn Function to allocate memory (size, align) -> ptr, or NULL
    /// @param dealloc_fn Function to deallocate memory (ptr, size, align), or NULL
    void pk_set_allocator(void *(*_Nullable alloc_fn)(size_t size, size_t align),
                          void (*_Nullable dealloc_fn)(void *ptr, size_t size, size_t align));

#ifdef __cplusplus
}
#endif
