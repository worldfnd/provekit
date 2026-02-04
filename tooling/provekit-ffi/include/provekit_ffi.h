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

    /// Error codes returned by ProveKit functions
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
        /// Failed to generate proof
        PK_PROOF_ERROR = 4,
        /// Failed to serialize output
        PK_SERIALIZATION_ERROR = 5,
        /// UTF-8 conversion error
        PK_UTF8_ERROR = 6,
        /// File write error
        PK_FILE_WRITE_ERROR = 7,
    } PKError;

    /// Initialize the ProveKit library.
    ///
    /// This function should be called once before using any other ProveKit functions.
    ///
    /// @return PK_SUCCESS on success
    int pk_init(void);

    /// Prove a Noir program and write the proof to a file.
    ///
    /// @param prover_path Path to the prepared proof scheme (.pkp file)
    /// @param input_path Path to the witness/input values (.toml file)
    /// @param out_path Path where to write the proof file (.np or .json)
    /// @return PK_SUCCESS on success, or an appropriate error code on failure
    int pk_prove_to_file(const char *prover_path, const char *input_path, const char *out_path);

    /// Prove a Noir program and return the proof as JSON string.
    ///
    /// This function is only available when the library is built with JSON support.
    ///
    /// @param prover_path Path to the prepared proof scheme (.pkp file)
    /// @param input_path Path to the witness/input values (.toml file)
    /// @param out_buf Output buffer to store the JSON string (must be freed with pk_free_buf)
    /// @return PK_SUCCESS on success, or an appropriate error code on failure
    int pk_prove_to_json(const char *prover_path, const char *input_path, PKBuf *out_buf);

    /// Free a buffer allocated by ProveKit FFI functions.
    ///
    /// @param buf The buffer to free
    void pk_free_buf(PKBuf buf);

    /// Set custom allocator functions for memory management.
    ///
    /// When set, all allocations will be delegated to the provided functions.
    /// Pass NULL for both to use the system allocator (default).
    ///
    /// @param alloc_fn Function to allocate memory (size, align) -> ptr, or NULL
    /// @param dealloc_fn Function to deallocate memory (ptr, size, align), or NULL
    void pk_set_allocator(void *(*_Nullable alloc_fn)(size_t size, size_t align),
                          void (*_Nullable dealloc_fn)(void *ptr, size_t size, size_t align));

    /// Configure the mmap-based memory allocator (MUST be called before pk_init).
    ///
    /// This configures the pure Rust mmap allocator with RAM limits and swap settings.
    /// Call this before pk_init() to use the mmap allocator instead of callbacks.
    ///
    /// @param ram_limit_bytes Maximum RAM before using swap (must be > 0)
    /// @param use_file_backed Whether to use file-backed mmap for swap
    /// @param swap_file_path Directory for swap files (NULL = system temp)
    /// @return PK_SUCCESS or PK_INVALID_INPUT
    int pk_configure_memory(size_t ram_limit_bytes, bool use_file_backed, const char *_Nullable swap_file_path);

    /// Get current memory statistics.
    ///
    /// Returns statistics about current RAM and swap usage from the mmap allocator.
    ///
    /// @param ram_used Output pointer for current RAM usage (can be NULL)
    /// @param swap_used Output pointer for current swap usage (can be NULL)
    /// @param peak_ram Output pointer for peak RAM usage (can be NULL)
    /// @return PK_SUCCESS
    int pk_get_memory_stats(size_t *_Nullable ram_used, size_t *_Nullable swap_used, size_t *_Nullable peak_ram);

#ifdef __cplusplus
}
#endif
