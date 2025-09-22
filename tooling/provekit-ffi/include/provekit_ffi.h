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
    } PKBuf;

    // Note: To use custom memory allocation, you need to provide these functions
    // at link time in your host application:
    //
    // C/C++:
    //   void* provekit_alloc(size_t size, size_t align);
    //   void provekit_free(void* ptr);
    //
    // Swift:
    //   @_cdecl("provekit_alloc")
    //   func provekit_alloc(size: Int, align: Int) -> UnsafeMutableRawPointer?
    //   @_cdecl("provekit_free")
    //   func provekit_free(ptr: UnsafeMutableRawPointer?)
    //
    // Kotlin/JNI:
    //   external fun provekit_alloc(size: Long, align: Long): Long
    //   external fun provekit_free(ptr: Long)
    //
    // The host application can implement custom memory management strategies
    // such as memory pools, mmap, or platform-specific allocators.

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
    /// @param scheme_path Path to the prepared proof scheme (.nps file)
    /// @param input_path Path to the witness/input values (.toml file)
    /// @param out_path Path where to write the proof file (.np or .json)
    /// @return PK_SUCCESS on success, or an appropriate error code on failure
    int pk_prove_to_file(const char *scheme_path, const char *input_path, const char *out_path);

    /// Prove a Noir program and return the proof as JSON string.
    ///
    /// This function is only available when the library is built with JSON support.
    ///
    /// @param scheme_path Path to the prepared proof scheme (.nps file)
    /// @param input_path Path to the witness/input values (.toml file)
    /// @param out_buf Output buffer to store the JSON string (must be freed with pk_free_buf)
    /// @return PK_SUCCESS on success, or an appropriate error code on failure
    int pk_prove_to_json(const char *scheme_path, const char *input_path, PKBuf *out_buf);

    /// Free a buffer allocated by ProveKit FFI functions.
    ///
    /// @param buf The buffer to free
    void pk_free_buf(PKBuf buf);

    /// Get the last error message as a C string.
    ///
    /// @return A null-terminated C string containing the last error message,
    ///         or NULL if no error occurred. The returned string is static and
    ///         does not need to be freed.
    const char *pk_last_error(void);

#ifdef __cplusplus
}
#endif
