#include "bb_v087_mobile.h"

#include "barretenberg/api/api_ultra_honk.hpp"
#include "barretenberg/srs/global_crs.hpp"

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::mutex backend_mutex;
bool crs_initialized = false;

void clear_bundle(bb_v087_proof_bundle* bundle)
{
    if (bundle != nullptr) {
        bundle->public_inputs = {};
        bundle->proof = {};
        bundle->verification_key = {};
    }
}

void set_error(char** error_out, const std::string& message)
{
    if (error_out == nullptr) {
        return;
    }
    *error_out = static_cast<char*>(std::malloc(message.size() + 1));
    if (*error_out != nullptr) {
        std::memcpy(*error_out, message.c_str(), message.size() + 1);
    }
}

bb_v087_buffer read_owned_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }
    const auto end = input.tellg();
    if (end < 0) {
        throw std::runtime_error("failed to determine output size: " + path.string());
    }
    const auto length = static_cast<size_t>(end);
    input.seekg(0, std::ios::beg);
    auto* data = static_cast<uint8_t*>(std::malloc(length == 0 ? 1 : length));
    if (data == nullptr) {
        throw std::bad_alloc();
    }
    if (length != 0 && !input.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(length))) {
        std::free(data);
        throw std::runtime_error("failed to read output file: " + path.string());
    }
    return { data, length };
}

bool valid_path_argument(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bb::API::Flags campaign_flags()
{
    return {
        .zk = false,
        .ipa_accumulation = false,
        .scheme = "ultra_honk",
        .oracle_hash_type = "poseidon2",
        .output_format = "bytes",
        .write_vk = true,
    };
}

template <typename Function> bb_v087_status guarded(char** error_out, Function&& function)
{
    if (error_out != nullptr) {
        *error_out = nullptr;
    }
    try {
        function();
        return BB_V087_OK;
    } catch (const std::filesystem::filesystem_error& error) {
        set_error(error_out, error.what());
        return BB_V087_IO_ERROR;
    } catch (const std::exception& error) {
        set_error(error_out, error.what());
        return BB_V087_BACKEND_ERROR;
    } catch (...) {
        set_error(error_out, "unknown Barretenberg exception");
        return BB_V087_BACKEND_ERROR;
    }
}

} // namespace

// The upstream aggregate archive omits its `env` module: native executables
// normally link that module as a separate CMake target. Mobile consumers link
// only the aggregate archive, so provide the two native environment hooks in
// the adapter. Upstream is compiled with NO_MULTITHREADING for this lane.
extern "C" uint32_t env_hardware_concurrency(void)
{
    return 1;
}

extern "C" void logstr(const char* value)
{
    if (value != nullptr) {
        std::cerr << value << '\n';
    }
}

extern "C" const char* bb_v087_mobile_version(void)
{
    return "0.87.0";
}

extern "C" bb_v087_status bb_v087_init_local_crs(const char* crs_directory, char** error_out)
{
    if (!valid_path_argument(crs_directory)) {
        set_error(error_out, "crs_directory must be a non-empty path");
        return BB_V087_INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> lock(backend_mutex);
    return guarded(error_out, [&] {
        if (!crs_initialized) {
            bb::srs::init_file_crs_factory(std::filesystem::path(crs_directory));
            crs_initialized = true;
        }
    });
}

extern "C" bb_v087_status bb_v087_prove(const char* circuit_path,
                                         const char* witness_path,
                                         const char* output_directory,
                                         bb_v087_proof_bundle* out,
                                         char** error_out)
{
    if (!valid_path_argument(circuit_path) || !valid_path_argument(witness_path) ||
        !valid_path_argument(output_directory) || out == nullptr) {
        set_error(error_out, "prove requires circuit, witness, output directory, and output bundle");
        return BB_V087_INVALID_ARGUMENT;
    }
    clear_bundle(out);
    std::lock_guard<std::mutex> lock(backend_mutex);
    if (!crs_initialized) {
        set_error(error_out, "local CRS must be initialized before proving");
        return BB_V087_INVALID_ARGUMENT;
    }
    return guarded(error_out, [&] {
        const std::filesystem::path output(output_directory);
        std::filesystem::create_directories(output);
        std::filesystem::remove(output / "public_inputs");
        std::filesystem::remove(output / "proof");
        std::filesystem::remove(output / "vk");

        bb::UltraHonkAPI api;
        api.prove(campaign_flags(), circuit_path, witness_path, output);

        bb_v087_proof_bundle result{};
        try {
            result.public_inputs = read_owned_file(output / "public_inputs");
            result.proof = read_owned_file(output / "proof");
            result.verification_key = read_owned_file(output / "vk");
        } catch (...) {
            bb_v087_free_proof_bundle(&result);
            throw;
        }
        *out = result;
    });
}

extern "C" bb_v087_status bb_v087_verify(const char* public_inputs_path,
                                          const char* proof_path,
                                          const char* verification_key_path,
                                          bool* verified_out,
                                          char** error_out)
{
    if (!valid_path_argument(public_inputs_path) || !valid_path_argument(proof_path) ||
        !valid_path_argument(verification_key_path) || verified_out == nullptr) {
        set_error(error_out, "verify requires public inputs, proof, verification key, and result");
        return BB_V087_INVALID_ARGUMENT;
    }
    *verified_out = false;
    std::lock_guard<std::mutex> lock(backend_mutex);
    if (!crs_initialized) {
        set_error(error_out, "local CRS must be initialized before verification");
        return BB_V087_INVALID_ARGUMENT;
    }
    return guarded(error_out, [&] {
        bb::UltraHonkAPI api;
        *verified_out =
            api.verify(campaign_flags(), public_inputs_path, proof_path, verification_key_path);
    });
}

extern "C" void bb_v087_free_buffer(bb_v087_buffer* buffer)
{
    if (buffer != nullptr) {
        std::free(buffer->data);
        buffer->data = nullptr;
        buffer->len = 0;
    }
}

extern "C" void bb_v087_free_proof_bundle(bb_v087_proof_bundle* bundle)
{
    if (bundle != nullptr) {
        bb_v087_free_buffer(&bundle->public_inputs);
        bb_v087_free_buffer(&bundle->proof);
        bb_v087_free_buffer(&bundle->verification_key);
    }
}

extern "C" void bb_v087_free_error(char* error)
{
    std::free(error);
}
