#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <zlib.h>

/**
 * Mobile replacement for v0.87's CLI loader, which invokes `gunzip` through
 * `popen`. iOS and Android app sandboxes have no shell utility contract.
 */
inline std::vector<uint8_t> gunzip(const std::string& path)
{
    gzFile input = gzopen(path.c_str(), "rb");
    if (input == nullptr) {
        throw std::runtime_error("failed to open gzip input: " + path);
    }
    std::vector<uint8_t> output;
    std::array<uint8_t, 64 * 1024> chunk{};
    for (;;) {
        const int bytes = gzread(input, chunk.data(), static_cast<unsigned int>(chunk.size()));
        if (bytes > 0) {
            output.insert(output.end(), chunk.begin(), chunk.begin() + bytes);
            continue;
        }
        if (bytes == 0 && gzeof(input) != 0) {
            break;
        }
        int error_number = Z_OK;
        const char* error = gzerror(input, &error_number);
        const std::string message =
            error != nullptr ? error : "unknown gzip decompression error";
        gzclose(input);
        throw std::runtime_error("failed to decompress " + path + ": " + message);
    }
    if (gzclose(input) != Z_OK) {
        throw std::runtime_error("failed to close gzip input: " + path);
    }
    return output;
}

inline std::vector<uint8_t> get_bytecode(const std::string& bytecode_path)
{
    if (bytecode_path == "-") {
        return { std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>() };
    }
    if (std::filesystem::path(bytecode_path).extension() == ".json") {
        throw std::runtime_error(
            "mobile Barretenberg requires a packaged raw .gz bytecode fixture");
    }
    return gunzip(bytecode_path);
}
