#include <charconv>
#include <cstdio>
#include <limits>

namespace {
template <typename Float>
std::to_chars_result format_float(
    char* first,
    char* last,
    Float value,
    std::chars_format format,
    int precision)
{
    if (first >= last) {
        return {last, std::errc::value_too_large};
    }

    const char* specifier = "%.*g";
    switch (format) {
    case std::chars_format::fixed:
        specifier = "%.*f";
        break;
    case std::chars_format::scientific:
        specifier = "%.*e";
        break;
    case std::chars_format::hex:
        specifier = "%.*a";
        break;
    case std::chars_format::general:
        break;
    }

    const int available = static_cast<int>(last - first);
    const int written = snprintf(first, static_cast<size_t>(available), specifier, precision, value);
    if (written < 0 || written >= available) {
        return {last, std::errc::value_too_large};
    }
    return {first + written, std::errc{}};
}

template <typename Float>
std::to_chars_result format_float(
    char* first,
    char* last,
    Float value,
    std::chars_format format)
{
    return format_float(first, last, value, format, std::numeric_limits<Float>::max_digits10);
}
} // namespace

// The Barretenberg 4.2.0 iOS archive was built against a newer libc++ and
// imports the std::__1 floating-point to_chars ABI that iOS 15 does not
// provide. Export those exact historical symbols from the application.
extern "C" std::to_chars_result shim_float(char*, char*, float)
    __asm("__ZNSt3__18to_charsEPcS0_f");
extern "C" std::to_chars_result shim_double(char*, char*, double)
    __asm("__ZNSt3__18to_charsEPcS0_d");
extern "C" std::to_chars_result shim_long_double(char*, char*, long double)
    __asm("__ZNSt3__18to_charsEPcS0_e");
extern "C" std::to_chars_result shim_float_format(char*, char*, float, std::chars_format)
    __asm("__ZNSt3__18to_charsEPcS0_fNS_12chars_formatE");
extern "C" std::to_chars_result shim_double_format(char*, char*, double, std::chars_format)
    __asm("__ZNSt3__18to_charsEPcS0_dNS_12chars_formatE");
extern "C" std::to_chars_result shim_long_double_format(
    char*,
    char*,
    long double,
    std::chars_format) __asm("__ZNSt3__18to_charsEPcS0_eNS_12chars_formatE");
extern "C" std::to_chars_result shim_float_precision(
    char*,
    char*,
    float,
    std::chars_format,
    int) __asm("__ZNSt3__18to_charsEPcS0_fNS_12chars_formatEi");
extern "C" std::to_chars_result shim_double_precision(
    char*,
    char*,
    double,
    std::chars_format,
    int) __asm("__ZNSt3__18to_charsEPcS0_dNS_12chars_formatEi");
extern "C" std::to_chars_result shim_long_double_precision(
    char*,
    char*,
    long double,
    std::chars_format,
    int) __asm("__ZNSt3__18to_charsEPcS0_eNS_12chars_formatEi");

std::to_chars_result shim_float(char* first, char* last, float value)
{
    return format_float(first, last, value, std::chars_format::general);
}

std::to_chars_result shim_double(char* first, char* last, double value)
{
    return format_float(first, last, value, std::chars_format::general);
}

std::to_chars_result shim_long_double(char* first, char* last, long double value)
{
    return format_float(first, last, static_cast<double>(value), std::chars_format::general);
}

std::to_chars_result shim_float_format(
    char* first,
    char* last,
    float value,
    std::chars_format format)
{
    return format_float(first, last, value, format);
}

std::to_chars_result shim_double_format(
    char* first,
    char* last,
    double value,
    std::chars_format format)
{
    return format_float(first, last, value, format);
}

std::to_chars_result shim_long_double_format(
    char* first,
    char* last,
    long double value,
    std::chars_format format)
{
    return format_float(first, last, static_cast<double>(value), format);
}

std::to_chars_result shim_float_precision(
    char* first,
    char* last,
    float value,
    std::chars_format format,
    int precision)
{
    return format_float(first, last, value, format, precision);
}

std::to_chars_result shim_double_precision(
    char* first,
    char* last,
    double value,
    std::chars_format format,
    int precision)
{
    return format_float(first, last, value, format, precision);
}

std::to_chars_result shim_long_double_precision(
    char* first,
    char* last,
    long double value,
    std::chars_format format,
    int precision)
{
    return format_float(first, last, static_cast<double>(value), format, precision);
}
