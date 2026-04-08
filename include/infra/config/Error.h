#pragma once

#include <string>

namespace area {
enum class Error {
    ExpectedNamedArgValue,
    NotYetParsed,
    NoSuchPositionalArg,

    UnknownCommand,

    UnknownDirectory,
};

std::string toStr(Error e);
}  // namespace area
