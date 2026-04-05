#pragma once

#include <string>

namespace area {

enum class Error {
    // ArgParse errors (TODO: unused)
    ExpectedNamedArgValue,
    NotYetParsed,
    NoSuchPositionalArg,

    // command errors
    UnknownCommand,

    // "scan" command errors
    UnknownDirectory,
};

std::string toStr(Error e);

} // namespace area
