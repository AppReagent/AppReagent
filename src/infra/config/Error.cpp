#include "infra/config/Error.h"
#include <string>

namespace area {

std::string toStr(Error e) {
    switch (e) {
        // ArgParse errors (TODO: unused)
        case Error::ExpectedNamedArgValue: return "ExpectedNamedArgValue";
        case Error::NotYetParsed: return "NotYetParsed";
        case Error::NoSuchPositionalArg: return "NoSuchPositionalArg";

        // command errors
        case Error::UnknownCommand: return "UnknownCommand";

        // "process" command errors
        case Error::UnknownDirectory: return "UnknownDirectory";

        default: return "(UnknownError!)";
    }
}

} // namespace area
