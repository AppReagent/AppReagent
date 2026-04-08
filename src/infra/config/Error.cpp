#include "infra/config/Error.h"
#include <string>

namespace area {
std::string toStr(Error e) {
    switch (e) {
        case Error::ExpectedNamedArgValue: return "ExpectedNamedArgValue";
        case Error::NotYetParsed: return "NotYetParsed";
        case Error::NoSuchPositionalArg: return "NoSuchPositionalArg";

        case Error::UnknownCommand: return "UnknownCommand";

        case Error::UnknownDirectory: return "UnknownDirectory";

        default: return "(UnknownError!)";
    }
}
}  // namespace area
