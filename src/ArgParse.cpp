#include "ArgParse.h"
#include "Error.h"

namespace area {

ArgParse::ArgParse(int argc, char *argv[]) : argc_(argc), argv_(argv) {}

std::optional<Error> ArgParse::parse() {
    if (parsed_) {
        return std::nullopt;
    }
    bool positional = true;
    for (int i = 0; i < argc_; i++) {
        std::string arg(argv_[i]);
        if (arg.length() > 2 && arg.substr(0, 2) == "--") {
            positional = false;
        }
        if (positional) {
            positionalArgs_.push_back(argv_[i]);
        } else {
            if (i + 1 == argc_) {
                return Error::ExpectedNamedArgValue;
            }
            namedArgs_[arg.substr(2)] = std::string(argv_[i+1]);
            i++; // skip the value
        }
    }
    parsed_ = true;
    return std::nullopt;
}

std::optional<std::string> ArgParse::getPositionalArg(const size_t idx) const {
    if (idx >= positionalArgs_.size()) {
        return std::nullopt;
    }
    return positionalArgs_[idx];
}

std::optional<std::string> ArgParse::getNamedArg(const std::string& key) const {
    if (namedArgs_.count(key)) {
        return namedArgs_.at(key);
    }
    return std::nullopt;
}

} // namespace area
