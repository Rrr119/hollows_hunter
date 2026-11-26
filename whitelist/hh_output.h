#pragma once

#include <string>

#include "hh_types.h"

namespace hh_white {

// Renders the extra fields that extend (never replace) the legacy HollowsHunter
// JSON contract. The output is a self-contained object so it can be embedded
// either inside each suspicious process entry or as a standalone audit block.
class EnhancedOutput {
public:
    static std::string findingToJson(const ModuleFinding& finding, size_t level);
    static std::string verdictToJson(const ProcessVerdict& verdict, size_t level);

    // Plain-text, one line per finding, used by the non-JSON console summary.
    static std::string verdictToText(const ProcessVerdict& verdict);

private:
    static void pad(std::string& out, size_t level);
};

} // namespace hh_white
