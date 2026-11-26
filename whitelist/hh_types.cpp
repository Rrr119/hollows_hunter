#include "hh_types.h"

namespace hh_white {

size_t ProcessVerdict::countRemaining() const
{
    size_t count = 0;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (findings[i].decision == WL_NOT_WHITELISTED ||
            findings[i].decision == WL_RULE_DISABLED) {
            ++count;
        }
    }
    return count;
}

size_t ProcessVerdict::countSuppressed() const
{
    size_t count = 0;
    for (size_t i = 0; i < findings.size(); ++i) {
        if (findings[i].decision == WL_SIGNER_MATCH ||
            findings[i].decision == WL_PATH_MATCH) {
            ++count;
        }
    }
    return count;
}

bool ProcessVerdict::isFpSuppressed() const
{
    return !findings.empty() && countRemaining() == 0;
}

} // namespace hh_white
