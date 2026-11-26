#include "hh_integration.h"

namespace hh_white {

HHWhitelistContext::HHWhitelistContext()
    : enabled(false), verifier(nullptr), processor(nullptr)
{
#ifdef _WIN32
    verifier = new WinSignatureVerifier();
#else
    // Off-Windows builds (unit tests) inject their own verifier; leave null.
    verifier = nullptr;
#endif
}

HHWhitelistContext::~HHWhitelistContext()
{
    delete processor;
    delete verifier;
}

size_t HHWhitelistContext::configure(const std::string& whitelist_file, bool enabled_flag)
{
    enabled = enabled_flag && !whitelist_file.empty();
    size_t loaded = 0;
    if (enabled) {
        loaded = whitelist.loadFromFile(whitelist_file);
        // A configured but unreadable/empty file must not silently disable
        // suppression guarantees: stay enabled with zero rules (nothing is
        // suppressed, all findings remain visible).
        enabled = true;
    }
    delete processor;
    if (verifier) {
        processor = new PostProcessor(whitelist, *verifier, enabled);
    }
    return loaded;
}

} // namespace hh_white
