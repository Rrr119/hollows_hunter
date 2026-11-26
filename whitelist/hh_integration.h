#pragma once

#include <string>

#include "hh_types.h"
#include "hh_whitelist.h"
#include "hh_signature.h"
#include "hh_postprocessor.h"

namespace hh_white {

// Process-wide context shared by every scan round. It owns the whitelist
// rules, the platform signature verifier and the lazily constructed pipeline.
class HHWhitelistContext {
public:
    HHWhitelistContext();
    ~HHWhitelistContext();

    // Loads the configured whitelist file. Returns the number of rules loaded
    // (0 means either an empty/missing file or a disabled feature).
    size_t configure(const std::string& whitelist_file, bool enabled);

    bool isEnabled() const { return enabled; }
    PostProcessor* getProcessor() { return processor; }
    WhitelistEngine& engine() { return whitelist; }

private:
    bool enabled;
    WhitelistEngine whitelist;
    SignatureVerifier* verifier;
    PostProcessor* processor;
};

} // namespace hh_white
