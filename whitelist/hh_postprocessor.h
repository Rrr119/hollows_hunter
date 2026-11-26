#pragma once

#include <string>

#include "hh_types.h"
#include "hh_whitelist.h"
#include "hh_signature.h"

namespace hh_white {

// End-to-end pipeline used by HollowsHunter for every scanned process:
// parse PE-sieve JSON -> classify each finding -> verify signatures once per
// module -> apply the whitelist. The signature verifier is injected so the
// whole pipeline remains testable off-Windows.
class PostProcessor {
public:
    PostProcessor(WhitelistEngine& engine, SignatureVerifier& verifier,
                  bool whitelist_enabled)
        : whitelist(engine), sig_verifier(verifier),
          enabled(whitelist_enabled)
    {
    }

    // Full processing of one PE-sieve per-process JSON document.
    bool process(const std::string& pesieve_json, ProcessVerdict& out);

    // Enriches an already parsed verdict (used when the JSON path is bypassed).
    void enrich(ProcessVerdict& verdict);

private:
    void verifySignatures(ProcessVerdict& verdict);

    WhitelistEngine& whitelist;
    SignatureVerifier& sig_verifier;
    bool enabled;
};

} // namespace hh_white
