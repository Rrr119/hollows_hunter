#pragma once

#include <string>
#include <vector>
#include <set>

#include "hh_types.h"

namespace hh_white {

// One line from the whitelist configuration file.
// Syntax (case-insensitive keywords, '#' starts a comment):
//   signer:<certificate subject substring>
//   path:<load path prefix or glob>
//   name:<module file name>
// A line may be prefixed with "sig:" / "nosig:" to restrict its scope:
//   sig:path:C:\Program Files\...   -> applies only when the module signature is valid
//   nosig:path:C:\Windows\...       -> applies only to unsigned/unverified modules
// Prefixing a rule with "strict:" requires both signer and path scope to be valid.
struct WhitelistRule {
    std::string raw;             // original line, kept for audit output
    std::string signer;          // lower-cased signer substring, empty if unused
    std::string path;            // normalized lower-cased path prefix/glob, empty if unused
    std::string name;            // lower-cased module file name, empty if unused
    bool require_valid_sig = false;  // "sig:" scope
    bool require_no_sig = false;     // "nosig:" scope
    bool strict = false;             // both signature and path conditions must hold

    bool empty() const
    {
        return signer.empty() && path.empty() && name.empty();
    }
};

// Platform-independent whitelist engine. Signature verification itself is
// performed by an injected verifier (see SignatureVerifier) so that this code
// remains testable off-Windows.
class WhitelistEngine {
public:
    virtual ~WhitelistEngine() {}

    // Loads rules from an UTF-8 text file. Returns the number of rules loaded.
    size_t loadFromFile(const std::string& file_path);

    // Loads rules from an in-memory list of lines (used by tests).
    size_t loadFromLines(const std::vector<std::string>& lines);

    size_t ruleCount() const { return rules.size(); }
    const std::vector<WhitelistRule>& getRules() const { return rules; }

    // Evaluates every finding of the process and fills the whitelist decision
    // fields. Findings that remain suspicious keep WL_NOT_WHITELISTED.
    void apply(ProcessVerdict& verdict) const;

    // Exposed for unit testing: evaluate one finding against one rule.
    t_whitelist_decision evaluate(const ModuleFinding& finding,
                                  const WhitelistRule& rule) const;

    // Normalization helpers (public for tests).
    static std::string normalizePath(const std::string& path);
    static std::string toLower(const std::string& s);
    static bool globMatch(const std::string& pattern, const std::string& text);

private:
    bool parseLine(const std::string& line, WhitelistRule& out) const;
    bool ruleScopeOk(const ModuleFinding& finding, const WhitelistRule& rule) const;
    bool ruleTargetMatch(const ModuleFinding& finding, const WhitelistRule& rule) const;

    std::vector<WhitelistRule> rules;
};

} // namespace hh_white
