#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace hh_white {

// Verdict assigned to a single suspicious module finding.
// The numeric values are part of the JSON output contract and must not change.
typedef enum inject_type {
    INJ_UNKNOWN = 0,            // indicators present but no specific type matched
    INJ_HOLLOWING = 1,          // PE replaced in memory (section headers overwritten)
    INJ_HEADER_MODIFIED = 2,    // PE header modified but not fully replaced
    INJ_IMPLANTED_PE = 3,       // full PE mapped outside the loader (manual mapping)
    INJ_SHELLCODE = 4,          // executable shellcode in private/working-set memory
    INJ_THREAD_SHELLCODE = 5,   // shellcode reached from a thread call stack
    INJ_CODE_PATCH = 6,         // inline hook / code patch inside a loaded module
    INJ_IAT_HOOK = 7,           // import address table hook
    INJ_UNREACHABLE_FILE = 8,   // backing file of the module cannot be read
    INJ_TYPES_COUNT
} t_inject_type;

// Whether a finding of this type may ever be suppressed by the whitelist.
// High-confidence injection techniques are intentionally NOT whitelistable,
// so that real injections can never be missed (zero false negatives).
bool isWhitelistable(t_inject_type type);

const char* injectTypeName(t_inject_type type);

// Human readable explanation of the exact indicators that lead to the verdict.
const char* injectTypeRationale(t_inject_type type);

typedef enum signature_state {
    SIG_NOT_CHECKED = 0,   // signature verification was not performed
    SIG_VALID = 1,         // Authenticode signature verified and trusted
    SIG_INVALID = 2,       // signature present but broken/untrusted
    SIG_UNSIGNED = 3       // no embedded Authenticode signature
} t_signature_state;

const char* signatureStateName(t_signature_state state);

typedef enum whitelist_decision {
    WL_NOT_WHITELISTED = 0,    // keep the finding as suspicious
    WL_SIGNER_MATCH = 1,       // suppressed: signer matched a whitelist rule
    WL_PATH_MATCH = 2,         // suppressed: load path matched a whitelist rule
    WL_RULE_DISABLED = 3,      // rule matched but its signature/path scope did not
} t_whitelist_decision;

const char* whitelistDecisionName(t_whitelist_decision decision);

// One suspicious module extracted from a PE-sieve per-process JSON report.
struct ModuleFinding {
    std::string module_file;       // "module_file" as emitted by PE-sieve (escaped)
    bool has_headers_scan = false;
    bool is_pe_replaced = false;   // headers_scan.is_pe_replaced
    bool hdr_modified = false;     // any of dos/file/nt/sec/ep header flags set
    bool has_code_scan = false;
    bool has_iat_scan = false;
    bool has_workingset_scan = false;
    bool has_thread_scan = false;
    bool has_artefact_scan = false;
    bool has_unreachable_scan = false;
    bool has_malformed_header = false;
    int status = 0;                // PE-sieve per-module "status"

    // Filled by the classification / whitelist pipeline:
    t_inject_type inject_type = INJ_UNKNOWN;
    t_signature_state signature = SIG_NOT_CHECKED;
    std::string signer_name;       // certificate subject CN when available
    t_whitelist_decision decision = WL_NOT_WHITELISTED;
    std::string matched_rule;      // raw text of the whitelist rule that matched
};

// Result of post-processing one scanned process.
struct ProcessVerdict {
    uint32_t pid = 0;
    std::string image_name;
    std::vector<ModuleFinding> findings;

    size_t countRemaining() const;   // findings still suspicious after whitelisting
    size_t countSuppressed() const;  // findings moved to the whitelist audit trail
    bool isFpSuppressed() const;     // originally suspicious, now fully explained
};

} // namespace hh_white
