#include "hh_classifier.h"

namespace hh_white {

const char* injectTypeName(t_inject_type type)
{
    switch (type) {
    case INJ_HOLLOWING:          return "hollowing";
    case INJ_HEADER_MODIFIED:    return "header_modified";
    case INJ_IMPLANTED_PE:       return "implanted_pe";
    case INJ_SHELLCODE:          return "shellcode";
    case INJ_THREAD_SHELLCODE:   return "thread_shellcode";
    case INJ_CODE_PATCH:         return "code_patch";
    case INJ_IAT_HOOK:           return "iat_hook";
    case INJ_UNREACHABLE_FILE:   return "unreachable_file";
    case INJ_UNKNOWN:            return "unknown";
    default:                     return "unknown";
    }
}

const char* injectTypeRationale(t_inject_type type)
{
    switch (type) {
    case INJ_HOLLOWING:
        return "headers_scan.is_pe_replaced=1: section headers of the mapped module "
               "differ from the backing file, i.e. the original PE image was replaced in memory";
    case INJ_IMPLANTED_PE:
        return "workingset_scan/artefact scan flagged a full PE image inside private memory "
               "that is not connected to the loader module list (manual mapping / reflective loading)";
    case INJ_THREAD_SHELLCODE:
        return "thread_scan suspicious: an executing thread call stack leads into executable "
               "memory that does not belong to any loaded module (active shellcode/injection)";
    case INJ_SHELLCODE:
        return "workingset_scan suspicious: executable private memory region recognized as shellcode "
               "by code patterns or entropy statistics, with no backing module";
    case INJ_HEADER_MODIFIED:
        return "headers_scan reports modified DOS/NT/file/optional/entry-point headers while "
               "is_pe_replaced=0: in-place header tampering without a full image replacement";
    case INJ_CODE_PATCH:
        return "code_scan suspicious: bytes of the loaded module diverge from the on-disk image "
               "(inline hook or runtime code patch)";
    case INJ_IAT_HOOK:
        return "iat_scan suspicious: one or more import address table entries point outside the "
               "expected module range (IAT hooking)";
    case INJ_UNREACHABLE_FILE:
        return "unreachable_scan: the file backing the mapped module cannot be opened/read, so the "
               "in-memory image cannot be validated against its original payload";
    case INJ_UNKNOWN:
    default:
        return "module marked suspicious by PE-sieve but none of the recognized indicator blocks matched";
    }
}

bool isWhitelistable(t_inject_type type)
{
    // Only low-confidence indicators, typically produced by legitimate security
    // products (AV/EDR hooks, locked self-protection drivers), can be suppressed.
    // The four high-confidence injection classes below are never suppressible.
    switch (type) {
    case INJ_CODE_PATCH:
    case INJ_IAT_HOOK:
    case INJ_UNREACHABLE_FILE:
    case INJ_HEADER_MODIFIED:
        return true;
    case INJ_HOLLOWING:
    case INJ_IMPLANTED_PE:
    case INJ_SHELLCODE:
    case INJ_THREAD_SHELLCODE:
    case INJ_UNKNOWN:
    default:
        return false;
    }
}

const char* signatureStateName(t_signature_state state)
{
    switch (state) {
    case SIG_VALID:       return "valid";
    case SIG_INVALID:     return "invalid";
    case SIG_UNSIGNED:    return "unsigned";
    case SIG_NOT_CHECKED:
    default:              return "not_checked";
    }
}

const char* whitelistDecisionName(t_whitelist_decision decision)
{
    switch (decision) {
    case WL_SIGNER_MATCH:   return "signer_match";
    case WL_PATH_MATCH:     return "path_match";
    case WL_RULE_DISABLED:  return "rule_scope_rejected";
    case WL_NOT_WHITELISTED:
    default:                return "not_whitelisted";
    }
}

bool InjectClassifier::looksLikeHollowing(const ModuleFinding& f)
{
    return f.has_headers_scan && f.is_pe_replaced;
}

bool InjectClassifier::looksLikeImplantedPe(const ModuleFinding& f)
{
    // A manual-mapped PE is reported by the artefact/workingset scanner and is
    // not attached to a headers scan of a loader-known module.
    return f.has_artefact_scan;
}

bool InjectClassifier::looksLikeThreadShellcode(const ModuleFinding& f)
{
    return f.has_thread_scan;
}

bool InjectClassifier::looksLikeShellcode(const ModuleFinding& f)
{
    return f.has_workingset_scan;
}

bool InjectClassifier::looksLikeHeaderMod(const ModuleFinding& f)
{
    return f.has_malformed_header ||
           (f.has_headers_scan && !f.is_pe_replaced && f.hdr_modified);
}

bool InjectClassifier::looksLikeIatHook(const ModuleFinding& f)
{
    return f.has_iat_scan;
}

bool InjectClassifier::looksLikeCodePatch(const ModuleFinding& f)
{
    return f.has_code_scan;
}

bool InjectClassifier::looksLikeUnreachable(const ModuleFinding& f)
{
    return f.has_unreachable_scan;
}

t_inject_type InjectClassifier::classify(const ModuleFinding& finding)
{
    // Order matters: evaluate the most dangerous, highest-confidence technique
    // first. A hollowed image that also carries code patches is still hollowing.
    if (looksLikeHollowing(finding))         return INJ_HOLLOWING;
    if (looksLikeImplantedPe(finding))       return INJ_IMPLANTED_PE;
    if (looksLikeThreadShellcode(finding))   return INJ_THREAD_SHELLCODE;
    if (looksLikeShellcode(finding))         return INJ_SHELLCODE;
    if (looksLikeHeaderMod(finding))         return INJ_HEADER_MODIFIED;
    if (looksLikeIatHook(finding))           return INJ_IAT_HOOK;
    if (looksLikeCodePatch(finding))         return INJ_CODE_PATCH;
    if (looksLikeUnreachable(finding))       return INJ_UNREACHABLE_FILE;
    return INJ_UNKNOWN;
}

void InjectClassifier::classifyAll(ProcessVerdict& verdict)
{
    for (size_t i = 0; i < verdict.findings.size(); ++i) {
        ModuleFinding& finding = verdict.findings[i];
        finding.inject_type = classify(finding);
    }
}

} // namespace hh_white
