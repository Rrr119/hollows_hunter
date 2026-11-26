#pragma once

#include "hh_types.h"

namespace hh_white {

// Maps the raw indicators collected from a PE-sieve module report onto a
// single, fine-grained injection type. The mapping is deterministic and the
// rationale for every type is exposed via injectTypeRationale().
class InjectClassifier {
public:
    static t_inject_type classify(const ModuleFinding& finding);

    // Apply the classification in-place to a full process verdict.
    static void classifyAll(ProcessVerdict& verdict);

private:
    // Ordered by severity: the first matching high-confidence type wins, so
    // that a module exhibiting several indicators is always reported using
    // the most dangerous applicable category.
    static bool looksLikeHollowing(const ModuleFinding& f);
    static bool looksLikeImplantedPe(const ModuleFinding& f);
    static bool looksLikeThreadShellcode(const ModuleFinding& f);
    static bool looksLikeShellcode(const ModuleFinding& f);
    static bool looksLikeHeaderMod(const ModuleFinding& f);
    static bool looksLikeIatHook(const ModuleFinding& f);
    static bool looksLikeCodePatch(const ModuleFinding& f);
    static bool looksLikeUnreachable(const ModuleFinding& f);
};

} // namespace hh_white
