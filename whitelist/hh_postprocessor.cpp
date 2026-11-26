#include "hh_postprocessor.h"

#include <map>
#include "hh_report_adapter.h"
#include "hh_classifier.h"

namespace hh_white {

void PostProcessor::verifySignatures(ProcessVerdict& verdict)
{
    // One verification per unique backing file: the same signed AV DLL can be
    // reported by several scanner blocks.
    std::map<std::string, SignatureInfo> cache;
    for (size_t i = 0; i < verdict.findings.size(); ++i) {
        ModuleFinding& finding = verdict.findings[i];
        const std::string& path = finding.module_file;
        if (path.empty()) {
            finding.signature = SIG_NOT_CHECKED;
            continue;
        }
        std::map<std::string, SignatureInfo>::iterator cached = cache.find(path);
        if (cached == cache.end()) {
            cached = cache.insert(std::make_pair(path, sig_verifier.verify(path))).first;
        }
        finding.signature = cached->second.state;
        finding.signer_name = cached->second.signer;
    }
}

void PostProcessor::enrich(ProcessVerdict& verdict)
{
    InjectClassifier::classifyAll(verdict);
    verifySignatures(verdict);
    if (enabled) {
        whitelist.apply(verdict);
    }
}

bool PostProcessor::process(const std::string& pesieve_json, ProcessVerdict& out)
{
    if (!ReportAdapter::fromPesieveJson(pesieve_json, out)) {
        return false;
    }
    enrich(out);
    return true;
}

} // namespace hh_white
