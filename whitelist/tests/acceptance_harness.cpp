// Acceptance harness for the HollowsHunter whitelist / classification work.
//
// It builds a deterministic corpus of 100 synthetic PE-sieve per-process
// reports: 60 benign processes whose only indicators come from legitimate
// security software (the historical false positives) and 40 processes that
// contain real injection techniques. It then runs the exact production
// pipeline (JSON parser -> classifier -> signature verifier -> whitelist)
// and reports:
//   * false-positive rate before and after whitelisting (quantified delta),
//   * false-negative rate on the real injections (required to stay 0),
//   * the distribution of every fine-grained injection type with its rationale.
//
// The verifier is a fake because Authenticode cannot run off-Windows; the
// signer/path assignments mirror what WinVerifyTrust returns on a real host.

#include <cstdio>
#include <string>
#include <sstream>
#include <vector>
#include <map>

#include "../hh_json.h"
#include "../hh_classifier.h"
#include "../hh_whitelist.h"
#include "../hh_report_adapter.h"
#include "../hh_postprocessor.h"
#include "../hh_output.h"

using namespace hh_white;

struct Sample {
    int id;
    bool malicious;          // ground truth
    std::string label;       // scenario description
    std::string json;        // PE-sieve style report
    std::string module_path; // primary suspicious module
    t_signature_state signature;
    std::string signer;
};

static std::string esc(const std::string& in)
{
    std::string out;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\') out += "\\\\";
        else out.push_back(in[i]);
    }
    return out;
}

static std::string wrapEntry(const std::string& block, const std::string& path, int status)
{
    std::stringstream ss;
    ss << "    {\"" << block << "\" : {\"status\" : " << status
       << ", \"module_file\" : \"" << esc(path) << "\"";
    if (block == "headers_scan") {
        const bool replaced = false;
        ss << ", \"is_pe_replaced\" : " << (replaced ? "true" : "false");
    }
    ss << "}}";
    return ss.str();
}

static std::string wrapReport(int pid, const std::vector<std::string>& entries)
{
    std::stringstream ss;
    ss << "{\"pid\" : " << pid << ", \"main_image_path\" : \"proc" << pid
       << ".exe\", \"scans\" : [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        ss << entries[i];
        if (i + 1 < entries.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ]}";
    return ss.str();
}

static std::string artefactEntry(const std::string& path)
{
    std::stringstream ss;
    ss << "    {\"workingset_scan\" : {\"status\" : 1"
       << ", \"module_file\" : \"" << esc(path) << "\""
       << ", \"has_pe\" : true, \"has_shellcode\" : false}}";
    return ss.str();
}

static std::string headersEntry(const std::string& path, bool replaced, bool modified, int status)
{
    std::stringstream ss;
    ss << "    {\"headers_scan\" : {\"status\" : " << status
       << ", \"module_file\" : \"" << esc(path) << "\""
       << ", \"is_pe_replaced\" : " << (replaced ? "true" : "false")
       << ", \"nt_hdr_modified\" : " << (modified ? "true" : "false") << "}}";
    return ss.str();
}

static void addBenignAvScenarios(std::vector<Sample>& samples)
{
    struct Scenario { const char* block; const char* path; const char* signer; t_signature_state sig; const char* label; };
    const std::string av_root = "C:\\Program Files\\TrustedAV\\";
    const std::string sys_root = "C:\\Windows\\System32\\drivers\\";
    const Scenario scenarios[] = {
        {"code_scan",        "C:\\Program Files\\TrustedAV\\avengine.dll",        "TrustedAV Inc.",      SIG_VALID,    "AV user-mode inline hook"},
        {"iat_scan",         "C:\\Program Files\\TrustedAV\\avhook.dll",          "TrustedAV Inc.",      SIG_VALID,    "AV IAT hook for telemetry"},
        {"unreachable_scan", "C:\\Program Files\\TrustedAV\\selfprotect.sys",     "TrustedAV Inc.",      SIG_VALID,    "AV self-protection locks file"},
        {"code_scan",        "C:\\Windows\\System32\\drivers\\edrfilter.sys",     "Microsoft Corporation", SIG_VALID,  "signed EDR kernel filter patch"},
        {"iat_scan",         "C:\\Program Files\\EndpointGuard\\egdll.dll",       "EndpointGuard Ltd.",  SIG_VALID,    "EDR DLL IAT instrumentation"},
        {"headers_scan",     "C:\\Program Files\\TrustedAV\\avrt.dll",            "TrustedAV Inc.",      SIG_VALID,    "AV runtime header touch"},
    };
    const size_t scenario_count = sizeof(scenarios) / sizeof(scenarios[0]);
    for (int i = 0; i < 60; ++i) {
        const Scenario& sc = scenarios[i % scenario_count];
        Sample s;
        s.id = i;
        s.malicious = false;
        s.label = sc.label;
        s.module_path = sc.path;
        s.signature = sc.sig;
        s.signer = sc.signer;

        std::vector<std::string> entries;
        if (std::string(sc.block) == "headers_scan") {
            entries.push_back(headersEntry(sc.path, false, true, 1));
        }
        else {
            entries.push_back(wrapEntry(sc.block, sc.path, 1));
        }
        // A clean, unrelated signed module always accompanies the indicator.
        entries.push_back(headersEntry("C:\\Windows\\System32\\kernel32.dll", false, false, 0));
        s.json = wrapReport(1000 + i, entries);
        samples.push_back(s);
    }
}

static void addMaliciousScenarios(std::vector<Sample>& samples)
{
    struct Scenario { const char* block; const char* path; t_signature_state sig; const char* signer; const char* label; t_inject_type expected; };
    const Scenario scenarios[] = {
        {"headers_scan",    "C:\\Users\\victim\\app.exe",               SIG_UNSIGNED, "",                       "process hollowing",          INJ_HOLLOWING},
        {"artefact_scan",   "C:\\Users\\victim\\manualmap.bin",         SIG_UNSIGNED, "",                       "manual mapped PE artefact",  INJ_IMPLANTED_PE},
        {"workingset_scan", "C:\\Users\\victim\\manualmap.bin",         SIG_UNSIGNED, "",                       "manual mapped PE",           INJ_SHELLCODE},
        {"workingset_scan", "C:\\Users\\victim\\shellcode.bin",         SIG_UNSIGNED, "",                       "private shellcode region",   INJ_SHELLCODE},
        {"thread_scan",     "C:\\Users\\victim\\stack_beacon.bin",      SIG_UNSIGNED, "",                       "thread callstack shellcode", INJ_THREAD_SHELLCODE},
    };
    const size_t scenario_count = sizeof(scenarios) / sizeof(scenarios[0]);
    for (int i = 0; i < 38; ++i) {
        const Scenario& sc = scenarios[i % scenario_count];
        Sample s;
        s.id = 60 + i;
        s.malicious = true;
        s.label = sc.label;
        s.module_path = sc.path;
        s.signature = sc.sig;
        s.signer = sc.signer;

        std::vector<std::string> entries;
        if (std::string(sc.block) == "headers_scan") {
            entries.push_back(headersEntry(sc.path, true, true, 1));
        }
        else if (std::string(sc.block) == "artefact_scan") {
            entries.push_back(artefactEntry(sc.path));
        }
        else {
            entries.push_back(wrapEntry(sc.block, sc.path, 1));
        }
        s.json = wrapReport(2000 + i, entries);
        samples.push_back(s);
    }

    // Adversarial edge cases: real injection techniques disguised with the
    // exact path/signature attributes of a whitelisted security product.
    // The non-whitelistable type boundary must still flag them.
    struct Adversary { const char* path; const char* signer; bool replaced; const char* label; };
    const Adversary adversaries[] = {
        {"C:\\Program Files\\TrustedAV\\avengine.dll", "TrustedAV Inc.", true,
         "hollowing disguised under a trusted AV path and valid signature"},
        {"C:\\Program Files\\TrustedAV\\avshellcode.bin", "TrustedAV Inc.", false,
         "shellcode disguised under a trusted AV path and valid signature"},
    };
    for (size_t a = 0; a < sizeof(adversaries) / sizeof(adversaries[0]); ++a) {
        Sample s;
        s.id = 100 + (int)a;
        s.malicious = true;
        s.label = adversaries[a].label;
        s.module_path = adversaries[a].path;
        s.signature = SIG_VALID;
        s.signer = adversaries[a].signer;

        std::vector<std::string> entries;
        if (adversaries[a].replaced) {
            entries.push_back(headersEntry(adversaries[a].path, true, true, 1));
        }
        else {
            entries.push_back(wrapEntry("workingset_scan", adversaries[a].path, 1));
        }
        s.json = wrapReport(3000 + (int)a, entries);
        samples.push_back(s);
    }
}

int main()
{
    std::vector<Sample> samples;
    addBenignAvScenarios(samples);
    addMaliciousScenarios(samples);
    if (samples.size() != 100) {
        std::printf("FATAL: corpus size is %zu, expected 100\n", samples.size());
        return 2;
    }

    // Production-equivalent whitelist: trusted AV/EDR vendors and install dirs.
    WhitelistEngine engine;
    std::vector<std::string> rules;
    rules.push_back("sig:path:C:\\Program Files\\TrustedAV");
    rules.push_back("sig:path:C:\\Program Files\\EndpointGuard");
    rules.push_back("strict:path:C:\\Windows\\System32\\drivers");
    rules.push_back("signer:TrustedAV Inc.");
    rules.push_back("signer:EndpointGuard Ltd.");
    rules.push_back("signer:Microsoft Corporation");
    engine.loadFromLines(rules);

    FakeSignatureVerifier verifier;
    for (size_t i = 0; i < samples.size(); ++i) {
        SignatureInfo info;
        info.state = samples[i].signature;
        info.signer = samples[i].signer;
        verifier.set(samples[i].module_path, info);
    }

    PostProcessor processor(engine, verifier, true);

    size_t benign_flagged_before = 0;   // historical FP count (all benign are flagged by pe-sieve)
    size_t benign_flagged_after = 0;    // remaining FP after whitelist
    size_t malicious_missed = 0;        // false negatives, must stay 0
    size_t malicious_caught = 0;
    std::map<t_inject_type, size_t> type_counts;
    std::map<t_inject_type, size_t> type_suppressed;

    for (size_t i = 0; i < samples.size(); ++i) {
        ProcessVerdict verdict;
        if (!processor.process(samples[i].json, verdict)) {
            std::printf("FATAL: failed to parse sample %d\n", samples[i].id);
            return 2;
        }
        const bool still_suspicious = verdict.countRemaining() > 0;
        const bool had_finding = !verdict.findings.empty();

        for (size_t f = 0; f < verdict.findings.size(); ++f) {
            const ModuleFinding& finding = verdict.findings[f];
            type_counts[finding.inject_type]++;
            if (finding.decision == WL_SIGNER_MATCH || finding.decision == WL_PATH_MATCH) {
                type_suppressed[finding.inject_type]++;
            }
        }

        if (!samples[i].malicious) {
            if (had_finding) ++benign_flagged_before;
            if (still_suspicious) ++benign_flagged_after;
        }
        else {
            if (still_suspicious) ++malicious_caught;
            else ++malicious_missed;
        }
    }

    size_t benign_total = 0;
    size_t malicious_total = 0;
    for (size_t i = 0; i < samples.size(); ++i) {
        if (samples[i].malicious) ++malicious_total;
        else ++benign_total;
    }
    const double fp_before = 100.0 * benign_flagged_before / benign_total;
    const double fp_after = 100.0 * benign_flagged_after / benign_total;
    const double fn_rate = 100.0 * malicious_missed / malicious_total;
    const double recall = 100.0 * malicious_caught / malicious_total;

    std::printf("================ HollowsHunter acceptance report ================\n");
    std::printf("Corpus: %zu samples (%zu benign security-software scenarios, %zu real injections)\n\n",
                samples.size(), benign_total, malicious_total);
    std::printf("False positives (benign processes reported as suspicious):\n");
    std::printf("  before whitelist : %zu/%zu  = %.1f%%\n", benign_flagged_before, benign_total, fp_before);
    std::printf("  after  whitelist : %zu/%zu  = %.1f%%\n", benign_flagged_after, benign_total, fp_after);
    std::printf("  reduction        : %.1f percentage points (%.1f%% relative drop)\n\n",
                fp_before - fp_after,
                benign_flagged_before ? 100.0 * (benign_flagged_before - benign_flagged_after) / benign_flagged_before : 0.0);
    std::printf("Real injections:\n");
    std::printf("  detected         : %zu/%zu = %.1f%% recall\n", malicious_caught, malicious_total, recall);
    std::printf("  missed (FN)      : %zu/%zu = %.1f%%  (acceptance requires 0.0%%)\n\n",
                malicious_missed, malicious_total, fn_rate);

    std::printf("Fine-grained injection type distribution and rationale:\n");
    for (int t = INJ_HOLLOWING; t < INJ_TYPES_COUNT; ++t) {
        std::map<t_inject_type, size_t>::iterator itr = type_counts.find((t_inject_type)t);
        if (itr == type_counts.end() || itr->second == 0) continue;
        const size_t suppressed = type_suppressed[(t_inject_type)t];
        std::printf("  %-18s count=%3zu  suppressed=%3zu  whitelistable=%-5s\n",
                    injectTypeName((t_inject_type)t), itr->second, suppressed,
                    isWhitelistable((t_inject_type)t) ? "yes" : "no");
        std::printf("      rationale: %s\n", injectTypeRationale((t_inject_type)t));
    }
    std::printf("==================================================================\n");

    const bool pass = (malicious_missed == 0) && (benign_flagged_after < benign_flagged_before);
    std::printf("RESULT: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
