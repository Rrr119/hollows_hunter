#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../hh_json.h"
#include "../hh_classifier.h"
#include "../hh_whitelist.h"
#include "../hh_report_adapter.h"
#include "../hh_postprocessor.h"
#include "../hh_output.h"

using namespace hh_white;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond) do { \
    ++g_checks; \
    if (!(cond)) { \
        ++g_failures; \
        std::printf("FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

#define CHECK_EQ(actual, expected) do { \
    ++g_checks; \
    auto _a = (actual); \
    auto _e = (expected); \
    if (!(_a == _e)) { \
        ++g_failures; \
        std::printf("FAIL [%s:%d]: %s => got %lld, expected %lld\n", \
            __FILE__, __LINE__, #actual, (long long)_a, (long long)_e); \
    } \
} while (0)

#define CHECK_STREQ(actual, expected) do { \
    ++g_checks; \
    std::string _a = (actual); \
    std::string _e = (expected); \
    if (_a != _e) { \
        ++g_failures; \
        std::printf("FAIL [%s:%d]: %s => got \"%s\", expected \"%s\"\n", \
            __FILE__, __LINE__, #actual, _a.c_str(), _e.c_str()); \
    } \
} while (0)

static void test_json_parser()
{
    const std::string text =
        "{\"pid\": 1234, \"flag\": true, \"name\": \"c:\\\\path\\\\file.dll\","
        "\"arr\": [1, 2, 3], \"nested\": {\"is_pe_replaced\": false, \"x\": null}}";
    JsonValue root;
    CHECK(JsonParser::parse(text, root));
    CHECK(root.isObject());
    CHECK_EQ(root.getNumber("pid"), 1234);
    CHECK(root.getBool("flag"));
    CHECK_STREQ(root.getString("name"), std::string("c:\\path\\file.dll"));
    const JsonValue* arr = root.get("arr");
    CHECK(arr && arr->isArray() && arr->arr_val.size() == 3);
    const JsonValue* nested = root.get("nested");
    CHECK(nested && nested->isObject());
    CHECK(!nested->getBool("is_pe_replaced", true));
    CHECK(nested->get("x") && nested->get("x")->type == JsonValue::J_NULL);

    JsonValue broken;
    CHECK(!JsonParser::parse("{\"a\": }", broken));
    CHECK(!JsonParser::parse("[1, 2,]", broken));
}

static ModuleFinding makeFinding(t_inject_type type)
{
    ModuleFinding f;
    f.status = 1;
    f.module_file = "C:\\Windows\\System32\\kernel32.dll";
    switch (type) {
    case INJ_HOLLOWING:
        f.has_headers_scan = true; f.is_pe_replaced = true; break;
    case INJ_IMPLANTED_PE:
        f.has_artefact_scan = true; break;
    case INJ_THREAD_SHELLCODE:
        f.has_thread_scan = true; break;
    case INJ_SHELLCODE:
        f.has_workingset_scan = true; break;
    case INJ_HEADER_MODIFIED:
        f.has_headers_scan = true; f.hdr_modified = true; break;
    case INJ_IAT_HOOK:
        f.has_iat_scan = true; break;
    case INJ_CODE_PATCH:
        f.has_code_scan = true; break;
    case INJ_UNREACHABLE_FILE:
        f.has_unreachable_scan = true; break;
    default: break;
    }
    return f;
}

static void test_classifier()
{
    for (int t = INJ_HOLLOWING; t < INJ_TYPES_COUNT; ++t) {
        ModuleFinding f = makeFinding((t_inject_type)t);
        CHECK_EQ((int)InjectClassifier::classify(f), t);
    }
    // Severity precedence: hollowing beats an accompanying code patch.
    ModuleFinding mixed = makeFinding(INJ_HOLLOWING);
    mixed.has_code_scan = true;
    CHECK_EQ((int)InjectClassifier::classify(mixed), (int)INJ_HOLLOWING);

    // High-confidence injection types must never be whitelistable.
    CHECK(!isWhitelistable(INJ_HOLLOWING));
    CHECK(!isWhitelistable(INJ_IMPLANTED_PE));
    CHECK(!isWhitelistable(INJ_SHELLCODE));
    CHECK(!isWhitelistable(INJ_THREAD_SHELLCODE));
    // Low-confidence AV-style indicators are whitelistable.
    CHECK(isWhitelistable(INJ_CODE_PATCH));
    CHECK(isWhitelistable(INJ_IAT_HOOK));
    CHECK(isWhitelistable(INJ_UNREACHABLE_FILE));
    CHECK(isWhitelistable(INJ_HEADER_MODIFIED));
}

static void test_path_normalization_and_glob()
{
    CHECK_STREQ(WhitelistEngine::normalizePath("C:/Program Files/AV/x.DLL"),
             std::string("c:\\program files\\av\\x.dll"));
    CHECK(WhitelistEngine::globMatch("c:\\windows\\*\\kernel32.dll",
                                     "c:\\windows\\system32\\kernel32.dll"));
    CHECK(!WhitelistEngine::globMatch("c:\\windows\\*.dll",
                                      "c:\\temp\\x.dll"));
    CHECK(WhitelistEngine::globMatch("*avengine*", "c:\\program files\\av\\avengine64.dll"));
}

static void test_whitelist_rules()
{
    WhitelistEngine engine;
    std::vector<std::string> lines;
    lines.push_back("# comment line");
    lines.push_back("signer:Microsoft Corporation");
    lines.push_back("path:C:\\Program Files\\TrustedAV");
    lines.push_back("sig:path:C:\\Windows\\System32");
    lines.push_back("strict:path:C:\\Program Files\\EDR");
    const size_t loaded = engine.loadFromLines(lines);
    CHECK_EQ(loaded, (size_t)4);

    // Signer match on a code patch: suppressible.
    {
        ModuleFinding f = makeFinding(INJ_CODE_PATCH);
        f.signature = SIG_VALID;
        f.signer_name = "Microsoft Corporation";
        WhitelistRule rule;
        std::string raw;
        // locate the signer rule
        for (size_t i = 0; i < engine.getRules().size(); ++i) {
            if (!engine.getRules()[i].signer.empty()) {
                rule = engine.getRules()[i];
                break;
            }
        }
        CHECK_EQ((int)engine.evaluate(f, rule), (int)WL_SIGNER_MATCH);
    }

    // Path prefix match.
    {
        ModuleFinding f = makeFinding(INJ_IAT_HOOK);
        f.module_file = "C:\\Program Files\\TrustedAV\\sub\\avhook.dll";
        WhitelistRule rule;
        for (size_t i = 0; i < engine.getRules().size(); ++i) {
            if (engine.getRules()[i].path == "c:\\program files\\trustedav") {
                rule = engine.getRules()[i];
                break;
            }
        }
        CHECK_EQ((int)engine.evaluate(f, rule), (int)WL_PATH_MATCH);
    }

    // sig: scope rejects an unsigned module even when the path matches.
    {
        ModuleFinding f = makeFinding(INJ_CODE_PATCH);
        f.signature = SIG_UNSIGNED;
        f.module_file = "C:\\Windows\\System32\\fake.dll";
        WhitelistRule rule;
        for (size_t i = 0; i < engine.getRules().size(); ++i) {
            if (engine.getRules()[i].require_valid_sig) {
                rule = engine.getRules()[i];
                break;
            }
        }
        CHECK_EQ((int)engine.evaluate(f, rule), (int)WL_RULE_DISABLED);
    }

    // A high-confidence injection can never be suppressed.
    {
        ProcessVerdict verdict;
        verdict.findings.push_back(makeFinding(INJ_HOLLOWING));
        verdict.findings[0].signature = SIG_VALID;
        verdict.findings[0].signer_name = "Microsoft Corporation";
        verdict.findings[0].module_file = "C:\\Program Files\\TrustedAV\\x.exe";
        InjectClassifier::classifyAll(verdict);
        engine.apply(verdict);
        CHECK_EQ((int)verdict.findings[0].decision, (int)WL_NOT_WHITELISTED);
        CHECK_EQ(verdict.countRemaining(), (size_t)1);
        CHECK_EQ(verdict.countSuppressed(), (size_t)0);
    }
}

static void test_adapter_and_pipeline()
{
    // One hollowing (must stay) + one AV code patch (whitelistable).
    const std::string json =
        "{\n"
        "  \"pid\" : 4321,\n"
        "  \"main_image_path\" : \"c:\\\\target\\\\app.exe\",\n"
        "  \"scans\" : [\n"
        "    {\"headers_scan\" : {\"status\" : 1, \"module_file\" : \"c:\\\\target\\\\app.exe\",\n"
        "      \"is_pe_replaced\" : true}},\n"
        "    {\"code_scan\" : {\"status\" : 1, \"module_file\" : \"c:\\\\program files\\\\tav\\\\av.dll\"}},\n"
        "    {\"headers_scan\" : {\"status\" : 0, \"module_file\" : \"c:\\\\windows\\\\ntdll.dll\",\n"
        "      \"is_pe_replaced\" : false}}\n"
        "  ]\n"
        "}\n";

    ProcessVerdict verdict;
    CHECK(ReportAdapter::fromPesieveJson(json, verdict));
    CHECK_EQ(verdict.pid, (uint32_t)4321);
    CHECK_EQ(verdict.findings.size(), (size_t)2); // only suspicious entries
    InjectClassifier::classifyAll(verdict);
    CHECK_EQ((int)verdict.findings[0].inject_type, (int)INJ_HOLLOWING);
    CHECK_EQ((int)verdict.findings[1].inject_type, (int)INJ_CODE_PATCH);

    WhitelistEngine engine;
    engine.loadFromLines(std::vector<std::string>(1, "path:C:\\Program Files\\TAV"));
    FakeSignatureVerifier verifier;
    SignatureInfo valid;
    valid.state = SIG_VALID;
    valid.signer = "Trusted AV Ltd";
    verifier.set("c:\\program files\\tav\\av.dll", valid);

    PostProcessor processor(engine, verifier, true);
    ProcessVerdict processed;
    CHECK(processor.process(json, processed));
    CHECK_EQ(processed.countSuppressed(), (size_t)1);
    CHECK_EQ(processed.countRemaining(), (size_t)1); // hollowing remains

    const std::string out = EnhancedOutput::verdictToJson(processed, 0);
    CHECK(out.find("\"inject_type\" : \"hollowing\"") != std::string::npos);
    CHECK(out.find("\"whitelist_decision\" : \"path_match\"") != std::string::npos);
    CHECK(out.find("\"rationale\"") != std::string::npos);

    // Manual-mapped PE via workingset has_pe must classify as implanted_pe and
    // is never whitelistable.
    const std::string pe_json =
        "{\"pid\":9,\"scans\":[{\"workingset_scan\":{\"status\":1,"
        "\"module_file\":\"c:\\\\tmp\\\\m.bin\",\"has_pe\":true,\"has_shellcode\":false}}]}";
    ProcessVerdict pe_verdict;
    CHECK(ReportAdapter::fromPesieveJson(pe_json, pe_verdict));
    CHECK_EQ(pe_verdict.findings.size(), (size_t)1);
    InjectClassifier::classifyAll(pe_verdict);
    CHECK_EQ((int)pe_verdict.findings[0].inject_type, (int)INJ_IMPLANTED_PE);
    CHECK(!isWhitelistable(INJ_IMPLANTED_PE));
}

int main()
{
    test_json_parser();
    test_classifier();
    test_path_normalization_and_glob();
    test_whitelist_rules();
    test_adapter_and_pipeline();

    std::printf("\nUnit tests: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
