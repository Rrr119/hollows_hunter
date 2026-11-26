#include "hh_output.h"

#include <cstdio>
#include <sstream>

namespace hh_white {

static std::string jsonEscape(const std::string& input)
{
    std::string out;
    out.reserve(input.size() + 8);
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char buffer[8];
                snprintf(buffer, sizeof(buffer), "\\u%04x", (unsigned char)c);
                out += buffer;
            }
            else {
                out.push_back(c);
            }
        }
    }
    return out;
}

void EnhancedOutput::pad(std::string& out, size_t level)
{
    out.append(level * 4, ' ');
}

std::string EnhancedOutput::findingToJson(const ModuleFinding& finding, size_t level)
{
    std::string out;
    pad(out, level);
    out += "{\n";

    pad(out, level + 1);
    out += "\"module_file\" : \"" + jsonEscape(finding.module_file) + "\",\n";
    pad(out, level + 1);
    out += std::string("\"inject_type\" : \"") + injectTypeName(finding.inject_type) + "\",\n";
    pad(out, level + 1);
    out += std::string("\"inject_type_id\" : ") +
           std::to_string((int)finding.inject_type) + ",\n";
    pad(out, level + 1);
    out += std::string("\"whitelistable\" : ") +
           (isWhitelistable(finding.inject_type) ? "true" : "false") + ",\n";
    pad(out, level + 1);
    out += std::string("\"signature\" : \"") +
           signatureStateName(finding.signature) + "\",\n";
    pad(out, level + 1);
    out += "\"signer\" : \"" + jsonEscape(finding.signer_name) + "\",\n";
    pad(out, level + 1);
    out += std::string("\"whitelist_decision\" : \"") +
           whitelistDecisionName(finding.decision) + "\",\n";
    pad(out, level + 1);
    out += "\"matched_rule\" : \"" + jsonEscape(finding.matched_rule) + "\",\n";
    pad(out, level + 1);
    out += std::string("\"suppressed\" : ") +
           ((finding.decision == WL_SIGNER_MATCH ||
             finding.decision == WL_PATH_MATCH) ? "true" : "false") + ",\n";
    pad(out, level + 1);
    out += "\"rationale\" : \"" +
           jsonEscape(injectTypeRationale(finding.inject_type)) + "\"\n";

    pad(out, level);
    out += "}";
    return out;
}

std::string EnhancedOutput::verdictToJson(const ProcessVerdict& verdict, size_t level)
{
    std::string out;
    pad(out, level);
    out += "{\n";
    pad(out, level + 1);
    out += "\"pid\" : " + std::to_string(verdict.pid) + ",\n";
    pad(out, level + 1);
    out += "\"image\" : \"" + jsonEscape(verdict.image_name) + "\",\n";
    pad(out, level + 1);
    out += "\"findings_total\" : " +
           std::to_string(verdict.findings.size()) + ",\n";
    pad(out, level + 1);
    out += "\"findings_remaining\" : " +
           std::to_string(verdict.countRemaining()) + ",\n";
    pad(out, level + 1);
    out += "\"findings_suppressed\" : " +
           std::to_string(verdict.countSuppressed()) + ",\n";

    pad(out, level + 1);
    out += "\"findings\" : [\n";
    for (size_t i = 0; i < verdict.findings.size(); ++i) {
        out += findingToJson(verdict.findings[i], level + 2);
        if (i + 1 < verdict.findings.size()) out += ",";
        out += "\n";
    }
    pad(out, level + 1);
    out += "]\n";
    pad(out, level);
    out += "}";
    return out;
}

std::string EnhancedOutput::verdictToText(const ProcessVerdict& verdict)
{
    std::stringstream stream;
    for (size_t i = 0; i < verdict.findings.size(); ++i) {
        const ModuleFinding& finding = verdict.findings[i];
        const bool suppressed =
            finding.decision == WL_SIGNER_MATCH || finding.decision == WL_PATH_MATCH;
        stream << "    [" << (suppressed ? "WHITELISTED" : "SUSPICIOUS") << "] "
               << injectTypeName(finding.inject_type)
               << " (" << signatureStateName(finding.signature)
               << ") " << finding.module_file;
        if (suppressed) {
            stream << "  <- " << whitelistDecisionName(finding.decision)
                   << " rule: " << finding.matched_rule;
        }
        else if (finding.decision == WL_RULE_DISABLED) {
            stream << "  <- rule target matched but signature scope rejected: "
                   << finding.matched_rule;
        }
        stream << "\n";
    }
    return stream.str();
}

} // namespace hh_white
