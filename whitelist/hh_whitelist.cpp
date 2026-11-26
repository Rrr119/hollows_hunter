#include "hh_whitelist.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace hh_white {

std::string WhitelistEngine::toLower(const std::string& s)
{
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return char(std::tolower(c)); });
    return out;
}

std::string WhitelistEngine::normalizePath(const std::string& path)
{
    std::string out = toLower(path);
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] == '/') out[i] = '\\';
    }
    // collapse duplicate backslashes
    std::string collapsed;
    collapsed.reserve(out.size());
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] == '\\' && !collapsed.empty() && collapsed.back() == '\\') {
            continue;
        }
        collapsed.push_back(out[i]);
    }
    return collapsed;
}

// Glob supporting '*' (any run) and '?' (single char). Both inputs are already
// lower-cased. Implemented iteratively to avoid recursion depth issues.
bool WhitelistEngine::globMatch(const std::string& pattern, const std::string& text)
{
    size_t p = 0, t = 0;
    size_t star = std::string::npos, mark = 0;
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == text[t])) {
            ++p;
            ++t;
        }
        else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            mark = t;
        }
        else if (star != std::string::npos) {
            p = star + 1;
            t = ++mark;
        }
        else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

static std::string trim(const std::string& s)
{
    size_t begin = 0;
    while (begin < s.size() && std::isspace((unsigned char)s[begin])) ++begin;
    size_t end = s.size();
    while (end > begin && std::isspace((unsigned char)s[end - 1])) --end;
    return s.substr(begin, end - begin);
}

static std::string fileNameOf(const std::string& path)
{
    size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

bool WhitelistEngine::parseLine(const std::string& raw_line, WhitelistRule& out) const
{
    std::string line = trim(raw_line);
    if (line.empty() || line[0] == '#') {
        return false; // comment or blank
    }
    out.raw = line;

    // Optional scope prefixes, most specific first.
    if (line.rfind("strict:", 0) == 0) {
        out.strict = true;
        line = line.substr(7);
    }
    else if (line.rfind("sig:", 0) == 0) {
        out.require_valid_sig = true;
        line = line.substr(4);
    }
    else if (line.rfind("nosig:", 0) == 0) {
        out.require_no_sig = true;
        line = line.substr(6);
    }

    if (line.rfind("signer:", 0) == 0) {
        out.signer = toLower(trim(line.substr(7)));
    }
    else if (line.rfind("path:", 0) == 0) {
        out.path = normalizePath(trim(line.substr(5)));
    }
    else if (line.rfind("name:", 0) == 0) {
        out.name = toLower(trim(line.substr(5)));
    }
    else {
        return false; // unknown directive
    }
    return !out.empty();
}

size_t WhitelistEngine::loadFromLines(const std::vector<std::string>& lines)
{
    rules.clear();
    size_t loaded = 0;
    for (size_t i = 0; i < lines.size(); ++i) {
        WhitelistRule rule;
        if (parseLine(lines[i], rule)) {
            rules.push_back(rule);
            ++loaded;
        }
    }
    return loaded;
}

size_t WhitelistEngine::loadFromFile(const std::string& file_path)
{
    std::ifstream input(file_path.c_str());
    if (!input.is_open()) {
        return 0;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }
    return loadFromLines(lines);
}

bool WhitelistEngine::ruleScopeOk(const ModuleFinding& finding,
                                  const WhitelistRule& rule) const
{
    if (rule.require_valid_sig && finding.signature != SIG_VALID) {
        return false;
    }
    if (rule.require_no_sig && finding.signature == SIG_VALID) {
        return false;
    }
    if (rule.strict) {
        // strict rules demand a positively verified signature in every case.
        if (finding.signature != SIG_VALID) {
            return false;
        }
    }
    return true;
}

bool WhitelistEngine::ruleTargetMatch(const ModuleFinding& finding,
                                      const WhitelistRule& rule) const
{
    const std::string mod_path = normalizePath(finding.module_file);
    bool matched_any = false;

    if (!rule.signer.empty()) {
        if (toLower(finding.signer_name).find(rule.signer) == std::string::npos) {
            return false;
        }
        matched_any = true;
    }
    if (!rule.path.empty()) {
        // Prefix match on the directory, or glob when wildcards are present.
        bool path_ok;
        if (rule.path.find_first_of("*?") != std::string::npos) {
            path_ok = globMatch(rule.path, mod_path);
        }
        else {
            const std::string prefix =
                rule.path.back() == '\\' ? rule.path : rule.path + "\\";
            path_ok = (mod_path.compare(0, prefix.size(), prefix) == 0)
                   || (mod_path == rule.path);
        }
        if (!path_ok) {
            return false;
        }
        matched_any = true;
    }
    if (!rule.name.empty()) {
        if (toLower(fileNameOf(finding.module_file)) != rule.name) {
            return false;
        }
        matched_any = true;
    }
    return matched_any;
}

t_whitelist_decision WhitelistEngine::evaluate(const ModuleFinding& finding,
                                               const WhitelistRule& rule) const
{
    if (!ruleTargetMatch(finding, rule)) {
        return WL_NOT_WHITELISTED;
    }
    if (!ruleScopeOk(finding, rule)) {
        return WL_RULE_DISABLED;
    }
    if (!rule.signer.empty()) {
        return WL_SIGNER_MATCH;
    }
    return WL_PATH_MATCH;
}

void WhitelistEngine::apply(ProcessVerdict& verdict) const
{
    for (size_t i = 0; i < verdict.findings.size(); ++i) {
        ModuleFinding& finding = verdict.findings[i];

        // Hard safety boundary: high-confidence injections are never suppressed.
        if (!isWhitelistable(finding.inject_type)) {
            finding.decision = WL_NOT_WHITELISTED;
            continue;
        }
        for (size_t r = 0; r < rules.size(); ++r) {
            const WhitelistRule& rule = rules[r];
            t_whitelist_decision decision = evaluate(finding, rule);
            if (decision == WL_SIGNER_MATCH || decision == WL_PATH_MATCH) {
                finding.decision = decision;
                finding.matched_rule = rule.raw;
                break;
            }
            if (decision == WL_RULE_DISABLED && finding.decision == WL_NOT_WHITELISTED) {
                // Remember that a target matched but its signature scope failed,
                // so the audit trail can explain why it stayed suspicious.
                finding.decision = WL_RULE_DISABLED;
                finding.matched_rule = rule.raw;
            }
        }
    }
}

} // namespace hh_white
