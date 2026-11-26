#include "hh_report_adapter.h"

namespace hh_white {

bool ReportAdapter::hasKey(const JsonValue& obj, const std::string& key)
{
    return obj.isObject() && obj.get(key) != nullptr;
}

bool ReportAdapter::parseModuleEntry(const JsonValue& entry, ModuleFinding& out)
{
    if (!entry.isObject()) {
        return false;
    }
    // Each entry of "scans" contains exactly one named block (headers_scan,
    // code_scan, iat_scan, workingset_scan, thread_scan, ...) and the shared
    // fields "status"/"module_file" live inside that block.
    if (entry.obj_val.empty()) {
        return false;
    }
    const std::string block_name = entry.obj_val.begin()->first;
    const JsonValue* block = &entry.obj_val.begin()->second;
    if (!block->isObject()) {
        return false;
    }
    out.status = (int)block->getNumber("status", 0);
    out.module_file = block->getString("module_file");

    const JsonValue* headers = (block_name == "headers_scan") ? block : nullptr;
    if (headers) {
        out.has_headers_scan = true;
        out.is_pe_replaced = headers->getBool("is_pe_replaced", false);
        out.hdr_modified =
            headers->getBool("dos_hdr_modified", false) ||
            headers->getBool("file_hdr_modified", false) ||
            headers->getBool("nt_hdr_modified", false) ||
            headers->getBool("sec_hdr_modified", false) ||
            headers->getBool("ep_modified", false);
    }

    const JsonValue* code = (block_name == "code_scan") ? block : nullptr;
    if (code) {
        out.has_code_scan = true;
    }

    const JsonValue* iat = (block_name == "iat_scan") ? block : nullptr;
    if (iat) {
        out.has_iat_scan = true;
    }

    const JsonValue* workingset = (block_name == "workingset_scan") ? block : nullptr;
    if (workingset) {
        out.has_workingset_scan = true;
    }

    const JsonValue* thread = (block_name == "thread_scan") ? block : nullptr;
    if (thread) {
        out.has_thread_scan = true;
    }

    const JsonValue* unreachable = (block_name == "unreachable_scan") ? block : nullptr;
    if (unreachable) {
        out.has_unreachable_scan = true;
    }

    if (block_name == "malformed_header") {
        out.has_malformed_header = true;
    }

    // Both the working-set scanner and the artefact scanner emit a
    // "workingset_scan" block. A manual-mapped PE is distinguished from raw
    // shellcode by "has_pe" (or the artefact scanner's "pe_artefacts" object).
    if (workingset) {
        if (workingset->getBool("has_pe", false) || hasKey(*workingset, "pe_artefacts")) {
            out.has_artefact_scan = true;
        }
    }

    return true;
}

bool ReportAdapter::fromPesieveJson(const std::string& json, ProcessVerdict& out)
{
    JsonValue root;
    if (!JsonParser::parse(json, root) || !root.isObject()) {
        return false;
    }
    out.pid = (uint32_t)root.getNumber("pid", 0);
    out.image_name = root.getString("main_image_path");

    const JsonValue* scans = root.get("scans");
    if (!scans || !scans->isArray()) {
        return true; // valid document, no modules
    }
    for (size_t i = 0; i < scans->arr_val.size(); ++i) {
        const JsonValue& entry = scans->arr_val[i];
        ModuleFinding finding;
        if (!parseModuleEntry(entry, finding)) {
            continue;
        }
        // SCAN_SUSPICIOUS == 1. Errors and clean modules stay out of the list.
        if (finding.status != 1) {
            continue;
        }
        out.findings.push_back(finding);
    }
    return true;
}

} // namespace hh_white
