#pragma once

#include <string>

#include "hh_types.h"
#include "hh_json.h"

namespace hh_white {

// Converts the per-process JSON emitted by PESieve_scan_ex(REPORT_SCANNED)
// into the internal ProcessVerdict model. Only suspicious modules
// (status == SCAN_SUSPICIOUS, i.e. 1) are materialized, mirroring the way
// HollowsHunter currently consumes pe-sieve results.
class ReportAdapter {
public:
    // Parses one PE-sieve JSON document. Returns false if the document does
    // not contain the expected structure.
    static bool fromPesieveJson(const std::string& json, ProcessVerdict& out);

    // Converts a single entry of the top-level "scans" array.
    static bool parseModuleEntry(const JsonValue& entry, ModuleFinding& out);

private:
    static bool hasKey(const JsonValue& obj, const std::string& key);
};

} // namespace hh_white
