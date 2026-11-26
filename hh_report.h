#pragma once

#include <time.h>

#include <windows.h>
#include <pe_sieve_api.h>
#include <map>
#include <vector>

#include "hh_params.h"

#include "whitelist/hh_types.h"

// Per-process whitelist audit entry, keyed by PID.
typedef struct hh_whitelist_audit {
    hh_white::ProcessVerdict verdict;
    bool was_suspicious = false;   // pe-sieve flagged the process before whitelisting
    bool remains_suspicious = false; // still reported after applying the whitelist
} t_hh_whitelist_audit;

class HHScanReport
{
public:
    HHScanReport(DWORD start_tick, time_t start_time)
        : startTick(start_tick), endTick(0),
        startTime(start_time), endTime(0)
    {
    }

    bool setEndTick(DWORD end_tick, time_t end_time)
    {
        if (end_tick < this->startTick) {
            return false;
        }
        this->endTick = end_tick;
        this->endTime = end_time;
        return true;
    }

    DWORD getScanTime() const
    {
        if (startTick == 0 || endTick == 0) return 0;
        return (this->endTick - this->startTick);
    }

    bool appendReport(pesieve::t_report &scan_report, const std::wstring &img_name);

    // Stores the fine-grained classification / whitelist audit for a process.
    // When the whitelist suppresses every finding of a previously suspicious
    // process, the PID is removed from the suspicious list (the raw pe-sieve
    // counters stay untouched for backward compatibility).
    void appendWhitelistAudit(DWORD pid, const hh_white::ProcessVerdict& verdict);
    const std::map<DWORD, t_hh_whitelist_audit>& getWhitelistAudits() const
    {
        return whitelistAudits;
    }

    size_t countReports(const pesieve::t_results_filter rfilter) const
    {
        if (rfilter == pesieve::SHOW_NONE) {
            return 0;
        }
        if (rfilter == pesieve::SHOW_ALL) {
            return countTotal(false);
        }
        if (rfilter == pesieve::SHOW_SUCCESSFUL_ONLY) {
            return countTotal(true);
        }
        size_t total = 0;
        if (rfilter & pesieve::SHOW_ERRORS) {
            total += failed.size();
        }
        if (rfilter & pesieve::SHOW_SUSPICIOUS) {
            total += suspicious.size();
        }
        return total;
    }

    size_t countTotal(bool successfulOnly = true) const
    {
        size_t total = pidToReport.size();
        if (successfulOnly) {
            total -= failed.size();
        }
        return total;
    }

    void toString(std::wstringstream &stream, const pesieve::t_results_filter rfilter);

protected:
    size_t reportsToString(std::wstringstream &stream, const pesieve::t_results_filter rfilter);

    size_t toJSON(std::wstringstream &stream, const t_hh_params &params);
    size_t reportsToJSON(std::wstringstream &stream, size_t level, const t_hh_params &params);

    time_t startTime;
    time_t endTime;

    DWORD startTick;
    DWORD endTick;

    std::map<DWORD, pesieve::t_report> pidToReport;
    std::map<DWORD, std::wstring> pidToName;
    std::vector<DWORD> suspicious;
    std::vector<DWORD> failed;
    std::map<DWORD, t_hh_whitelist_audit> whitelistAudits;
    friend class HHScanner;
};
