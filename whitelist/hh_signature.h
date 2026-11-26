#pragma once

#include <string>
#include <map>

#include "hh_types.h"
#include "hh_whitelist.h"

namespace hh_white {

struct SignatureInfo {
    t_signature_state state;
    std::string signer; // certificate subject common name, UTF-8

    SignatureInfo() : state(SIG_NOT_CHECKED) {}
};

// Abstraction over Authenticode verification so the decision logic can be
// unit tested with a fake verifier while production uses WinVerifyTrust.
class SignatureVerifier {
public:
    virtual ~SignatureVerifier() {}
    virtual SignatureInfo verify(const std::string& file_path) = 0;
};

// Off-Windows / unit-test verifier returning pre-canned answers keyed by path.
class FakeSignatureVerifier : public SignatureVerifier {
public:
    void set(const std::string& normalized_path, const SignatureInfo& info)
    {
        store[WhitelistEngine::normalizePath(normalized_path)] = info;
    }

    SignatureInfo verify(const std::string& file_path) override
    {
        std::map<std::string, SignatureInfo>::const_iterator itr =
            store.find(WhitelistEngine::normalizePath(file_path));
        if (itr == store.end()) {
            SignatureInfo unknown;
            unknown.state = SIG_NOT_CHECKED;
            return unknown;
        }
        return itr->second;
    }

private:
    std::map<std::string, SignatureInfo> store;
};

#ifdef _WIN32
// Production verifier backed by the WinVerifyTrust Authenticode API.
class WinSignatureVerifier : public SignatureVerifier {
public:
    SignatureInfo verify(const std::string& file_path) override;
};
#endif

} // namespace hh_white
