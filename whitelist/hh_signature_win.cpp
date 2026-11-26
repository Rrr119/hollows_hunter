#ifdef _WIN32

#include "hh_signature.h"

#include <vector>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace hh_white {

// Reads the signer subject name from the embedded catalog/PE certificate so
// that "signer:" rules can match without hashing or network access.
static std::string extractSignerName(const std::wstring& wide_path)
{
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, wide_path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            &encoding, &content_type, &format_type,
            &store, &message, nullptr)) {
        return "";
    }

    std::string signer;
    DWORD signer_size = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size) &&
        signer_size > 0) {
        std::vector<BYTE> buffer(signer_size);
        CMSG_SIGNER_INFO* signer_info = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.data());
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
                             signer_info, &signer_size)) {
            CERT_INFO cert_info;
            memset(&cert_info, 0, sizeof(cert_info));
            cert_info.Issuer = signer_info->Issuer;
            cert_info.SerialNumber = signer_info->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_FIND_SUBJECT_CERT, &cert_info, nullptr);
            if (cert) {
                DWORD name_len = CertGetNameStringA(
                    cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                if (name_len > 1) {
                    signer.resize(name_len);
                    CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                       nullptr, &signer[0], name_len);
                    signer.resize(name_len - 1); // drop terminating NUL
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return signer;
}

static std::wstring utf8ToWide(const std::string& utf8)
{
    if (utf8.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                   (int)utf8.size(), nullptr, 0);
    std::wstring wide(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(),
                        &wide[0], size);
    return wide;
}

SignatureInfo WinSignatureVerifier::verify(const std::string& file_path)
{
    SignatureInfo result;
    if (file_path.empty()) {
        result.state = SIG_NOT_CHECKED;
        return result;
    }
    std::wstring wide_path = utf8ToWide(file_path);

    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcFilePath = wide_path.c_str();

    GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust_data;
    memset(&trust_data, 0, sizeof(trust_data));
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(nullptr, &action_guid, &trust_data);

    if (status == ERROR_SUCCESS) {
        result.state = SIG_VALID;
        result.signer = extractSignerName(wide_path);
    }
    else if (status == TRUST_E_NOSIGNATURE ||
             status == TRUST_E_BAD_DIGEST ||
             status == CERT_E_UNTRUSTEDROOT ||
             status == TRUST_E_EXPLICIT_DISTRUST) {
        // NOSIGNATURE -> unsigned; any other failure means a signature exists
        // but cannot be trusted, which never grants a whitelist match.
        result.state = (status == TRUST_E_NOSIGNATURE) ? SIG_UNSIGNED : SIG_INVALID;
    }
    else {
        result.state = SIG_INVALID;
    }

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action_guid, &trust_data);
    return result;
}

} // namespace hh_white

#endif // _WIN32
