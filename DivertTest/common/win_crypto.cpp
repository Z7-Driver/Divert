#include "common_head.h"
#include "win_crypto.h"





namespace common {

    // ntstatus.h conflicts with windows.h so define this locally.
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

    WinCrypto::~WinCrypto() {
        for (auto& alg_handle_pair : alg_handles_) {
            ::BCryptCloseAlgorithmProvider(alg_handle_pair.second, 0);
        }
    }

    bool WinCrypto::CertGetNameStringUtil(PCCERT_CONTEXT cert_context, DWORD name_type, DWORD flags, void* type_param, std::wstring* name) {
        DWORD name_size = ::CertGetNameStringW(cert_context, name_type, flags, type_param, NULL, 0);
        if (name_size <= 1) {
            return false;
        }
        name->resize(name_size, 0);
        name_size = ::CertGetNameStringW(cert_context, name_type, flags, type_param, (LPWSTR)name->data(), name_size);
        name->pop_back();
        return true;
    }

    bool WinCrypto::BinaryStringEncode(BinaryStringCodeType code_type, const BYTE* binary_bytes, DWORD binary_bytes_size, std::string* str_out) {
        DWORD flags = 0;
        switch (code_type)
        {
        case BINARY_STRING_CODE_HEX:
            flags = CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF;
            break;
        case BINARY_STRING_CODE_BASE64:
            flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
            break;
        case BINARY_STRING_CODE_PEM:
            flags = CRYPT_STRING_BASE64HEADER | CRYPT_STRING_NOCR;
            break;
        default:
            return false;
        }
        DWORD str_size = 0;
        if (!::CryptBinaryToStringA(binary_bytes, binary_bytes_size, flags, NULL, &str_size)) {
            return false;
        }
        if (str_size == 0) {
            return false;
        }
        str_out->resize(str_size, 0);
        if (!::CryptBinaryToStringA(binary_bytes, binary_bytes_size, flags, (LPSTR)str_out->data(), &str_size)) {
            return false;
        }
        str_out->pop_back();
        return true;
    }
    bool WinCrypto::BinaryStringDecode(BinaryStringCodeType code_type, LPCSTR in_str, DWORD in_str_size, std::vector<BYTE>* binary_out) {
        DWORD flags = 0;
        switch (code_type)
        {
        case BINARY_STRING_CODE_HEX:
            flags = CRYPT_STRING_HEXRAW;
            break;
        case BINARY_STRING_CODE_BASE64:
            flags = CRYPT_STRING_BASE64;
            break;
        case BINARY_STRING_CODE_PEM:
            flags = CRYPT_STRING_BASE64HEADER;
            break;
        default:
            return false;
        }
        DWORD binary_size = 0;
        if (!::CryptStringToBinaryA(in_str, in_str_size, flags, NULL, &binary_size, NULL, NULL)) {
            return false;
        }
        if (binary_size == 0) {
            return false;
        }
        binary_out->resize(binary_size, 0);
        if (!::CryptStringToBinaryA(in_str, in_str_size, flags, binary_out->data(), &binary_size, NULL, NULL)) {
            return false;
        }
        return true;
    }

    //using LocalFree(*key_out) if do not need it any more.
    bool WinCrypto::ParsePKIXPublicKey(const BYTE* encoded_key, DWORD encoded_key_size, PCERT_PUBLIC_KEY_INFO* key_out) {
        PCERT_PUBLIC_KEY_INFO decoded_pub_key = nullptr;
        DWORD decoded_pub_key_size = 0;
        BOOL ret = ::CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, encoded_key, encoded_key_size, CRYPT_DECODE_ALLOC_FLAG, NULL, &decoded_pub_key, &decoded_pub_key_size);
        if (!ret) {
            return false;
        }
        if (!decoded_pub_key || decoded_pub_key_size == 0) {
            return false;
        }
        *key_out = decoded_pub_key;
        return true;
    }

    //certificate is encoded in base64 in param certs
    bool WinCrypto::GetSystemTrustedRootCerts(bool machine_store, std::list<std::vector<unsigned char>>* certs) {
        HCERTSTORE cert_store = NULL;
        if (machine_store) {

        }
        else {
            cert_store = ::CertOpenSystemStoreW(NULL, L"ROOT");
        }
        if (!cert_store) {
            return false;
        }

        PCCERT_CONTEXT cert_context = ::CertEnumCertificatesInStore(cert_store, NULL);
        while (true)
        {
            if (!cert_context) {
                break;
            }
            std::vector<unsigned char> cert_bytes(cert_context->cbCertEncoded, 0);
            memcpy(cert_bytes.data(), cert_context->pbCertEncoded, cert_context->cbCertEncoded);
            certs->push_back(cert_bytes);
            cert_context = ::CertEnumCertificatesInStore(cert_store, cert_context);
        }

        ::CertCloseStore(cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
        if (certs->size() == 0) {
            return false;
        }
        return true;
    }

    bool WinCrypto::GetEmbedSignInfo(LPCWSTR file_path, bool verify_signature, std::list<SignInfo>* sign_info_list) {

        bool ret = false;
        HCERTSTORE cert_store = NULL;
        HCRYPTMSG crypt_msg = NULL;
        DWORD encoding_type = 0;
        DWORD content_type = 0;
        DWORD format_type = 0;
        do
        {
            if (!::CryptQueryObject(CERT_QUERY_OBJECT_FILE, file_path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                &encoding_type, &content_type, &format_type, &cert_store, &crypt_msg, NULL)) {
                break;
            }
            if (CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED != content_type ||
                NULL == cert_store ||
                NULL == crypt_msg) {
                break;
            }

            DWORD msg_data_size = 4;
            DWORD signer_count = 0;
            if (!::CryptMsgGetParam(crypt_msg, CMSG_SIGNER_COUNT_PARAM, 0, &signer_count, &msg_data_size)) {
                break;
            }
            if (signer_count == 0) {
                break;
            }
            bool loop_signer_error = false;
            for (DWORD i = 0; i < signer_count; i++) {
                msg_data_size = 0;
                if (!::CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, i, NULL, &msg_data_size)) {
                    loop_signer_error = true;
                    break;
                }
                std::vector<BYTE> msg_data_buf(msg_data_size, 0);
                if (!::CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, i, msg_data_buf.data(), &msg_data_size)) {
                    loop_signer_error = true;
                    break;
                }
                PCMSG_SIGNER_INFO msg_signer_info = (PCMSG_SIGNER_INFO)msg_data_buf.data();
                CERT_INFO signer_cert_info;
                signer_cert_info.Issuer = msg_signer_info->Issuer;
                signer_cert_info.SerialNumber = msg_signer_info->SerialNumber;
                PCCERT_CONTEXT signer_cert = ::CertFindCertificateInStore(cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &signer_cert_info, NULL);
                if (!signer_cert) {
                    loop_signer_error = true;
                    break;
                }
                SignInfo sign_info;
                if (!CertGetNameStringUtil(signer_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &sign_info.signer_name)) {
                    loop_signer_error = true;
                }
                if (!CertGetNameStringUtil(signer_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, &sign_info.signer_issuer_name)) {
                    loop_signer_error = true;
                }
                ::CertFreeCertificateContext(signer_cert);
                if (loop_signer_error) {
                    break;
                }

                sign_info_list->push_back(sign_info);
            }
            if (loop_signer_error) {
                break;
            }
            ret = true;
        } while (false);
        if (sign_info_list->size() == 0) {
            ret = false;
        }

        if (cert_store) {
            ::CertCloseStore(cert_store, 0);
        }
        if (crypt_msg) {
            ::CryptMsgClose(crypt_msg);
        }
        return ret;
    }

    bool WinCrypto::VerifyPESignature(LPCWSTR file_path) {
        WINTRUST_FILE_INFO file_info;
        memset(&file_info, 0, sizeof(WINTRUST_FILE_INFO));
        file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
        file_info.pcwszFilePath = file_path;
        file_info.hFile = NULL;
        file_info.pgKnownSubject = NULL;


        WINTRUST_DATA trust_data;
        memset(&trust_data, 0, sizeof(WINTRUST_DATA));
        trust_data.cbStruct = sizeof(WINTRUST_DATA);
        trust_data.pPolicyCallbackData = NULL;
        trust_data.pSIPClientData = NULL;
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.pFile = &file_info;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.hWVTStateData = NULL;
        trust_data.pwszURLReference = NULL;
        trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        trust_data.dwUIContext = 0;
        GUID wvt_policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG verified = ::WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &wvt_policy_guid, &trust_data);
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &wvt_policy_guid, &trust_data);
        if (0 == verified) {
            return true;
        }
        return false;
    }

    bool WinCrypto::OpenAlgProvider(LPCWSTR alg_id, LPCWSTR implementation, ULONG flags) {
        BCRYPT_ALG_HANDLE alg_handle;
        if (STATUS_SUCCESS != ::BCryptOpenAlgorithmProvider(&alg_handle, alg_id, implementation, flags)) {
            return false;
        }

        auto alg_find = alg_handles_.find(alg_id);
        if (alg_handles_.end() == alg_find) {
            alg_handles_[alg_id] = alg_handle;
        }
        else {
            ::BCryptCloseAlgorithmProvider(alg_handle, 0);
        }

        return true;
    }

    bool WinCrypto::Init(const std::vector<AlgProviderInfo>& alg_prov_vec) {
        for (auto& alg_prov_info : alg_prov_vec) {
            LPCWSTR alg_imple = MS_PRIMITIVE_PROVIDER;
            if (!alg_prov_info.implementation.empty()) {
                alg_imple = alg_prov_info.implementation.c_str();
            }
            if (!OpenAlgProvider(alg_prov_info.alg_id.c_str(), alg_imple, alg_prov_info.flags)) {
                return false;
            }
        }
        return true;
    }

    WinCrypto::HashHandle* WinCrypto::CreateHash(LPCWSTR hash_alg) {
        auto alg_find = alg_handles_.find(hash_alg);
        if (alg_handles_.end() == alg_find) {
            return nullptr;
        }
        ULONG prop_result_size = 0;
        DWORD hash_object_size = 0;
        DWORD hash_length = 0;
        if (STATUS_SUCCESS != ::BCryptGetProperty(alg_find->second, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_size, sizeof(DWORD), &prop_result_size, 0)) {
            return nullptr;
        }
        prop_result_size = 0;
        if (STATUS_SUCCESS != ::BCryptGetProperty(alg_find->second, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_length, sizeof(DWORD), &prop_result_size, 0)) {
            return nullptr;
        }

        HashHandle* handle = new HashHandle;
        handle->hash_handle = NULL;
        handle->hash_object_buf.resize(hash_object_size, 0);
        handle->hash_buf.resize(hash_length, 0);
        if (STATUS_SUCCESS != ::BCryptCreateHash(alg_find->second, &(handle->hash_handle), &(handle->hash_object_buf[0]), handle->hash_object_buf.size(), NULL, 0, 0)) {
            delete handle;
            return nullptr;
        }
        return handle;
    }

    bool WinCrypto::HashData(HashHandle* hash_handle, PUCHAR data, ULONG data_size) {
        if (STATUS_SUCCESS != ::BCryptHashData(hash_handle->hash_handle, data, data_size, 0)) {
            return false;
        }
        return true;
    }

    bool WinCrypto::FinishHash(HashHandle* hash_handle, std::vector<UCHAR>* hash) {
        bool ret = true;
        if (STATUS_SUCCESS != ::BCryptFinishHash(hash_handle->hash_handle, &(hash_handle->hash_buf[0]), hash_handle->hash_buf.size(), 0)) {
            ret = false;
        }
        else {
            *hash = hash_handle->hash_buf;
        }
        if (NULL != hash_handle->hash_handle) {
            ::BCryptDestroyHash(hash_handle->hash_handle);
        }
        delete hash_handle;
        return ret;
    }

    bool WinCrypto::Hash(LPCWSTR hash_alg, const void* data, size_t data_size, std::vector<UCHAR>* hash) {
        HashHandle* handle = CreateHash(hash_alg);
        if (!handle) {
            return false;
        }
        bool hash_data = HashData(handle, (PUCHAR)data, data_size);
        bool hash_finish = FinishHash(handle, hash);

        return (hash_data && hash_finish);
    }

    std::string WinCrypto::Hash(LPCWSTR hash_alg, const void* data, size_t data_size) {
        std::vector<UCHAR> hash;
        if (!Hash(hash_alg, data, data_size, &hash)) {
            return "";
        }
        std::string hex_str;
        if (!BinaryStringEncode(BINARY_STRING_CODE_HEX, hash.data(), hash.size(), &hex_str)) {
            return "";
        }
        return hex_str;
    }

    bool WinCrypto::HashFile(LPCWSTR hash_alg, const wchar_t* file_path, std::vector<UCHAR>* hash) {
        HashHandle* hash_handle = CreateHash(hash_alg);
        if (!hash_handle) {
            return "";
        }

        bool compute_hash_success = false;
        HANDLE file_handle = ::CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE != file_handle) {
            const size_t read_buf_size = 1024 * 1024;
            std::vector<char> read_buf(read_buf_size, 0);
            while (true)
            {
                DWORD bytes_read = 0;
                if (!::ReadFile(file_handle, &read_buf[0], read_buf_size, &bytes_read, NULL)) {
                    break;
                }
                if (0 == bytes_read) {
                    //reach end of file
                    compute_hash_success = true;
                    break;
                }
                if (!HashData(hash_handle, (PUCHAR)&read_buf[0], bytes_read)) {
                    break;
                }
            }
            ::CloseHandle(file_handle);
        }

        bool hash_finish = FinishHash(hash_handle, hash);
        return (compute_hash_success && hash_finish);
    }

    std::string WinCrypto::HashFile(LPCWSTR hash_alg, const wchar_t* file_path) {
        std::vector<UCHAR> hash_buf;
        if (!HashFile(hash_alg, file_path, &hash_buf)) {
            return "";
        }
        std::string hex_str;
        if (!BinaryStringEncode(BINARY_STRING_CODE_HEX, hash_buf.data(), hash_buf.size(), &hex_str)) {
            return "";
        }
        return hex_str;
    }


    BCRYPT_KEY_HANDLE WinCrypto::ImportECCKey(LPCWSTR alg_id, ULONG blob_magic, ULONG key_length, BYTE* x, BYTE* y, BYTE* d, bool is_private_key) {
        auto alg_find = alg_handles_.find(alg_id);
        if (alg_handles_.end() == alg_find) {
            return NULL;
        }
        BCRYPT_ECCKEY_BLOB blob_header = { 0 };
        blob_header.dwMagic = blob_magic;
        blob_header.cbKey = key_length;
        size_t blob_size = sizeof(BCRYPT_ECCKEY_BLOB) + (key_length * 2);
        if (is_private_key) {
            blob_size += key_length;
        }
        std::vector<BYTE> blob_buf(blob_size, 0);
        size_t blob_index = 0;
        memcpy(&blob_buf[blob_index], &blob_header, sizeof(blob_header));
        blob_index += sizeof(blob_header);
        memcpy(&blob_buf[blob_index], x, key_length);
        blob_index += key_length;
        memcpy(&blob_buf[blob_index], y, key_length);
        if (is_private_key) {
            blob_index += key_length;
            memcpy(&blob_buf[blob_index], d, key_length);
        }
        LPCWSTR blob_type = BCRYPT_ECCPUBLIC_BLOB;
        if (is_private_key) {
            blob_type = BCRYPT_ECCPRIVATE_BLOB;
        }
        BCRYPT_KEY_HANDLE key_handle = NULL;
        NTSTATUS status = ::BCryptImportKeyPair(alg_find->second, NULL, blob_type, &key_handle, blob_buf.data(), blob_buf.size(), 0);
        if (STATUS_SUCCESS == status) {
            return key_handle;
        }
        return NULL;
    }

    bool WinCrypto::VerifySignature(PUCHAR pkix_pub_key_pem, ULONG pkix_pub_key_pem_size, PUCHAR hash, ULONG hash_size, PUCHAR signature, ULONG signature_size) {
        std::vector<BYTE> pub_key_raw;
        if (!BinaryStringDecode(BINARY_STRING_CODE_PEM, (LPCSTR)pkix_pub_key_pem, pkix_pub_key_pem_size, &pub_key_raw)) {
            return false;
        }
        PCERT_PUBLIC_KEY_INFO cert_pub_key = nullptr;
        if (!ParsePKIXPublicKey(pub_key_raw.data(), pub_key_raw.size(), &cert_pub_key)) {
            return false;
        }

        bool ret = false;
        BCRYPT_KEY_HANDLE b_key_handle = NULL;
        do
        {
            if (!::CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, cert_pub_key, CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, NULL, &b_key_handle)) {
                b_key_handle = NULL;
                break;
            }
            NTSTATUS verify_status = ::BCryptVerifySignature(b_key_handle, NULL, hash, hash_size, signature, signature_size, 0);
            if (STATUS_SUCCESS == verify_status) {
                ret = true;
            }
        } while (false);

        if (b_key_handle) {
            ::BCryptDestroyKey(b_key_handle);
        }
        if (cert_pub_key) {
            ::LocalFree(cert_pub_key);
        }

        return ret;
    }
}