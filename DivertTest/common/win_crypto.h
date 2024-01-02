#pragma once
namespace common {


    class WinCrypto
    {
    public:

        enum BinaryStringCodeType
        {
            BINARY_STRING_CODE_HEX = 1,
            BINARY_STRING_CODE_BASE64,
            BINARY_STRING_CODE_PEM,
        };
        struct AlgProviderInfo
        {
            std::wstring alg_id;
            std::wstring implementation;
            ULONG flags;
        };

        struct HashHandle
        {
            BCRYPT_HASH_HANDLE hash_handle;
            std::vector<UCHAR> hash_object_buf;
            std::vector<UCHAR> hash_buf;
        };

        struct SignInfo
        {
            std::wstring signer_name;
            std::wstring signer_issuer_name;
            bool signature_valid;
        };

        WinCrypto() = default;
        virtual ~WinCrypto();

        static bool CertGetNameStringUtil(PCCERT_CONTEXT cert_context, DWORD name_type, DWORD flags, void* type_param, std::wstring* name);
        static bool BinaryStringEncode(BinaryStringCodeType code_type, const BYTE* binary_bytes, DWORD binary_bytes_size, std::string* str_out);
        static bool BinaryStringDecode(BinaryStringCodeType code_type, LPCSTR in_str, DWORD in_str_size, std::vector<BYTE>* binary_out);
        static bool ParsePKIXPublicKey(const BYTE* encoded_key, DWORD encoded_key_size, PCERT_PUBLIC_KEY_INFO* key_out);
        static bool GetSystemTrustedRootCerts(bool machine_store, std::list<std::vector<unsigned char>>* certs);
        static bool GetEmbedSignInfo(LPCWSTR file_path, bool verify_signature, std::list<SignInfo>* sign_info_list);
        static bool VerifyPESignature(LPCWSTR file_path);

        bool Init(const std::vector<AlgProviderInfo>& alg_prov_vec);


        HashHandle* CreateHash(LPCWSTR hash_alg);
        bool HashData(HashHandle* hash_handle, PUCHAR data, ULONG data_size);
        bool FinishHash(HashHandle* hash_handle, std::vector<UCHAR>* hash);
        bool Hash(LPCWSTR hash_alg, const void* data, size_t data_size, std::vector<UCHAR>* hash);
        std::string Hash(LPCWSTR hash_alg, const void* data, size_t data_size);
        bool HashFile(LPCWSTR hash_alg, const wchar_t* file_path, std::vector<UCHAR>* hash);
        std::string HashFile(LPCWSTR hash_alg, const wchar_t* file_path);

        BCRYPT_KEY_HANDLE ImportECCKey(LPCWSTR alg_id, ULONG blob_magic, ULONG key_length, BYTE* x, BYTE* y, BYTE* d, bool is_private_key);
        //must init specific algorithm before verifing
        bool VerifySignature(PUCHAR pkix_pub_key_pem, ULONG pkix_pub_key_pem_size, PUCHAR hash, ULONG hash_size, PUCHAR signature, ULONG signature_size);

    private:
        bool OpenAlgProvider(LPCWSTR alg_id, LPCWSTR implementation, ULONG flags);


        std::map<std::wstring, BCRYPT_ALG_HANDLE> alg_handles_;
    };

}