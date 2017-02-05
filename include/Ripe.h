//
//  Ripe.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef Ripe_h
#define Ripe_h

#include <memory>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/x509.h>

using byte = unsigned char;

class Ripe {
public:

    using RipeBigNum = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
    using RipeRSA = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    using RipeEVPKey = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
    using RipeBio = std::unique_ptr<BIO, decltype(&::BIO_free)>;
    using KeyPair = std::pair<std::string, std::string>;
    using RipeByte = std::unique_ptr<byte, std::default_delete<byte[]>>;

    static const std::string BASE64_CHARS;
    static const int BITS_PER_BYTE;
    static const int AES_BSIZE;
    static const int RSA_PADDING;

    // Asymmetric cryptography
    static int encryptRSA(byte* data, int dataLength, byte* key, byte* destination) noexcept;
    static int decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination) noexcept;
    static inline int decryptRSA(byte* encryptedData, int dataLength, const char* key, byte* destination) noexcept
    {
        return Ripe::decryptRSA(encryptedData, dataLength, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
    }

    static inline int encryptStringRSA(const std::string& data, const char* key, byte* destination) noexcept
    {
        return Ripe::encryptCStringRSA(data.c_str(), data.size(), key, destination);
    }

    static inline int encryptCStringRSA(const char* data, int length, const char* key, byte* destination) noexcept
    {
        return Ripe::encryptRSA(const_cast<byte*>(reinterpret_cast<const byte*>(data)), length, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
    }

    static bool writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length = 2048, unsigned long exponent = RSA_3) noexcept;
    static KeyPair generateRSAKeyPair(unsigned int length = 2048, unsigned long exponent = RSA_3) noexcept;

    static std::string convertDecryptedRSAToString(byte* decryptedData, int dataLength) noexcept;

    static void printLastError(const char* name = "Error: ") noexcept;

    static std::string prepareData(const char* data, std::size_t length, const char* key, int keySize, const char* clientId = "") noexcept;

    static inline unsigned int maxRSABlockSize(std::size_t keySize)
    {
        return ((keySize - 384) / 8) + 7;
    }

    //
    // Base64
    //
    static std::string base64Encode(const byte* input, std::size_t length) noexcept;
    static inline std::string base64Encode(const std::string& binaryData) noexcept
    {
        return Ripe::base64Encode(reinterpret_cast<byte*>(const_cast<char*>(binaryData.data())), binaryData.size());
    }

    static std::string base64Decode(const std::string& base64Encoded) noexcept;

    static inline unsigned int expectedBase64Length(unsigned int n) noexcept
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    //
    // Symmetric cryptography
    //
    static std::string encryptAES(const char* buffer, std::size_t length, const char* key, std::size_t keySize, std::vector<byte>& iv) noexcept;
    static std::string decryptAES(const char* buffer, std::size_t length, const char* key, std::size_t keySize, std::vector<byte>& iv) noexcept;

    static inline std::string decryptAES(const char* buffer, std::size_t length, const char* key, std::size_t keySize, byte* iv) noexcept
    {
        std::vector<byte> ivHex = Ripe::ivToVector(iv);
        return Ripe::decryptAES(buffer, length, key, keySize, ivHex);
    }

    static bool normalizeIV(std::string& iv) noexcept;
    static std::vector<byte> ivToVector(byte* iv) noexcept;

private:
    static RipeRSA createRSA(byte* key, bool isPublic) noexcept;
    static bool getRSAString(RSA* rsa, bool isPublic, char** strPtr) noexcept;

    static std::string normalizeAESKey(const char* keyBuffer, std::size_t keySize) noexcept;

    static inline bool isBase64(byte c) noexcept
    {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }
};
#endif /* Ripe_h */
