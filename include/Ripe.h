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

using byte = unsigned char;

///
/// \brief The Ripe class contains wrapper functions for OpenSSL that are memory-leak safe.
/// User does not need to have OpenSSL installed in order to use pre-compiled Ripe library.
///
class Ripe {
public:
    ///
    /// \brief Safe array using unique_ptr for ripe
    ///
    template <typename T>
    using RipeArray = std::unique_ptr<T, std::default_delete<T[]>>;

    ///
    /// \brief Safe C-pointer for ripe with custom free function
    ///
    template <typename T, typename T_Free>
    using RipeCPtr = std::unique_ptr<T, T_Free>;

    ///
    /// \brief RSA Key pair
    ///
    using KeyPair = std::pair<std::string, std::string>;

    ///
    /// \brief BITS_PER_BYTE constant value for bits per bytes (8)
    ///
    static const int BITS_PER_BYTE;

    ///
    /// \brief AES_BSIZE constant value for AES block size
    ///
    static const int AES_BSIZE;

    // Asymmetric cryptography

    ///
    /// \brief encryptRSA Encrypts data of length = dataLength using RSA key and puts it in destination
    /// \return The size of the encrypted data. On error -1 is returned. use printLastError(const char*) to see the error details
    ///
    static int encryptRSA(byte* data, int dataLength, byte* key, byte* destination) noexcept;

    ///
    /// \brief decryptRSA Decrypts encryptedData of length dataLength with RSA key and puts result in destination
    /// \return The size of the recovered plaintext. On error -1 is returned. use printLastError(const char* name) to see the error details
    ///
    static int decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination) noexcept;

    ///
    /// \brief decryptRSA helper method
    /// \see decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination)
    ///
    static inline int decryptRSA(byte* encryptedData, int dataLength, const char* key, byte* destination) noexcept
    {
        return Ripe::decryptRSA(encryptedData, dataLength, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
    }

    ///
    /// \brief encryptStringRSA helper method
    /// \see encryptRSA(byte* data, int dataLength, byte* key, byte* destination)
    ///
    static inline int encryptStringRSA(const std::string& data, const char* key, byte* destination) noexcept
    {
        return Ripe::encryptCStringRSA(data.c_str(), data.size(), key, destination);
    }

    ///
    /// \brief encryptCStringRSA helper method
    /// \see encryptRSA(byte* data, int dataLength, byte* key, byte* destination)
    ///
    static inline int encryptCStringRSA(const char* data, int length, const char* key, byte* destination) noexcept
    {
        return Ripe::encryptRSA(const_cast<byte*>(reinterpret_cast<const byte*>(data)), length, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
    }

    ///
    /// \brief writeRSAKeyPair Writes RSA key pair and saves private key to privateOutputFile (file path) and public key to publicOutputFile
    /// \param length Length of the key (defaults to 256-bit [2048])
    ///
    static bool writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length = 2048, unsigned long exponent = RIPE_RSA_3) noexcept;

    ///
    /// \brief generateRSAKeyPair Generate key pair and returns KeyPair, where KeyPair.first is private key and KeyPair.second is public key
    /// \see writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length, unsigned long exponent)
    ///
    static KeyPair generateRSAKeyPair(unsigned int length = 2048, unsigned long exponent = RIPE_RSA_3) noexcept;

    ///
    /// \brief convertDecryptedRSAToString Helper method to treat decryptedData as string adding nul-terminator at the end of dataLength
    ///
    static std::string convertDecryptedRSAToString(byte* decryptedData, int dataLength) noexcept;

    ///
    /// \brief printLastError Print last RSA error
    ///
    static void printLastError(const char* name = "Error: ") noexcept;

    ///
    /// \brief prepareData Helper method to encrypt data with symmetric key and convert it in to tranferable data.
    /// \param clientId Extra text in between representing client ID (leave empty if you don't need it)
    /// \return Base64 format of encrypted data with format: <pre>[IV]:[<Client_ID>:]:[Base64 Data]</pre>
    ///
    static std::string prepareData(const char* data, const std::string& hexKey, const char* clientId = "") noexcept;

    ///
    /// \brief maxRSABlockSize Maximum size of RSA block with specified key size
    ///
    ///
    static inline unsigned int maxRSABlockSize(std::size_t keySize)
    {
        return ((keySize - 384) / 8) + 7;
    }

    ///
    /// \brief base64Encode Encode input of length to base64 encoding
    ///
    static std::string base64Encode(const byte* input, std::size_t length) noexcept;

    ///
    /// \brief base64Encode Helper method
    /// \see base64Encode(const byte* input, std::size_t length)
    ///
    static inline std::string base64Encode(const std::string& binaryData) noexcept
    {
        return Ripe::base64Encode(reinterpret_cast<byte*>(const_cast<char*>(binaryData.data())), binaryData.size());
    }

    ///
    /// \brief base64Decode Decode encoded base64
    ///
    static std::string base64Decode(const std::string& base64Encoded) noexcept;

    ///
    /// \brief expectedBase64Length Returns expected base64 length
    /// \param n Length of input (plain data)
    ///
    static inline unsigned int expectedBase64Length(unsigned int n) noexcept
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    static inline unsigned int expectedAESCipherLength(std::size_t size) noexcept
    {
        return (size / Ripe::AES_BSIZE + 1) * Ripe::AES_BSIZE;
    }

    ///
    /// \brief encryptAES Encrypts data of length with symmetric key of size = keySize with specified initialization vector
    ///
    static std::string encryptAES(const char* data, const byte* key, std::size_t keySize, std::vector<byte>& iv) noexcept;

    static std::string encryptAES(const char* data, const std::string& hexKey, std::vector<byte>& iv) noexcept;

    ///
    /// \brief decryptAES Decrypts data of specified length with specified key and initialization vector
    ///
    static std::string decryptAES(const char* data, const byte* key, std::size_t keySize, std::vector<byte>& iv);

    static std::string decryptAES(const char* buffer, const std::string& hexKey, std::vector<byte>& iv);

    ///
    /// \brief decryptAES Helper method
    /// \see decryptAES(const char* data, std::size_t length, const char* key, std::size_t keySize, std::vector<byte>& iv)
    ///
    static inline std::string decryptAES(const char* buffer, const std::string& hexKey, byte* iv)
    {
        std::vector<byte> ivHex = Ripe::byteToVec(iv);
        return Ripe::decryptAES(buffer, hexKey, ivHex);
    }

    ///
    /// \brief normalizeIV If IV with no space is provided e.g, <pre>67e56fee50e22a8c2ba05c0fb2932bfa:</pre> normalized IV
    /// is <pre>67 e5 6f ee 50 e2 2a 8c 2b a0 5c 0f b2 93 2b fa:</pre>
    ///
    static bool normalizeIV(std::string& iv) noexcept;

    static std::string vecToString(const std::vector<byte>& iv) noexcept;

    ///
    /// \brief ivToVector Converts plain (unsigned char*) IV to std::vector<byte>
    ///
    static std::vector<byte> byteToVec(const byte* iv) noexcept;

    ///
    /// \brief version Version of Ripe library
    ///
    static std::string version() noexcept;

    static std::string generateNewKey(int length) noexcept;


    static std::string stringToHex(const std::string& str) noexcept;
    static const byte* hexToByte(const std::string& hex) noexcept;
private:
    static const int RSA_PADDING;
    static const long RIPE_RSA_3;
};
#endif /* Ripe_h */
