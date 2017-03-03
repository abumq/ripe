//
//  Ripe.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef Ripe_h
#define Ripe_h

#include "RipeCrypto.h"

///
/// \brief The RipeHelpers class contains wrapper functions for Ripe class. Please refer to it's documentation for details
///
class Ripe {
public:


    ///
    /// \brief Data delimiter for prepared data
    /// \see prepareData(const char*, const std::string&, const char*)
    ///
    static const char DATA_DELIMITER;

    ///
    /// \brief Constant value for bits per bytes (8)
    ///
    static const int BITS_PER_BYTE;


    /*******************************************************************\
     *                               AES                               *
    \*******************************************************************/
    ///
    /// \brief encryptAES Encrypts data with provided symmetric key
    /// \param outputFile Optional, if provided instead of printing it to console data is saved to file and IV is printed on console
    ///
    static std::string encryptAES(std::string& data, const std::string& hexKey, const std::string& clientId, const std::string& outputFile);

    ///
    /// \brief Helper function that takes hex key
    /// \see encryptAES(std::string& data, const std::string& hexKey, const std::string& clientId, const std::string& outputFile)
    ///
    static inline std::string encryptAES(const std::string& buffer, const std::string& hexKey, std::vector<byte>& iv)
    {
        return RipeCrypto::encryptAES(buffer.c_str(), Ripe::hexToByte(hexKey), hexKey.size() / 2, iv);
    }

    ///
    /// \brief decryptAES Decrypts data using specified symmetric key.
    /// \param isBase64 If true, first base64 decoding is done on data and then decryption is processed
    ///
    static std::string decryptAES(std::string& data, const std::string& hexKey, std::string& iv, bool isBase64 = false);

    ///
    /// \brief base64Encode Helper method
    /// \see base64Encode(const byte* input, std::size_t length)
    ///
    static inline std::string base64Encode(const std::string& binaryData)
    {
        return RipeCrypto::base64Encode(reinterpret_cast<byte*>(const_cast<char*>(binaryData.data())), binaryData.size());
    }

    ///
    /// \brief base64Decode wrapper
    ///
    static inline std::string base64Decode(const std::string& base64Encoded)
    {
        return RipeCrypto::base64Decode(base64Encoded);
    }

    ///
    /// \brief maxRSABlockSize Maximum size of RSA block with specified key size
    ///
    ///
    static inline unsigned int maxRSABlockSize(std::size_t keySize)
    {
        return ((keySize - 384) / 8) + 7;
    }
    ///
    /// \brief expectedBase64Length Returns expected base64 length
    /// \param n Length of input (plain data)
    ///
    static inline std::size_t expectedBase64Length(std::size_t n) noexcept
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    ///
    /// \brief Exceptect size of AES cipher when plainDataSize size data is encrypted
    ///
    static inline std::size_t expectedAESCipherLength(std::size_t plainDataSize) noexcept
    {
        return (plainDataSize / RipeCrypto::AES_BSIZE + 1) * RipeCrypto::AES_BSIZE;
    }

    ///
    /// \brief decryptRSA helper method
    /// \see decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination)
    ///
    static inline int decryptRSA(byte* encryptedData, int dataLength, const char* key, byte* destination) noexcept
    {
        return RipeCrypto::decryptRSA(encryptedData, dataLength, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
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
        return RipeCrypto::encryptRSA(const_cast<byte*>(reinterpret_cast<const byte*>(data)), length, const_cast<byte*>(reinterpret_cast<const byte*>(key)), destination);
    }

    ///
    /// \brief encryptRSA Encrypts using RSA key
    /// \param outputFile Optional, if provided instead of printing it to console data is saved to file
    /// \param length Size of encryption (RSA key size)
    ///
    static std::string encryptRSA(std::string& data, const std::string& key, const std::string& outputFile, int length = 2048) noexcept;

    ///
    /// \brief decryptRSA Decrypts using RSA key
    /// \param isBase64 If true, first base64 decoding is done on data and then decryption is processed
    /// \param length Size of encryption (RSA key size)
    ///
    static std::string decryptRSA(std::string& data, const std::string& key, bool isBase64, int length = 2048) noexcept;

    ///
    /// \brief Helper function that basically puts null terminator in the end of data and return it as string
    ///
    static std::string convertDecryptedRSAToString(byte* decryptedData, int dataLength) noexcept;

    ///
    /// \brief writeRSAKeyPair Writes RSA key pair to public and private file paths.
    /// \param length RSA key size
    ///
    static void writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile, int length = 2048) noexcept;

    ///
    /// \brief generateRSAKeyPair Generates RSA key pair and returns colon seperated base64 where first part is private key and second part is public key.
    ///
    static std::string generateRSAKeyPair(int length = 2048) noexcept;

    ///
    /// \brief prepareData Helper method to encrypt data with symmetric key and convert it in to tranferable data.
    /// \param clientId Extra text in between representing client ID (leave empty if you don't need it)
    /// \return Base64 format of encrypted data with format: <pre>[LENGTH]:[IV]:[<Client_ID>:]:[Base64 Data]</pre>
    ///
    static std::string prepareData(const char* data, const std::string& hexKey, const char* clientId = "");

    ///
    /// \brief Calculates expected data size. Assumed IV size = 32
    /// \see prepareData(const char*, const std::string&, const char*)
    ///
    static std::size_t expectedDataSize(std::size_t plainDataSize, std::size_t clientIdSize = 16) noexcept
    {
        static const int DATA_DELIMITER_LENGTH = sizeof(DATA_DELIMITER);

        std::size_t dataSize = 32 /* IV */
                + DATA_DELIMITER_LENGTH
                + (clientIdSize > 0 ? clientIdSize + DATA_DELIMITER_LENGTH : 0)
                + expectedBase64Length(expectedAESCipherLength(plainDataSize));
        unsigned int digits = 0;
        unsigned int n = static_cast<unsigned int>(dataSize);
        while (n) {
            n /= 10;
            ++digits;
        };
        return digits + DATA_DELIMITER_LENGTH + dataSize;
    }


    ///
    /// \brief Helper functino to convert string to hexdecimal e.g, khn = 6b686e
    ///
    static std::string stringToHex(const std::string& str) noexcept;

    ///
    /// \brief Helper function to convert hexadecimal input to byte array e.g, 6b686e = (byte*)khn
    ///
    static const byte* hexToByte(const std::string& hex);

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
};
#endif /* RipeHelpers_h */
