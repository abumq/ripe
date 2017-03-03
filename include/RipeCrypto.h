//
//  RipeCrypto.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef RipeCrypto_h
#define RipeCrypto_h

#include <memory>
#include <string>
#include <vector>

using byte = unsigned char;

///
/// \brief The RipeCrypto contains low level cryptography methods without any helpers
///
class RipeCrypto {
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
    struct KeyPair {
        std::string privateKey;
        std::string publicKey;
    };

    ///
    /// \brief Constant value for AES block size
    ///
    static const int AES_BSIZE;


    /*******************************************************************\
     *                             RSA                                 *
    \*******************************************************************/

    ///
    /// \brief Encrypts data of length = dataLength using RSA key and puts it in destination
    /// \return The size of the encrypted data. On error -1 is returned. use printLastError(const char*) to see the error details
    ///
    static int encryptRSA(byte* data, int dataLength, byte* key, byte* destination) noexcept;

    ///
    /// \brief Decrypts encryptedData of length dataLength with RSA key and puts result in destination
    /// \return The size of the recovered plaintext. On error -1 is returned. use printLastError(const char* name) to see the error details
    ///
    static int decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination) noexcept;

    ///
    /// \brief Writes RSA key pair and saves private key to privateOutputFile (file path) and public key to publicOutputFile
    /// \param length Length of the key (defaults to 256-bit [2048])
    ///
    static bool writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length = 2048, unsigned long exponent = RipeCrypto::RIPE_RSA_3) noexcept;

    ///
    /// \brief Generate key pair and returns KeyPair
    /// \see KeyPair
    /// \see writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length, unsigned long exponent)
    ///
    static KeyPair generateRSAKeyPair(unsigned int length = 2048, unsigned long exponent = RipeCrypto::RIPE_RSA_3);

    ///
    /// \brief printLastError Print last RSA error
    ///
    static void printLastError(const char* name = "Error: ") noexcept;

    /*******************************************************************\
     *                             Base64                              *
    \*******************************************************************/

    ///
    /// \brief Encodes input of length to base64 encoding
    ///
    static std::string base64Encode(const byte* input, std::size_t length);

    ///
    /// \brief Decodes encoded base64
    ///
    static std::string base64Decode(const std::string& base64Encoded);


    /*******************************************************************\
     *                               AES                               *
    \*******************************************************************/

    ///
    /// \brief Encrypts data of length with symmetric key of size = keySize with specified initialization vector
    ///
    static std::string encryptAES(const char* data, const byte* key, std::size_t keySize, std::vector<byte>& iv);

    ///
    /// \brief Decrypts data of specified length with specified key and initialization vector
    ///
    static std::string decryptAES(const std::string& data, const byte* key, std::size_t keySize, std::vector<byte>& iv);

    ///
    /// \brief Generate random AES key
    /// \param length Length of key, must be 16, 24 or 32
    /// \return Hexadecimal value of key
    ///
    static std::string generateNewKey(int length);

private:
    static const int RSA_PADDING;
    static const long RIPE_RSA_3;
};
#endif /* RipeCrypto_h */
