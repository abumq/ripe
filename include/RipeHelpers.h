//
//  RipeHelpers.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef RipeHelpers_h
#define RipeHelpers_h

///
/// \brief The RipeHelpers class contains wrapper functions for Ripe class. Please refer to it's documentation for details
///
class RipeHelpers {
public:
    ///
    /// \brief encryptAES Encrypts data with provided symmetric key
    /// \param outputFile Optional, if provided instead of printing it to console data is saved to file and IV is printed on console
    ///
    static std::string encryptAES(std::string& data, const std::string& hexKey, const std::string& clientId, const std::string& outputFile);

    ///
    /// \brief decryptAES Decrypts data using specified symmetric key.
    /// \param isBase64 If true, first base64 decoding is done on data and then decryption is processed
    ///
    static std::string decryptAES(const std::string& data, const std::string& hexKey, std::string& iv, bool isBase64);

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
    /// \brief writeRSAKeyPair Writes RSA key pair to public and private file paths.
    /// \param length RSA key size
    ///
    static void writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile, int length = 2048) noexcept;

    ///
    /// \brief generateRSAKeyPair Generates RSA key pair and returns colon seperated base64 where first part is private key and second part is public key.
    ///
    static std::string generateRSAKeyPair(int length = 2048) noexcept;
};
#endif /* RipeHelpers_h */
