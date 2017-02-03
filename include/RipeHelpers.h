//
//  RipeHelpers.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef RipeHelpers_h
#define RipeHelpers_h

class RipeHelpers {
public:
    static std::string encryptAES(std::string& data, const std::string& key, const std::string& clientId, const std::string& outputFile) noexcept;
    static std::string decryptAES(std::string& data, const std::string& key, std::string& iv, bool isBase64) noexcept;
    static std::string encodeBase64(std::string& data) noexcept;
    static std::string decodeBase64(std::string& data) noexcept;
    static std::string encryptRSA(std::string& data, const std::string& key, const std::string& outputFile, int length = 2048) noexcept;
    static std::string decryptRSA(std::string& data, const std::string& key, bool isBase64, int length = 2048) noexcept;
    static void writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile, int length = 2048) noexcept;
    static std::string generateRSAKeyPair(int length = 2048) noexcept;
};
#endif /* RipeHelpers_h */
