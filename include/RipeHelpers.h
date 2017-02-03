//
//  RipeHelpers.h
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#ifndef RipeHelpers_h
#define RipeHelpers_h

namespace ripe {
namespace tools {
class Ripe {
public:
    static const int LENGTH;

    static std::string encrypt(std::string& data, const std::string& key, const std::string& clientId, const std::string& outputFile) noexcept;
    static std::string decrypt(std::string& data, const std::string& key, std::string& iv, bool isBase64) noexcept;
    static std::string encodeBase64(std::string& data) noexcept;
    static std::string decodeBase64(std::string& data) noexcept;

    static std::string encryptRSA(std::string& data, const std::string& key, const std::string& outputFile) noexcept;
    static std::string decryptRSA(std::string& data, const std::string& key, bool isBase64) noexcept;
    static void writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile) noexcept;
    static std::string generateRSAKeyPair() noexcept;
};
}
}
#endif /* RipeHelpers_h */
