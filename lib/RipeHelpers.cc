//
//  Ripe.cc
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#include <vector>
#include <sstream>
#include <iomanip>
#include "include/RipeHelpers.h"
#include "include/Ripe.h"
#include "include/log.h"

using namespace ripe::tools;

const int Ripe::LENGTH = 2048;

std::string Ripe::encryptRSA(std::string& data, const std::string& key, const std::string& outputFile) noexcept
{
    std::stringstream ss;
    byte newData[Ripe::LENGTH] = {};
    int newLength = ripe::crypto::Ripe::encryptStringRSA(data, key.c_str(), newData);
    if (newLength == -1) {
        ripe::crypto::Ripe::printLastError("Failed to encrypt");
    } else {
        std::string encrypted = ripe::crypto::Ripe::base64Encode(newData, newLength);
        if (!outputFile.empty()) {
            std::ofstream out(outputFile);
            out << encrypted;
            out.close();
            out.flush();
        } else {
            ss << encrypted;
        }
    }
    return ss.str();
}

std::string Ripe::decryptRSA(std::string& data, const std::string& key, bool isBase64) noexcept
{

    if (isBase64) {
        data = ripe::crypto::Ripe::base64Decode(data);
    }

    std::stringstream ss;
    byte newData[Ripe::LENGTH] = {};
    int dataLength = static_cast<int>(data.size());
    int newLength = ripe::crypto::Ripe::decryptRSA(reinterpret_cast<byte*>(const_cast<char*>(data.c_str())), dataLength, key.c_str(), newData);
    if (newLength == -1) {
        ripe::crypto::Ripe::printLastError("Failed to decrypt");
    } else {
        ss << newData;
    }
    return ss.str();
}

void Ripe::writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile) noexcept
{
    if (!ripe::crypto::Ripe::writeRSAKeyPair(publicFile.c_str(), privateFile.c_str(), Ripe::LENGTH)) {
        RLOG(ERROR) << "Failed to generate key pair! Please check logs for details" << std::endl;
        ripe::crypto::Ripe::printLastError("Failed to decrypt");
    }
}

std::string Ripe::generateRSAKeyPair() noexcept
{
    ripe::crypto::Ripe::KeyPair pair = ripe::crypto::Ripe::generateRSAKeyPair(Ripe::LENGTH);
    if (pair.first.empty() || pair.second.empty()) {
        RLOG(ERROR) << "Failed to generate key pair! Please check logs for details" << std::endl;
        ripe::crypto::Ripe::printLastError("Failed to decrypt");
        return "";
    }
    return std::string(ripe::crypto::Ripe::base64Encode(pair.first) + ":" + ripe::crypto::Ripe::base64Encode(pair.second));
}

std::string Ripe::encodeBase64(std::string& data) noexcept
{
    return ripe::crypto::Ripe::base64Encode(data);
}

std::string Ripe::decodeBase64(std::string& data) noexcept
{
    return ripe::crypto::Ripe::base64Decode(data);
}

std::string Ripe::encrypt(std::string& data, const std::string& key, const std::string& clientId, const std::string& outputFile) noexcept
{
    std::stringstream ss;
    if (!outputFile.empty()) {
        std::vector<byte> iv;
        std::string encrypted = ripe::crypto::Ripe::encryptAES(data.data(), data.size(), key.data(), key.size(), iv);
        std::ofstream out(outputFile);
        out << encrypted.data();
        out.close();
        ss << "IV: " << std::hex << std::setfill('0');
        for (byte b : iv) {
            ss << std::setw(2) << static_cast<unsigned int>(b);
        }
        ss << std::endl;
    } else {
        ss << ripe::crypto::Ripe::prepareData(data.data(), data.size(), key.data(), key.size(), clientId.c_str());
    }
    return ss.str();
}

std::string Ripe::decrypt(std::string& data, const std::string& key, std::string& ivec, bool isBase64) noexcept
{
    if (ivec.empty() && isBase64) {
        // Extract IV from data
        std::size_t pos = data.find_first_of(':');
        if (pos == 32) {
            ivec = data.substr(0, pos);
            ripe::crypto::Ripe::normalizeIV(ivec);
            data = data.substr(pos + 1);
            pos = data.find_first_of(':');
            if (pos != std::string::npos) {
                // We ignore clientId which is = data.substr(0, pos);
                data = data.substr(pos + 1);
            }
        }
    }
    if (ivec.size() == 32) {
        // Condensed form needs to be normalized
        ripe::crypto::Ripe::normalizeIV(ivec);
    }
    byte* iv = reinterpret_cast<byte*>(const_cast<char*>(ivec.data()));

    if (isBase64) {
        data = ripe::crypto::Ripe::base64Decode(data);
    }

    return ripe::crypto::Ripe::decryptAES(data.data(), data.size(), key.data(), key.size(), iv);
}
