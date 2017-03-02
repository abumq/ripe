//
//  Ripe.cc
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>
#include "include/Ripe.h"
#include "include/RipeCrypto.h"
#include "include/log.h"

const char Ripe::DATA_DELIMITER = ':';
const int Ripe::BITS_PER_BYTE = 8;

std::string Ripe::encryptRSA(std::string& data, const std::string& key, const std::string& outputFile, int length) noexcept
{
    std::stringstream ss;
    byte* newData = new byte[length];
    int newLength = Ripe::encryptStringRSA(data, key.c_str(), newData);
    if (newLength == -1) {
        delete[] newData;
        unsigned int maxBlockSize = Ripe::maxRSABlockSize(length);
        if (data.size() > maxBlockSize) {
            RLOG(FATAL) << "Data size should not exceed " << maxBlockSize << " bytes. You have " << data.size() << " bytes";
        }
        RipeCrypto::printLastError("Failed to encrypt");
    } else {
        std::string encrypted = RipeCrypto::base64Encode(newData, newLength);
        if (!outputFile.empty()) {
            std::ofstream out(outputFile);
            out << encrypted;
            out.close();
            out.flush();
        } else {
            ss << encrypted;
        }
    }
    delete[] newData;
    return ss.str();
}

std::string Ripe::decryptRSA(std::string& data, const std::string& key, bool isBase64, int length) noexcept
{

    if (isBase64) {
        data = RipeCrypto::base64Decode(data);
    }
    int dataLength = static_cast<int>(data.size());

    std::stringstream ss;
    byte* newData = new byte[length];

    int newLength = Ripe::decryptRSA(reinterpret_cast<byte*>(const_cast<char*>(data.c_str())), dataLength, key.c_str(), newData);
    if (newLength == -1) {
        delete[] newData;
        unsigned int maxBlockSize = Ripe::maxRSABlockSize(length);
        if (data.size() > maxBlockSize) {
            RLOG(FATAL) << "Data size should not exceed " << maxBlockSize << " bytes. You have " << data.size() << " bytes";
        }

        RipeCrypto::printLastError("Failed to decrypt");
    } else {
        ss << newData;
    }
    delete[] newData;
    return ss.str();
}

std::string Ripe::convertDecryptedRSAToString(byte* decryptedData, int dataLength) noexcept
{
    std::string result;
    if (dataLength != -1) {
        result = std::string(reinterpret_cast<const char*>(decryptedData));
        result[dataLength] = '\0';
        result.erase(dataLength);
    }
    return result;
}

void Ripe::writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile, int length) noexcept
{
    RLOG(INFO) << "Generating key pair that can encrypt " << Ripe::maxRSABlockSize(length) << " bytes";
    if (!RipeCrypto::writeRSAKeyPair(publicFile.c_str(), privateFile.c_str(), length)) {
        RLOG(ERROR) << "Failed to generate key pair! Please check logs for details" << std::endl;
        RipeCrypto::printLastError("Failed to decrypt");
        return;
    }
    RLOG(INFO) << "Successfully saved!";
}

std::string Ripe::generateRSAKeyPair(int length) noexcept
{
    RipeCrypto::KeyPair pair = RipeCrypto::generateRSAKeyPair(length);
    if (pair.first.empty() || pair.second.empty()) {
        RLOG(ERROR) << "Failed to generate key pair! Please check logs for details" << std::endl;
        RipeCrypto::printLastError("Failed to decrypt");
        return "";
    }
    return std::string(Ripe::base64Encode(pair.first) + ":" + Ripe::base64Encode(pair.second));
}

std::string Ripe::encryptAES(std::string& data, const std::string& hexKey, const std::string& clientId, const std::string& outputFile)
{
    std::stringstream ss;
    if (!outputFile.empty()) {
        std::vector<byte> iv;
        std::string encrypted = Ripe::encryptAES(data.data(), hexKey, iv);
        std::ofstream out(outputFile);
        out << encrypted.data();
        out.close();
        ss << "IV: " << std::hex << std::setfill('0');
        for (byte b : iv) {
            ss << std::setw(2) << static_cast<unsigned int>(b);
        }
        ss << std::endl;
    } else {
        ss << Ripe::prepareData(data.data(), hexKey, clientId.c_str());
    }
    return ss.str();
}

std::string Ripe::decryptAES(const std::string& d, const std::string& hexKey, std::string& ivec, bool isBase64)
{
    std::string data(d);
    if (ivec.empty() && isBase64) {
        // Extract IV from data
        std::size_t pos = data.find_first_of(':');
        if (pos == 32) {
            ivec = data.substr(0, pos);
            Ripe::normalizeIV(ivec);
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
        Ripe::normalizeIV(ivec);
    }

    byte* iv = reinterpret_cast<byte*>(const_cast<char*>(ivec.data()));

    if (isBase64) {
        data = RipeCrypto::base64Decode(data);
    }

    return Ripe::decryptAES(data.data(), hexKey, iv);
}

std::string Ripe::prepareData(const char* data, const std::string& hexKey, const char* clientId)
{
    std::vector<byte> iv;
    std::string encrypted = Ripe::encryptAES(data, hexKey, iv);
    // Encryption Base64 encoding
    std::string base64Encoded = Ripe::base64Encode(encrypted);

    // IV Hex
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (byte b : iv) {
        ss << std::setw(2) << static_cast<unsigned int>(b);
    }
    ss << Ripe::DATA_DELIMITER;
    if (strlen(clientId) > 0) {
        ss << clientId << Ripe::DATA_DELIMITER;
    }
    ss << base64Encoded;
    std::stringstream fss;
    std::string ssstr(ss.str());
    fss << ssstr.size() << Ripe::DATA_DELIMITER << ssstr;
    return fss.str();
}


bool Ripe::normalizeIV(std::string& iv) noexcept
{
    if (iv.size() == 32) {
        for (int j = 2; j < 32 + 15; j += 2) {
            iv.insert(j, " ");
            j++;
        }
        return true;
    }
    return false;
}

std::string Ripe::vecToString(const std::vector<byte>& iv) noexcept
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (byte b : iv) {
        ss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return ss.str();
}

std::vector<byte> Ripe::byteToVec(const byte* b) noexcept
{
    std::vector<byte> hexData;

    std::istringstream ss(reinterpret_cast<const char*>(b));

    unsigned int c;
    while (ss >> std::hex >> c) {
        hexData.push_back(c);
    }
    return hexData;
}


std::string Ripe::stringToHex(const std::string& str) noexcept
{
    std::stringstream ss;
    for (char c : str) {
        ss << std::hex << static_cast<unsigned>(c);
    }
    return ss.str();
}

const byte* Ripe::hexToByte(const std::string& hex)
{
    std::size_t len = hex.length();
    if (len % 2 != 0) {
        throw std::invalid_argument("Invalid hex");
    }
    std::string result;
    result.resize(len / 2);
    for (int i = 0; i < len; i += 2) {
        std::string pair = hex.substr(i, 2);
        char byte = static_cast<char>(strtol(pair.c_str(), NULL, 16));
        result[i / 2] = byte;
    }

    return reinterpret_cast<const byte*>(result.c_str());
}

std::string Ripe::version() noexcept
{
    return RIPE_VERSION;
}
