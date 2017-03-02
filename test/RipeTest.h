#ifndef RIPE_TEST_H
#define RIPE_TEST_H

#include <cmath>
#include <cstring>
#include <tuple>
#include <easylogging++.h>
#include "include/Ripe.h"
#include "include/RipeHelpers.h"
#include "test.h"

static const TestData base64Data = {
    {"cGxhaW4gdGV4dA==", "plain text"},
    {"cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"}
};

static const std::vector<std::tuple<std::string, std::string, std::string>> AESData = {
    std::make_tuple("128-bit key", "Quick Brown Fox Jumps Over The Lazy Dog", "71997e8f17d7cdb111398cb3bef4a424"),
};

static const std::vector<std::tuple<std::string, std::string, std::string, std::string>> AESDecryptionData = {
    std::make_tuple("VgUNMJr88rHn4vgumKRj0w==", "plain text", "71997e8f17d7cdb111398cb3bef4a424", "47be00dcde88c3084ae9e0a21f89cb81"),
};

static const std::vector<std::tuple<std::string, std::string, std::string, std::string>> AESDecryptionDataUsingHelpers = {
    std::make_tuple("VgUNMJr88rHn4vgumKRj0w==", "plain text", "71997e8f17d7cdb111398cb3bef4a424", "47be00dcde88c3084ae9e0a21f89cb81"),
};

static const std::vector<std::tuple<int, std::string>> RSAData = {
    std::make_tuple(1024, "plain text"),
    std::make_tuple(1024, "Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(1024, "{plain text}"),
    std::make_tuple(1024, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(1024, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
    std::make_tuple(2048, "plain text"),
    std::make_tuple(2048, "Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(2048, "{plain text}"),
    std::make_tuple(2048, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(2048, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
    std::make_tuple(4096, "plain text"),
    std::make_tuple(4096, "Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(4096, "{plain text}"),
    std::make_tuple(4096, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(4096, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
};

class RipeTest : public ::testing::Test
{
public:
    static const std::string publicKeyFile;
    static const std::string privateKeyFile;
    static const std::string encryptedDataFile;
};

const std::string RipeTest::publicKeyFile = "/tmp/ripe-unit-test-public-key.pem";
const std::string RipeTest::privateKeyFile = "/tmp/ripe-unit-test-private-key.pem";
const std::string RipeTest::encryptedDataFile = "/tmp/ripe-unit-test-rsa-encrypted.bin";

TEST(RipeTest, Base64Encode)
{
    for (const auto& item : base64Data) {
        std::string encoded = Ripe::base64Encode(item.second);
        ASSERT_EQ(item.first, encoded);
    }
}

TEST(RipeTest, Base64Decode)
{
    for (const auto& item : base64Data) {
        std::string decoded = Ripe::base64Decode(item.first);
        ASSERT_EQ(item.second, decoded);
    }
}

TEST(RipeTest, AESEncryption)
{
    for (const auto& item : AESData) {
        const std::string testCase = std::get<0>(item);
        const std::string testData = std::get<1>(item);
        const std::string testKey = std::get<2>(item);
        std::vector<byte> iv;
        TIMED_BLOCK(timer, "AES Encryption & Decryption") {
            std::string encrypted = Ripe::encryptAES(testData.c_str(), testData.size(), testKey.c_str(), testKey.size(), iv);
            int expectedBlockSize = (testData.size() / Ripe::AES_BSIZE + 1) * Ripe::AES_BSIZE;
            ASSERT_EQ(encrypted.size(), expectedBlockSize);

            std::string ivStr = Ripe::ivToString(iv);
            Ripe::normalizeIV(ivStr);
            LOG(INFO) << "IV: " << ivStr;
            EXPECT_STRCASEEQ(testData.c_str(), std::string(Ripe::decryptAES(encrypted.c_str(), encrypted.size(), testKey.c_str(), testKey.size(), iv)).c_str()) << testCase;
        }
    }
}

TEST(RipeTest, AESDecryption)
{
    for (const auto& item : AESDecryptionData) {
        const std::string data = std::get<0>(item);
        const std::string expected = std::get<1>(item);
        const std::string key = std::get<2>(item);
        std::string ivec = std::get<3>(item);
        std::string encrypted = Ripe::base64Decode(data);
        Ripe::normalizeIV(ivec);
        byte* iv = reinterpret_cast<byte*>(const_cast<char*>(ivec.data()));
        std::string decrypted = std::string(Ripe::decryptAES(encrypted.c_str(), encrypted.size(), key.c_str(), key.size(), iv));
        EXPECT_STRCASEEQ(expected.c_str(), decrypted.c_str());
    }
}

TEST(RipeTest, AESDecryptionUsingHelpers)
{
    for (const auto& item : AESDecryptionDataUsingHelpers) {
        const std::string data = std::get<0>(item);
        const std::string expected = std::get<1>(item);
        const std::string key = std::get<2>(item);
        std::string ivec = std::get<3>(item);

        std::string e(data);
        LOG(INFO) << "AES Data (Base64): " << e << " KEY: " << key << " IV: " << ivec;
        std::string decryptedUsingHelpers = RipeHelpers::decryptAES(e, key, ivec, true);
        EXPECT_STRCASEEQ(expected.c_str(), decryptedUsingHelpers.c_str());
    }
}
/*
TEST(RipeTest, RSAKeyGeneration)
{
    for (const auto& item : RSAData) {
        const int length = std::get<0>(item);
        const int lengthInBits = length / Ripe::BITS_PER_BYTE;
        std::stringstream ss;
        ss << lengthInBits << " bit keypair";
        TIMED_BLOCK(timer, ss.str()) {
            ASSERT_TRUE(Ripe::writeRSAKeyPair(RipeTest::publicKeyFile.c_str(), RipeTest::privateKeyFile.c_str(), length)) << "Could not generate RSA key pair";

            // Just ensure it can be generated
            std::ifstream publicKeyStream(RipeTest::publicKeyFile);
            std::string publicKey((std::istreambuf_iterator<char>(publicKeyStream)), (std::istreambuf_iterator<char>()));
            publicKeyStream.close();
            ASSERT_FALSE(publicKey.empty());

            std::ifstream privateKeyStream(RipeTest::privateKeyFile);
            std::string privateKey((std::istreambuf_iterator<char>(privateKeyStream)), (std::istreambuf_iterator<char>()));
            privateKeyStream.close();
            ASSERT_FALSE(privateKey.empty());
        }
    }
}

TEST(RipeTest, RSAOperations)
{
    for (const auto& item : RSAData) {

        const int length = std::get<0>(item);
        const int lengthInBits = length / Ripe::BITS_PER_BYTE;
        std::stringstream ss;
        ss << "With " << lengthInBits << " bit keypair";
        TIMED_BLOCK(o, ss.str()) {
            auto& timer = o.timer;
            int expectedBase64Length = Ripe::expectedBase64Length(lengthInBits);
            const std::string data = std::get<1>(item);
            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "generate keypair");
            std::pair<std::string, std::string> pair = Ripe::generateRSAKeyPair(length);
            std::string privateKey = pair.first;
            std::string publicKey = pair.second;

            byte encrypted[length];
            byte decrypted[length];

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "encrypt");
            // Encrypt
            int encryptedLength = Ripe::encryptStringRSA(data, publicKey.c_str(), encrypted);
            ASSERT_EQ(encryptedLength, lengthInBits) << "Unable to encrypt RSA properly";
            std::string b64 = Ripe::base64Encode(encrypted, encryptedLength);
            ASSERT_EQ(b64.size(), expectedBase64Length);

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "decrypt");
            // Decrypt
            int decryptionLength = encryptedLength;
            int decryptedLength = Ripe::decryptRSA(encrypted, decryptionLength, privateKey.c_str(), decrypted);
            ASSERT_EQ(decryptedLength, data.size()) << "Unable to decrypt RSA properly (Decryption with " << decryptionLength << ")";
            std::string decryptedData = Ripe::convertDecryptedRSAToString(decrypted, decryptedLength);
            ASSERT_EQ(data, decryptedData);

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "to-file");
            // Now we save it to file, read it from file and again decrypt it
            // Save encrypted data to the file
            std::fstream fs(RipeTest::encryptedDataFile, std::fstream::out | std::fstream::binary);
            ASSERT_TRUE(fs.is_open()) << "Unable to open file for writing encrypted data";
            fs << b64;
            fs.close();
            fs.flush();

            // Load from file
            fs.open(RipeTest::encryptedDataFile, std::fstream::in | std::fstream::binary);
            ASSERT_TRUE(fs.is_open()) << "Unable to open file to read encrypted data";

            std::string encryptedDataFromFile = std::string((std::istreambuf_iterator<char>(fs) ),
                            (std::istreambuf_iterator<char>()));

            // Confirm we read correct data
            encryptedDataFromFile = Ripe::base64Decode(encryptedDataFromFile);
            ASSERT_EQ(encryptedDataFromFile.size(), encryptedLength);

            // Decrypt file's data
            byte decryptedFromFile[length];
            decryptedLength = Ripe::decryptRSA(reinterpret_cast<byte*>(const_cast<char*>(encryptedDataFromFile.c_str())), decryptionLength, privateKey.c_str(), decryptedFromFile);
            ASSERT_EQ(decryptedLength, data.size()) << data << "\nUnable to decrypt RSA properly from the file (Decryption with " << decryptionLength << ")";
            decryptedData = Ripe::convertDecryptedRSAToString(decryptedFromFile, decryptedLength);
            ASSERT_EQ(data, decryptedData);
        }

    }
}*/

#endif // RIPE_TEST_H
