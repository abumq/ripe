#ifndef RIPE_TEST_H
#define RIPE_TEST_H

#include <cmath>
#include <cstring>
#include <tuple>
#include <easylogging++.h>
#include "include/Ripe.h"
#include "include/RipeCrypto.h"
#include "test.h"

static const TestData Base64TestData = {
    {"cGxhaW4gdGV4dA==", "plain text"},
    {"cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"}
};

static const std::vector<std::tuple<std::size_t, std::size_t, std::size_t>> DataSizeTestData = {
    std::make_tuple(4, 16, 77),
    std::make_tuple(4, 0, 60),
    std::make_tuple(55, 0, 125),
    std::make_tuple(55, 16, 142)
};

static const std::vector<std::tuple<std::size_t, std::string>> AESTestData = {
    std::make_tuple(16, "plain text"),
    std::make_tuple(24, "plain text"),
    std::make_tuple(32, "plain text"),
    std::make_tuple(16, "Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(24, "Quick Brown Fox Jumps Over The Lazy Dog"),
    std::make_tuple(32, "Quick Brown Fox Jumps Over The Lazy Dog"),
};

static const std::vector<std::tuple<std::string, std::string, std::string, std::string>> AESDecryptionData = {
    std::make_tuple("hkz20HKQA491wZqbEctxCA==", "plain text", "B1C8BFB9DA2D4FB054FE73047AE700BC", "88505d29e8f56bbd7c9e1408f4f42240"),
};

static const std::vector<std::tuple<int, std::string>> RSATestData = {
    /*std::make_tuple(1024, "plain text"),
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
    std::make_tuple(4096, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),*/
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
    for (const auto& item : Base64TestData) {
        std::string encoded = Ripe::base64Encode(item.second);
        ASSERT_EQ(item.first, encoded);
    }
}

TEST(RipeTest, Base64Decode)
{
    for (const auto& item : Base64TestData) {
        std::size_t s = Ripe::expectedBase64Length(item.second.size());
        ASSERT_EQ(item.first.size(), s);
    }
}

TEST(RipeTest, ExpectedB64Size)
{
    for (const auto& item : Base64TestData) {
        std::string decoded = RipeCrypto::base64Decode(item.first);
        ASSERT_EQ(item.second, decoded);
    }
}

TEST(RipeTest, ExpectedDataSize)
{
    for (const auto& item : DataSizeTestData) {
        std::size_t plainSize = std::get<0>(item);
        std::size_t clientIdSize = std::get<1>(item);
        std::size_t expected = std::get<2>(item);
        ASSERT_EQ(expected, Ripe::expectedDataSize(plainSize, clientIdSize));
    }
}

TEST(RipeTest, AESEncryption)
{
    for (const auto& item : AESTestData) {
        const std::size_t testKeySize = std::get<0>(item);
        const std::string testData = std::get<1>(item);
        const std::string testKey = "6BC027B45BE1B5A912EEE837B723A5DEEE397181439986AD9B1AB307780ECC8A";//RipeCrypto::generateNewKey(testKeySize);
        LOG(INFO) << "Test: " << testData;
        LOG(INFO) << "Key: " << testKey;
        std::vector<byte> iv;
        TIMED_BLOCK(timer, "AES Encryption & Decryption") {
            std::string encrypted = Ripe::encryptAES(testData.c_str(), testKey, iv);
            ASSERT_EQ(encrypted.size(), Ripe::expectedAESCipherLength(testData.size()));
            LOG(INFO) << "Cipher Length: " << encrypted.length() << std::endl;
            EXPECT_STRCASEEQ(testData.c_str(), std::string(Ripe::decryptAES(encrypted.c_str(), testKey, iv)).c_str()) << (testKeySize * Ripe::BITS_PER_BYTE) << "-bit key";
            std::string b64 = Ripe::base64Encode(encrypted);
            std::string ivStr = Ripe::vecToString(iv);
            LOG(INFO) << "IV: " << ivStr;
            LOG(INFO) << "CLI Command: echo " << b64 << " | ripe -d --key " << testKey << " --iv " << ivStr << " --base64";
            EXPECT_EQ(testData, Ripe::decryptAES(b64, testKey, ivStr, true)) << (testKeySize * Ripe::BITS_PER_BYTE) << "-bit key";
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
        std::string decrypted = Ripe::decryptAES(encrypted.c_str(), key, iv);
        EXPECT_STRCASEEQ(expected.c_str(), decrypted.c_str());
    }
}

TEST(RipeTest, RSAKeyGeneration)
{
    for (const auto& item : RSATestData) {
        const int length = std::get<0>(item);
        const int lengthInBits = length / Ripe::BITS_PER_BYTE;
        std::stringstream ss;
        ss << lengthInBits << " bit keypair";
        TIMED_BLOCK(timer, ss.str()) {
            ASSERT_TRUE(RipeCrypto::writeRSAKeyPair(RipeTest::publicKeyFile.c_str(), RipeTest::privateKeyFile.c_str(), length)) << "Could not generate RSA key pair";

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
    for (const auto& item : RSATestData) {

        const int length = std::get<0>(item);
        const int lengthInBits = length / Ripe::BITS_PER_BYTE;
        std::stringstream ss;
        ss << "With " << lengthInBits << " bit keypair";
        TIMED_BLOCK(o, ss.str()) {
            auto& timer = o.timer;
            int expectedBase64Length = Ripe::expectedBase64Length(lengthInBits);
            const std::string data = std::get<1>(item);
            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "generate keypair");
            std::pair<std::string, std::string> pair = RipeCrypto::generateRSAKeyPair(length);
            std::string privateKey = pair.first;
            std::string publicKey = pair.second;

            byte encrypted[length];
            byte decrypted[length];

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "encrypt");
            // Encrypt
            int encryptedLength = Ripe::encryptStringRSA(data, publicKey.c_str(), encrypted);
            ASSERT_EQ(encryptedLength, lengthInBits) << "Unable to encrypt RSA properly";
            std::string b64 = RipeCrypto::base64Encode(encrypted, encryptedLength);
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
            encryptedDataFromFile = RipeCrypto::base64Decode(encryptedDataFromFile);
            ASSERT_EQ(encryptedDataFromFile.size(), encryptedLength);

            // Decrypt file's data
            byte decryptedFromFile[length];
            decryptedLength = Ripe::decryptRSA(reinterpret_cast<byte*>(const_cast<char*>(encryptedDataFromFile.c_str())), decryptionLength, privateKey.c_str(), decryptedFromFile);
            ASSERT_EQ(decryptedLength, data.size()) << data << "\nUnable to decrypt RSA properly from the file (Decryption with " << decryptionLength << ")";
            decryptedData = Ripe::convertDecryptedRSAToString(decryptedFromFile, decryptedLength);
            ASSERT_EQ(data, decryptedData);
        }

    }
}

#endif // RIPE_TEST_H
