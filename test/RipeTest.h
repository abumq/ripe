#ifndef RIPE_TEST_H
#define RIPE_TEST_H

#include "include/Ripe.h"
#include "test.h"

static TestData<std::string, std::string> Base64TestData = {
    TestCase("cGxhaW4gdGV4dA==", "plain text"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"),
};

static TestData<std::string, bool> IsBase64Data = {
    TestCase("da024686f7f2da49da6c98253b42fe1c:erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("da024686f7f2da49da6c98253b42fe1c:i3eclcagfnUbK1B==", false),
    TestCase("erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("i3eclcagfnUbK1B==", true),
};

static TestData<std::string, std::string> HexTestData = {
    TestCase("61626364", "abcd"),
    TestCase("717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F6720515549434B2042524F574E20464F58204A554D5053204F56455220544845204C415A5920444F47", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"),
};

static TestData<std::string, std::string> ZLibData = {
    TestCase("abcd", "eNpLTEpOAQAD2AGL"),
};

static TestData<std::size_t, std::size_t, std::size_t> DataSizeTestData = {
    TestCase(4, 0, 57 + Ripe::PACKET_DELIMITER_SIZE),
    TestCase(4, 16, 74 + Ripe::PACKET_DELIMITER_SIZE),
    TestCase(55, 0, 121 + Ripe::PACKET_DELIMITER_SIZE),
    TestCase(55, 16, 138 + Ripe::PACKET_DELIMITER_SIZE),
};

static TestData<std::size_t, std::string> AESTestData = {
    //TestCase(16, "plain text"),
    TestCase(24, "plain text"),
    TestCase(32, "plain text"),
    TestCase(16, "Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(24, "Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(32, "Quick Brown Fox Jumps Over The Lazy Dog"),
};

static TestData<std::string, std::string, std::string, std::string, bool, bool> AESDecryptionData = {
    TestCase("864CF6D07290038F75C19A9B11CB7108", "706C61696E2074657874", "B1C8BFB9DA2D4FB054FE73047AE700BC", "88505d29e8f56bbd7c9e1408f4f42240", false, true),
    TestCase("hkz20HKQA491wZqbEctxCA==", "706C61696E2074657874", "B1C8BFB9DA2D4FB054FE73047AE700BC", "88505d29e8f56bbd7c9e1408f4f42240", true, false),
};

static TestData<int, std::string> RSATestData = {
    TestCase(1024, "plain text"),
    TestCase(1024, "Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(1024, "{plain text}"),
    TestCase(1024, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(1024, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
    TestCase(2048, "plain text"),
    TestCase(2048, "Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(2048, "{plain text}"),
    TestCase(2048, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(2048, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
    TestCase(4096, "plain text"),
    TestCase(4096, "Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(4096, "{plain text}"),
    TestCase(4096, "Quick Brown Fox Jumps Over The Lazy Dog Quick Brown Fox Jumps Over The Lazy Dog"),
    TestCase(4096, "{\n\"client_id\":\"biltskmftmolwhlf\",\n\"key\":\"biltSKMfTMOlWHlF\",\n\"status\":200\n}"),
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
        std::string encoded = Ripe::base64Encode(PARAM(1));
        ASSERT_EQ(PARAM(0), encoded);
    }
}

TEST(RipeTest, Base64Decode)
{
    for (const auto& item : Base64TestData) {
        std::string decoded = Ripe::base64Decode(PARAM(0));
        ASSERT_EQ(PARAM(1), decoded);
    }
}

TEST(RipeTest, ExpectedB64Size)
{
    for (const auto& item : Base64TestData) {
        std::size_t s = Ripe::expectedBase64Length(PARAM(1).size());
        ASSERT_EQ(PARAM(0).size(), s);
    }
}

TEST(UtilsTest, IsBase64)
{
    for (const auto& item : IsBase64Data) {
        auto first = PARAM(0);
        auto second = PARAM(1);
        ASSERT_EQ(Ripe::isBase64(first), second);
    }
}

TEST(RipeTest, HexEncode)
{
    for (const auto& item : HexTestData) {
        std::string encoded = Ripe::stringToHex(PARAM(1));
        ASSERT_EQ(PARAM(0), encoded);
    }
}

TEST(RipeTest, HexDecode)
{
    for (const auto& item : HexTestData) {
        std::string decoded = Ripe::hexToString(PARAM(0));
        ASSERT_EQ(PARAM(1), decoded);
    }
}

TEST(RipeTest, ZLibInflate)
{
    for (const auto& item : ZLibData) {
        std::string encoded = Ripe::compressString(PARAM(0));
        ASSERT_EQ(PARAM(1), Ripe::base64Encode(encoded));
    }
}

TEST(RipeTest, ZLibDeflate)
{
    for (const auto& item : ZLibData) {
        std::string decoded = Ripe::decompressString(Ripe::base64Decode(PARAM(1)));
        ASSERT_EQ(PARAM(0), decoded);
    }
}

TEST(RipeTest, ExpectedDataSize)
{
    for (const auto& item : DataSizeTestData) {
        std::size_t plainSize = PARAM(0);
        std::size_t clientIdSize = PARAM(1);
        std::size_t expected = PARAM(2);
        ASSERT_EQ(expected, Ripe::expectedDataSize(plainSize, clientIdSize));
    }
}

TEST(RipeTest, AESEncryption)
{
    for (const auto& item : AESTestData) {
        std::cout << "\n*****[ BEGIN ]*****\n\n";
        const std::size_t testKeySize = PARAM(0);
        const std::string testData = PARAM(1);
        const std::string testKey = Ripe::generateNewKey(testKeySize);//"6BC027B45BE1B5A912EEE837B723A5DEEE397181439986AD9B1AB307780ECC8A";

        LOG(INFO) << "Test: " <<  (testKeySize * 8) << "-bit key: " << testData;
        LOG(INFO) << "Key: " << testKey;
        std::vector<RipeByte> iv;
        TIMED_BLOCK(timer, "AES Encryption & Decryption") {

            LOG(INFO) << "Encrypting...";
            std::string encrypted = Ripe::encryptAES(testData, testKey, iv);
            ASSERT_EQ(encrypted.size(), Ripe::expectedAESCipherLength(testData.size()));
            LOG(INFO) << "Cipher Length: " << encrypted.length() << std::endl;

            std::string ivStr = Ripe::vecToString(iv);
            std::string b64 = Ripe::base64Encode(encrypted);
            LOG(INFO) << "Decrypting...";
            LOG(INFO) << "IV: " << ivStr;
            LOG(INFO) << "CLI: echo " << b64 << " | ripe -d --key " << testKey << " --iv " << ivStr << " --base64";
            std::string decrypted = Ripe::decryptAES(encrypted, testKey, ivStr);

            EXPECT_STRCASEEQ(testData.c_str(), decrypted.c_str());

            LOG(INFO) << "Decrypting using base64...";
            EXPECT_EQ(testData, Ripe::decryptAES(b64, testKey, ivStr, true));
        }
        std::cout << "\n*****[ END ]*****\n\n";
    }
}

TEST(RipeTest, AESDecryption)
{
    for (auto item : AESDecryptionData) {
        std::string data = PARAM(0);
        const std::string expected = PARAM(1);
        const std::string key = PARAM(2);
        std::string ivec = PARAM(3);
        bool isb64 = PARAM(4);
        bool ishex = PARAM(5);

        std::string decrypted = Ripe::stringToHex(Ripe::decryptAES(data, key, ivec, isb64, ishex));
        EXPECT_STRCASEEQ(expected.c_str(), decrypted.c_str());
    }
}

TEST(RipeTest, RSAKeyGeneration)
{
    for (const auto& item : RSATestData) {
        const int length = PARAM(0);
        const int lengthInBits = length / 8;
        std::stringstream ss;
        ss << lengthInBits << " bit keypair";
        TIMED_BLOCK(timer, ss.str()) {
            ASSERT_TRUE(Ripe::writeRSAKeyPair(RipeTest::publicKeyFile, RipeTest::privateKeyFile, length)) << "Could not generate RSA key pair";

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

TEST(RipeTest, RSASignVerify)
{
    for (const auto& item : RSATestData) {
        const int length = PARAM(0);
        const std::string data = PARAM(1);
        Ripe::KeyPair pair = Ripe::generateRSAKeyPair(length);

        std::string privateKey = pair.privateKey;
        std::string publicKey = pair.publicKey;

        std::string signature = Ripe::signRSA(data, privateKey);
        ASSERT_TRUE(Ripe::verifyRSA(data, signature, publicKey));
    }
}

TEST(RipeTest, RSAOperations)
{
    for (const auto& item : RSATestData) {

        const int length = PARAM(0);
        const int lengthInBits = length / 8;
        std::stringstream ss;
        ss << "With " << lengthInBits << " bit keypair";
        TIMED_BLOCK(o, ss.str()) {
            auto& timer = o.timer;
            int expectedBase64Length = Ripe::expectedBase64Length(lengthInBits);
            const std::string data = PARAM(1);
            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "generate keypair");
            Ripe::KeyPair pair = Ripe::generateRSAKeyPair(length);
            std::string privateKey = pair.privateKey;
            std::string publicKey = pair.publicKey;

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "encrypt");
            // Encrypt
            std::string encryptedData = Ripe::encryptRSA(data, publicKey);
            ASSERT_EQ(encryptedData.size(), lengthInBits) << "Unable to encrypt RSA properly";
            std::string b64 = Ripe::base64Encode(encryptedData);
            ASSERT_EQ(b64.size(), expectedBase64Length);

            PERFORMANCE_CHECKPOINT_WITH_ID(timer, "decrypt");
            // Decrypt
            std::string decryptedData = Ripe::decryptRSA(encryptedData, privateKey);
            ASSERT_EQ(decryptedData.size(), data.size()) << "Unable to decrypt RSA properly (Decryption with " << decryptedData.size() << ")";
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
            ASSERT_EQ(encryptedDataFromFile.size(), encryptedData.size());

            // Decrypt file's data
            std::string decryptedDataFromFile = Ripe::decryptRSA(encryptedDataFromFile, privateKey.c_str());
            ASSERT_EQ(decryptedDataFromFile.size(), data.size()) << data << "\nUnable to decrypt RSA properly from the file (Decryption with " << decryptedDataFromFile.size() << ")";
            ASSERT_EQ(data, decryptedData);
        }

    }
}

#endif // RIPE_TEST_H
