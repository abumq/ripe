//
//  Ripe.cc
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#include <iomanip>
#include <sstream>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

#include "include/RipeCrypto.h"
#include "include/log.h"

INITIALIZE_EASYLOGGINGPP

using namespace CryptoPP;

using RipeRSA = RipeCrypto::RipeCPtr<RSA, decltype(&::RSA_free)>;
using RipeBigNum = RipeCrypto::RipeCPtr<BIGNUM, decltype(&::BN_free)>;
using RipeEVPKey = RipeCrypto::RipeCPtr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using RipeBio = RipeCrypto::RipeCPtr<BIO, decltype(&::BIO_free)>;

const int RipeCrypto::RSA_PADDING = RSA_PKCS1_PADDING;
const int RipeCrypto::AES_BSIZE = AES::BLOCKSIZE;
const long RipeCrypto::RIPE_RSA_3 = RSA_3;

static RipeRSA createRSA(byte* key, bool isPublic) noexcept
{
    RipeBio keybio(BIO_new_mem_buf(key, -1), ::BIO_free);
    if (keybio.get() == nullptr) {
        RLOG(ERROR) << "Failed to create key BIO";
        return RipeRSA(RSA_new(), ::RSA_free);
    }
    RSA* rawRSA = nullptr;
    if (isPublic) {
        rawRSA = PEM_read_bio_RSAPublicKey(keybio.get(), &rawRSA, nullptr, nullptr);
        if (rawRSA == nullptr) {
            // Try with other method (openssl issue)
            keybio = RipeBio(BIO_new_mem_buf(key, -1), ::BIO_free);
            rawRSA = PEM_read_bio_RSA_PUBKEY(keybio.get(), &rawRSA, nullptr, nullptr);
        }
    } else {
        rawRSA = PEM_read_bio_RSAPrivateKey(keybio.get(), &rawRSA, nullptr, nullptr);
        if (rawRSA != nullptr) {
            int keyCheck = RSA_check_key(rawRSA);
            if (keyCheck <= 0) {
                RLOG_IF(keyCheck == -1, ERROR) << "Failed to validate RSA key";
                RLOG_IF(keyCheck == 0, ERROR) << "Failed to validate RSA key. Please check length and exponent value";
                RipeCrypto::printLastError();
            }
        } else {
            RLOG(ERROR) << "Unexpected error while read private key";
        }
    }
    RipeRSA rsa(rawRSA, ::RSA_free);
    RLOG_IF(rsa.get() == nullptr, ERROR) << "Failed to read RSA " << (isPublic ? "public" : "private") << "key"; // continue
    return rsa;
}

bool RipeCrypto::writeRSAKeyPair(const char* publicOutputFile, const char* privateOutputFile, unsigned int length, unsigned long exponent) noexcept
{
    KeyPair keypair = RipeCrypto::generateRSAKeyPair(length, exponent);
    if (keypair.first.size() > 0 && keypair.second.size() > 0) {
        std::ofstream fs(privateOutputFile, std::ios::out);
        if (fs.is_open()) {
            fs.write(keypair.first.c_str(), keypair.first.size());
            fs.close();
        } else {
            RLOG(ERROR) << "Unable to open [" << privateOutputFile << "]";
            return false;
        }
        fs.open(publicOutputFile, std::ios::out);
        if (fs.is_open()) {
            fs.write(keypair.second.c_str(), keypair.second.size());
            fs.close();
        } else {
            RLOG(ERROR) << "Unable to open [" << publicOutputFile << "]";
            return false;
        }
        return true;
    }
    RLOG(ERROR) << "Key pair failed to generate";
    return false;
}

static bool getRSAString(RSA* rsa, bool isPublic, char** strPtr) noexcept
{
    EVP_CIPHER* enc = nullptr;
    int status;

    RipeBio bio = RipeBio(BIO_new(BIO_s_mem()), ::BIO_free);

    if (isPublic) {
        status = PEM_write_bio_RSA_PUBKEY(bio.get(), rsa);
    } else {
        status = PEM_write_bio_RSAPrivateKey(bio.get(), rsa, enc, nullptr, 0, nullptr, nullptr);
    }
    if (status != 1) {
        RLOG(ERROR) << "Unable to write BIO to memory";
        return false;
    }

    BIO_flush(bio.get());
    long size = BIO_get_mem_data(bio.get(), strPtr);
    BIO_set_close(bio.get(), BIO_NOCLOSE);
    return size > 0;
}

RipeCrypto::KeyPair RipeCrypto::generateRSAKeyPair(unsigned int length, unsigned long exponent) noexcept
{
    RipeRSA rsa(RSA_new(), ::RSA_free);
    int status;
    RipeBigNum bign(BN_new(), ::BN_free);
    status = BN_set_word(bign.get(), exponent);
    if (status != 1) {
        RLOG(ERROR) << "Could not set big numb (OpenSSL)";
        return std::make_pair("", "");
    }
    status = RSA_generate_key_ex(rsa.get(), length, bign.get(), nullptr);
    if (status != 1) {
        RLOG(ERROR) << "Could not generate RSA key";
        return std::make_pair("", "");
    }

    if (rsa.get() != nullptr) {
        int keyCheck = RSA_check_key(rsa.get());
        RLOG_IF(keyCheck == -1, ERROR) << "Failed to validate RSA key pair";
        RLOG_IF(keyCheck == 0, ERROR) << "Failed to validate RSA key. Please check length and exponent value";
    }

    RipeArray<char> priv(new char[length]);
    char* p = priv.get();
    getRSAString(rsa.get(), false, &p);
    std::string privStr(p);

    RipeArray<char> pub(new char[length]);
    char* pu = pub.get();
    getRSAString(rsa.get(), true, &pu);
    std::string pubStr(pu);
    return std::make_pair(privStr, pubStr);
}

int RipeCrypto::encryptRSA(byte* data, int dataLength, byte* key, byte* destination) noexcept
{
    RipeRSA rsa = createRSA(key, true);
    if (rsa.get() == nullptr) {
        return -1;
    }
    return RSA_public_encrypt(dataLength, data, destination, rsa.get(), RipeCrypto::RSA_PADDING);
}

int RipeCrypto::decryptRSA(byte* encryptedData, int dataLength, byte* key, byte* destination) noexcept
{
    RipeRSA rsa = createRSA(key, false);
    if (rsa.get() == nullptr) {
        return -1;
    }
    return RSA_private_decrypt(dataLength, encryptedData, destination, rsa.get(), RipeCrypto::RSA_PADDING);
}

void RipeCrypto::printLastError(const char* name) noexcept
{
    char errString[130];
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), errString);
    RLOG(ERROR) << name << " " << errString;
}

std::string RipeCrypto::base64Encode(const byte* input, std::size_t length)
{
    std::string encoded;
    // Crypto++ has built-in smart pointer, it won't leak this memory
    StringSource ss(input, length, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}

std::string RipeCrypto::base64Decode(const std::string& base64Encoded)
{
    std::string decoded;
    // Crypto++ has built-in smart pointer, it won't leak this memory
    StringSource ss(base64Encoded, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

std::string RipeCrypto::generateNewKey(int length)
{
    if (!(length == 16 || length == 24 || length == 32)) {
        throw std::invalid_argument( "Invalid key length. Acceptable lengths are 16, 24 or 32" );
    }
    AutoSeededRandomPool rnd;
    SecByteBlock key(length);
    rnd.GenerateBlock(key, key.size());
    std::string s;
    HexEncoder hex(new StringSink(s));
    hex.Put(key.data(), key.size());
    hex.MessageEnd();
    return s;
}

std::string RipeCrypto::encryptAES(const char* buffer, const byte* key, std::size_t keySize, std::vector<byte>& iv)
{
    SecByteBlock keyBlock(key, keySize);

#if 1
    std::string s2;
    HexEncoder h2(new StringSink(s2));
    h2.Put(keyBlock.data(), keyBlock.size());
    h2.MessageEnd();
    std::cout << "KEY BEFORE AutoSeededRandomPool: " << s2 << "\n";
#endif
    byte ivArr[RipeCrypto::AES_BSIZE] = {0};

    // DO NOT DEFINE AutoSeededRandomPool BEFORE INITIALIZING
    // SecByteBlock FROM KEY, IT CAUSES INTERMITTENT ISSUE WITH PADDING
    // invalid PKCS #7 block padding found
    AutoSeededRandomPool rnd;
    rnd.GenerateBlock(ivArr, sizeof ivArr);

#if 1
    std::string s;
    HexEncoder hex(new StringSink(s));
    hex.Put(keyBlock.data(), keyBlock.size());
    hex.MessageEnd();
    std::cout << " KEY AFTER AutoSeededRandomPool: " << s << "\n";
#endif
    std::string cipher;

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(keyBlock, keyBlock.size(), ivArr);

    // store for user
    iv.resize(sizeof ivArr);
    std::copy(std::begin(ivArr), std::end(ivArr), iv.begin());

    // The StreamTransformationFilter adds padding as required.
    StringSource ss(buffer, true,
                    new StreamTransformationFilter(e, new StringSink(cipher))
                    );
    return cipher;
}

std::string RipeCrypto::decryptAES(const char* buffer, const byte* key, std::size_t keySize, std::vector<byte>& iv)
{
    std::string result;
    SecByteBlock keyBlock(key, keySize);

    byte ivArr[RipeCrypto::AES_BSIZE] = {0};
    std::copy(iv.begin(), iv.end(), std::begin(ivArr));

    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(keyBlock, keyBlock.size(), ivArr);

    StringSource ss(buffer, true,
                new StreamTransformationFilter( d, new StringSink(result))
                );
    return result;
}
