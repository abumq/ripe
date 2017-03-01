//
//  Ripe tool
//
//  Copyright © 2017 Muflihun.com. All rights reserved.
//

#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "include/RipeHelpers.h"

static int LENGTH = 2048;

void displayUsage()
{
    std::cout << "ripe [-d | -e | -g] [--in <input_file_path>] [--key <key>] [--in-key <file_path>] [--out-public <output_file_path>] [--out-private <output_file_path>] [--iv <init vector>] [--base64] [--rsa] [--length] [--out <output_file_path>] [--length-included]" << std::endl;
}

void displayVersion()
{
    std::cout << "Ripe - 256-bit security tool" << std::endl << "Version: " << RIPE_VERSION << std::endl << "http://muflihun.com" << std::endl;
}

void encryptAES(std::string& data, const std::string& key, const std::string& clientId, const std::string& outputFile)
{
    std::cout << RipeHelpers::encryptAES(data, key, clientId, outputFile);
}

void decryptAES(std::string& data, const std::string& key, std::string& iv, bool isBase64)
{
    std::cout << RipeHelpers::decryptAES(data, key, iv, isBase64);
}

void encodeBase64(std::string& data)
{
    std::cout << RipeHelpers::encodeBase64(data);
}

void decodeBase64(std::string& data)
{
    std::cout << RipeHelpers::decodeBase64(data);
}

void encryptRSA(std::string& data, const std::string& key, const std::string& outputFile)
{
    std::cout << RipeHelpers::encryptRSA(data, key, outputFile, LENGTH);
}

void decryptRSA(std::string& data, const std::string& key, bool isBase64)
{
    std::cout << RipeHelpers::decryptRSA(data, key, isBase64, LENGTH);
}

void writeRSAKeyPair(const std::string& publicFile, const std::string& privateFile)
{
    RipeHelpers::writeRSAKeyPair(publicFile, privateFile, LENGTH);
}

void generateRSAKeyPair()
{
    std::cout << RipeHelpers::generateRSAKeyPair(LENGTH);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        displayUsage();
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0) {
        displayVersion();
        return 0;
    }

    // This is quick check for args, use getopt in future
    int type = -1; // Decryption or encryption

    std::string key;
    std::string publicKeyFile;
    std::string privateKeyFile;
    std::string iv;
    std::string data;
    std::string clientId;
    bool isBase64 = false;
    bool lengthIncluded = false;
    bool isRSA = false;
    std::string outputFile;
    bool fileArgSpecified = false;

    for (int i = 0; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-d" && type == -1) {
            type = 1;
        } else if (arg == "-e" && type == -1) {
            type = 2;
        } else if (arg == "-g" && type == -1) {
            type = 3;
        } else if (arg == "--base64" && i < argc) {
            isBase64 = true;
        } else if (arg == "--rsa" && i < argc) {
            isRSA = true;
        } else if (arg == "--key" && i < argc) {
            key = argv[++i];
        } else if (arg == "--length" && i < argc) {
            LENGTH = atoi(argv[++i]);
        } else if (arg == "--length-included" && i < argc) {
            lengthIncluded = true;
        } else if (arg == "--out-public" && i < argc) {
            publicKeyFile = argv[++i];
        } else if (arg == "--out-private" && i < argc) {
            privateKeyFile = argv[++i];
        } else if (arg == "--in-key" && i < argc) {
            std::fstream fs;
            // Do not increment i here as we are only changing 'data'
            fs.open (argv[i + 1], std::fstream::binary | std::fstream::in);
            key = std::string((std::istreambuf_iterator<char>(fs)),
                            (std::istreambuf_iterator<char>()));
            fs.close();
        } else if (arg == "--out" && i < argc) {
            outputFile = argv[++i];
        } else if (arg == "--iv" && i < argc) {
            iv = argv[++i];
        } else if (arg == "--client-id" && i < argc) {
            clientId = argv[++i];
        } else if (arg == "--in" && i < argc) {
            fileArgSpecified = true;
            std::fstream fs;
            // Do not increment i here as we are only changing 'data'
            fs.open (argv[i + 1], std::fstream::binary | std::fstream::in);
            data = std::string((std::istreambuf_iterator<char>(fs) ),
                            (std::istreambuf_iterator<char>()));
            fs.close();
        }
    }

    if ((type == 1 || type == 2) && !fileArgSpecified) {
        std::stringstream ss;
        for (std::string line; std::getline(std::cin, line);) {
            ss << line << std::endl;
        }
        data = ss.str();
        // Remove last 'new line'
        data.erase(data.size() - 1);
    }

    if (lengthIncluded) {
        data.erase(0, data.find_first_of(':') + 1);
    }

    if (type == 1) { // Decrypt / Decode
        if (isBase64 && key.empty() && iv.empty()) {
            // base64 decode
            decodeBase64(data);
        } else if (isRSA) {
            // RSA decrypt (base64-flexiable)
            decryptRSA(data, key, isBase64);
        } else {
            // AES decrypt (base64-flexible)
            decryptAES(data, key, iv, isBase64);
        }
    } else if (type == 2) { // Encrypt / Encode
        if (isBase64 && key.empty() && iv.empty()) {
            encodeBase64(data);
        } else if (isRSA) {
            encryptRSA(data, key, outputFile);
        } else {
            encryptAES(data, key, clientId, outputFile);
        }
    } else if (type == 3) { // Generate
        if (isRSA) {
            if (publicKeyFile.empty() && privateKeyFile.empty()) {
                generateRSAKeyPair();
            } else if (publicKeyFile.empty() || privateKeyFile.empty()) {
                std::cout << "ERROR: Please provide both private and public key files [out-public] and [out-private]" << std::endl;
            } else {
                writeRSAKeyPair(publicKeyFile, privateKeyFile);
            }
        } else {
            std::cout << "ERROR: Please provide method (you probably forgot '--rsa')" << std::endl;
        }
    } else {
        displayUsage();
        return 1;
    }
    return 0;
}
