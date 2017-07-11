
                                               ‫بسم الله الرَّحْمَنِ الرَّحِيمِ

![Ripe](https://raw.githubusercontent.com/muflihun/ripe/master/ripe.png?)

Ripe is a minimal security tool. It consists of command-line tool and C++ API for cryptography.

Ripe contains encryption API for two major cryptography methods, RSA and AES (Rijndael). Also contains Base64 encoding/decoding API and some helper functions to make data transferable (called `prepareData`). Binaries do not depend on third-party tools or libraries but development will require cryptography libraries installed in system in order to compile.

It is fully compatible with OpenSSL. See [openssl-compatibility.sh](/openssl-compatibility.sh)


[![Build Status (Develop)](https://img.shields.io/travis/muflihun/ripe/develop.svg)](https://travis-ci.org/muflihun/ripe) (`develop`)

[![Build Status (Master)](https://img.shields.io/travis/muflihun/ripe/master.svg)](https://travis-ci.org/muflihun/ripe) (`master`)
    
[![Version](https://img.shields.io/github/release/muflihun/ripe.svg)](https://github.com/muflihun/ripe/releases/latest)

[![Documentation](https://img.shields.io/badge/docs-doxygen-blue.svg)](https://muflihun.github.io/ripe)

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/muflihun/ripe/blob/master/LICENCE)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

## Options

| Option Name | Description |
|-------------|--------|
| `--version` | Display version information
| `-g`        | Generate key |
| `-e`        | Encrypt the data |
| `-d`        | Decrypt the data |
| `-s`        | Sign the data |
| `-v`        | Verify the signed data |
| `--aes` | Generate AES key (requires `-g`) |
| `--key`     | Symmetric key for encryption / decryption |
| `--in-key`     | Symmetric key for encryption / decryption file path |
| `--iv`      | Initializaion vector for decription       |
| `--rsa`      | Use RSA encryption/decryption      |
| `--zlib`      | ZLib compression/decompression      |
| `--raw`      | Raw output for rsa encrypted data      |
| `--base64`   | Tells ripe the data needs to be decoded before decryption (this can be used for decoding base64) |
| `--hex`   | Tells ripe the data is hex string |
| `--clean`   | (Only applicable when `--base64` data provided) Tells ripe to clean the data before processing |
| `--signature`    | Signature for verifying the data |
| `--in`    | Input file. You can also pipe in the data. In that case you do not have to provide this parameter |
| `--out`   | Tells ripe to store encrypted data in specified file. (Outputs IV in console) |
| `--length`   | Specify key length |
| `--secret`   | Secret key for encrypted private key (RSA only) |

## Getting Started

### Minimum Requirements
These are the requirements to build Ripe binaries. When you use it in your C++ application, you can do so without following dependencies, including older version of C++ as long as you the machine has dynamic library for `libstdc++`.

  * C++11
  * [Easylogging++ v9.94.1](https://github.com/muflihun/easyloggingpp)
  * [Crypto++ v5.6.5](https://www.cryptopp.com/) (with Pem Pack)
  * [CMake Toolchains](https://cmake.org/) 2.8.12

### Get Code
You can either [download code from master branch](https://github.com/muflihun/ripe/archive/master.zip) or clone it using `git`:

```
git clone git@github.com:muflihun/ripe.git
```

### Build
Residue uses the CMake toolchains to create makefiles.
Steps to build Ripe:

```
mkdir build
cd build
cmake ..
cmake -Dtest=ON ..
make
```

Please consider running unit test before you move on

```
make test
```

The compilation process creates executable (`ripe`) as well as shared libraries in build directory. You can install it in system-wide directory using:

```
make install
```

If the default path (`/usr/local`) is not where you want things installed, then set the `CMAKE_INSTALL_PREFIX` option when running cmake. e.g,

```
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/bin
```

### Static Linking
By default ripe builds as shared library, you can pass `build_static_lib` option in cmake to build static library.

For example

```
cmake -Dbuild_static_lib=ON ..
make
```

### Windows
You can do `cmake -Ddll_export=ON ...` to export symbols and `cmake -Ddll=ON ...` to import if needed

### If build fails...
Make sure you have read [minimum requirements](#minimum-requirements). You can install required Crypto++ v5.6.5 (with Pem Pack) using following commands

```
wget -O cryptocpp.tar.gz https://github.com/weidai11/cryptopp/archive/CRYPTOPP_5_6_5.tar.gz
tar xf cryptocpp.tar.gz
cd cryptopp-CRYPTOPP_5_6_5
wget -O pem_pack.zip https://raw.githubusercontent.com/muflihun/muflihun.github.io/master/downloads/Pem-pack.zip
unzip pem_pack.zip
cmake .
make
make install
```

and Easylogging++ using

```
wget -O easylogging++.zip https://github.com/muflihun/easyloggingpp/archive/master.zip
unzip easylogging++.zip
cd easyloggingpp-master/
cmake -Dtest=ON .
make
./easyloggingpp-unit-tests
make install
```

If `make install` fails because of permission try to run it as super-user `sudo make install`

## Examples

### Encryption (AES)
Following command will encrypt `sample.json` file to be ready to send to the server.

`echo "plain text" | ripe -e --key B1C8BFB9DA2D4FB054FE73047AE700BC`

You can specify binary file as destination that will save only encrypted data, e.g,

`echo "plain text" | ripe -e --key B1C8BFB9DA2D4FB054FE73047AE700BC --out sample.enc`

Above command will provide you with IV that you can use to decrypt

Please note: If you do not provide `--out`, the output will base64 and it will have four parts. `{LENGTH}:{IV}:{Client_ID}:{Base64_Encoded_Encrypted_Data}`.

### Decryption (AES)
Following command will decrypt `hkz20HKQA491wZqbEctxCA==` (`plain text`) that was supposedly encrypted using same key and init vector.

`echo "hkz20HKQA491wZqbEctxCA==" | ripe -d --key B1C8BFB9DA2D4FB054FE73047AE700BC --iv 88505d29e8f56bbd7c9e1408f4f42240 --base64`

You can also provide filename, e.g,

`ripe -d --key B1C8BFB9DA2D4FB054FE73047AE700BC --in sample.enc --iv 88505d29e8f56bbd7c9e1408f4f42240`

OR

`echo 88505d29e8f56bbd7c9e1408f4f42240:hkz20HKQA491wZqbEctxCA== | ripe -d --key B1C8BFB9DA2D4FB054FE73047AE700BC --base64`

### Generate AES Key
Following command will generate 128-bit AES key

```
ripe -g --aes 256
```

Alternatively you can do
```
ripe -g --aes --length 256
```

Valid keys sizes: `128-bit`, `192-bit`, `256-bit`

### Generate RSA Key
Following command will produce random RSA key pair

```
ripe -g --rsa --out-private private.pem --out-public public.pem
```

Alternatively you can use

```
ripe -g --rsa
```

This will give you two base64 strings with `:` as separator. First encoded text is base64 of newly generated private key and second being newly generated corresponding public key.

If you wish to generate private RSA key, you can use `--secret` parameter, e.g,

```
ripe -g --rsa --out-private private.pem --out-public public.pem --secret ppks
```

### Encryption (RSA)
You can encrypt the data using public key and decrypt with a private key

```
echo 'plain text' | ripe -e --rsa --in-key public.pem
```

You can also use `--out /tmp/output.enc` to save it to `/tmp/output.enc` file

You can also add `--raw` option to output raw data instead of base64 encoded

### Decryption (RSA)

```
ripe -d --rsa --in-key private.pem --in /tmp/output.enc --base64
```

Please note, decryption (RSA) is unstable at the moment, you may use following alternative command until it's fixed

```
cat /tmp/output.enc | openssl rsautl -decrypt -inkey private.pem --base64
```

#### Encrypted Keys
If you have an RSA key that is encrypted with pass phrase, let's say
```
openssl genrsa -des3 -out private.pem 2048
```

extract public key: `openssl rsa -in private.pem -outform PEM -pubout -out public.pem`

You can use `--secret` to decrypt it

for example

Encrypt:

```
echo ff | ripe -e --rsa --in-key public.pem
```

Decrypt (pass phrase we chose was ppks):

```
ripe -d --rsa --in-key private.pem --base64 --secret ppks
```

Failing to provide `--secret` option will give you error:

```
ERROR: PEM_Load: RSA private key is encrypted
```

### Signing

```
echo "my signed data" | ripe -s --rsa --in-key private.pem
```

### Verify

```
echo "my signed data" | ripe -v --rsa --in-key public.pem --signature SIGNATURE
```

### Base64 Encoding

You can use following commands to encode raw data to base64 encoding

```
echo 'plain text' | ripe -e --base64
```

### Base64 Decoding

In order to decode you may use `-d` option instead

```
echo 'cGxhaW4gdGV4dAo=' | ripe -d --base64
```

### Hex Encoding

You can use following to encode data to hex encoded string

```
echo 'plain text' | ripe -e --hex
```

### Hex Decoding

Decoding hex can be done using `-d` option

```
echo 706c61696e2074657874 | ripe -d --hex
```

### ZLib Compression
Compression using zlib can be done using `-e` option

```
echo abcd | ripe -e --zlib
```

You can provide `--base64` to see base64 output e.g, 

```
echo abcd | ripe -e --zlib --base64
```

Same with `--hex` (or both `--base64` and `--hex` - in this case you will get base64 encoding of hex output)

### ZLib Decompression
Decompression using zlib can be done using `-d` option

```
echo eNpLTEpOAQAD2AGL | ripe -d --zlib --base64
```
 
## Licence
```
The MIT License (MIT)

Copyright (c) 2017 Muflihun Labs

http://github.com/muflihun/
http://muflihun.com

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
