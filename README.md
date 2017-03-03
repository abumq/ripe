
                                               ‫بسم الله الرَّحْمَنِ الرَّحِيمِ

![Ripe](https://raw.githubusercontent.com/muflihun/ripe/master/ripe.png?)

Ripe is a 256-bit security tool. It consists of command-line tool and C++ API for cryptography.

Ripe contains encryption API for two major cryptography methods, RSA and AES (Rijndael). Also contains Base64 encoding/decoding API and some helper functions to make data transferable (called `prepareData`). Binaries do not depend on third-party tools or libraries but development will require cryptography libraries installed in system in order to compile.
    
[![Build Status](https://img.shields.io/travis/muflihun/ripe.svg)](https://travis-ci.org/muflihun/ripe)

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
| `--aes` | Generate AES key (requires `-g`) |
| `--key`     | Symmetric key for encryption / decryption |
| `--in-key`     | Symmetric key for encryption / decryption file path |
| `--iv`      | Initializaion vector for decription       |
| `--rsa`      | Use RSA encryption/decryption (Must use `--in-key` with it)      |
| `--base64`   | Tells ripe the data needs to be decoded before decryption (this can be used for decoding base64) |
| `--clean`   | (Only applicable when `--base64` data provided) Tells ripe to clean the data before processing |
| `--in`    | Input file. You can also pipe in the data. In that case you do not have to provide this parameter |
| `--out`   | Tells ripe to store encrypted data in specified file. (Outputs IV in console) |
| `--length`   | Specify key length |
| `--secret`   | Secret key to decrypted encrypted private key |

## Getting Started

### Minimum Requirements
  * C++11
  * [Easylogging++ v9.94.1](https://github.com/muflihun/easyloggingpp)
  * Crypto++ with Pem Pack v5.6.5
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

The compilation process creates executable `ripe` in build directory. You can install it in system-wide directory using:

```
make install
```

If the default path (`/usr/local`) is not where you want things installed, then set the `CMAKE_INSTALL_PREFIX` option when running cmake. e.g,

```
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/bin
```

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

### Encryption (RSA)

You can encrypt the data using public key and decrypt with a private key

```
echo 'plain text' | ripe -e --rsa --in-key public.pem
```

(You can also use `--out /tmp/output.enc` to save it to `/tmp/output.enc` file

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
