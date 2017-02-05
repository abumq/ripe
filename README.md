
                                               ‫بسم الله الرَّحْمَنِ الرَّحِيمِ

![Ripe](https://raw.githubusercontent.com/muflihun/ripe/master/ripe.png?)

Ripe is a 256-bit security tool.
    
[![Build Status](https://img.shields.io/travis/muflihun/ripe.svg)](https://travis-ci.org/muflihun/ripe)

[![Licence (MIT)](https://img.shields.io/license/muflihun/ripe.svg)](https://github.com/muflihun/ripe/blob/master/LICENSE)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

## Options

| Option Name | Description |
|-------------|--------|
| `--version` | Display version information
| `-g`        | Generate key |
| `-e`        | Encrypt the data |
| `-d`        | Decrypt the data |
| `--key`     | Symmetric key for encryption / decryption |
| `--in-key`     | Symmetric key for encryption / decryption file path |
| `--iv`      | Initializaion vector for decription       |
| `--rsa`      | Use RSA encryption/decryption (Must use `--in-key` with it)      |
| `--base64`   | Tells ripe the data needs to be decoded before decryption (this can be used for decoding base64) |
| `--in`    | Input file. You can also pipe in the data. In that case you do not have to provide this parameter |
| `--out`   | Tells ripe to store encrypted data in specified file. (Outputs IV in console) |

## Installation

### Dependencies
  * C++11 (or higher)
  * Easylogging++ v9.93 (or higher)
  * OpenSSL v1.0.2 (or higher)
  * [CMake Toolchains](https://cmake.org/) 2.8.12 (or higher)
 
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

`echo "plain text" | ripe -e --key my_key`

You can specify binary file as destination that will save only encrypted data, e.g,

`echo "plain text" | ripe -e --key my_key --out sample.enc`

Above command will provide you with IV that you can use to decrypt

Please note: If you do not provide `--out`, the output will base64 and it will have three parts. `{IV}:{Client_ID}:{Base64_Encoded_Encrypted_Data}`.

### Decryption (AES)

Following command will decrypt `EM+2WPE9fXxrna+Pyb0Ycw==` (`plain text`) that was supposedly encrypted using same key and init vector.

`echo "EM+2WPE9fXxrna+Pyb0Ycw==" | ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64`

You can also provide filename, e.g,

`ripe -d --key my_key --in sample.enc --iv 313004c475a3986d2034e77542ab1d5b`

OR

`echo "313004c475a3986d2034e77542ab1d5b:123:EM+2WPE9fXxrna+Pyb0Ycw==" | ripe -d --key my_key --base64`

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

Copyright (c) 2017 muflihun.com

http://github.com/muflihun/
http://easylogging.muflihun.com
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
