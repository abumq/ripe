# Ripe

Ripe is a 256-bit security tool to translate data for the server (or from the server). It is used to encrypt request before sending or decrypt the response from it.

### Options

| Option Name | Description |
|-------------|--------|
| `--version` | Display version information
| `--in`    | Input file. You can also pipe in the data. In that case you do not have to provide this parameter |
| `-g`        | Generate key |
| `-e`        | Encrypt the data |
| `-d`        | Decrypt the data |
| `--key`     | Symmetric key for encryption / decryption |
| `--in-key`     | Symmetric key for encryption / decryption file path |
| `--iv`      | Initializaion vector for decription       |
| `--rsa`      | Use RSA encryption/decryption (Must use `--in-key` with it)      |
| `--client-id`| Client ID when encrypting the data       |
| `--base64`   | Tells ripe the data needs to be decoded before decryption (this can be used for decoding base64) |
| `--out`   | Tells ripe to store encrypted data in specified file. (Outputs IV in console) |

### Encryption (AES)

Following command will encrypt `sample.json` file to be ready to send to the server.

`echo "plain text" | ripe -e --key my_key --client-id 123`

You can specify binary file as destination that will save only encrypted data, e.g,

`echo "plain text" | ripe -e --key my_key --out sample.enc`

Above command will provide you with IV that you can use to decrypt

Please note: If you do not provide `--out`, the output will base64 and it will have three parts. `{IV}:{Client_ID}:{Encrypted_Data (Base64)}`.

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

Most requests to residue are base64 encoded, you can use following commands to encode raw data to base64 encoding

```
echo 'plain text' | ripe -e --base64
```

### Base64 Decoding

In order to decode you may use `-d` option instead

```
echo 'cGxhaW4gdGV4dAo=' | ripe -d --base64
```

## Manual

Residue ripe is a quick tool that does not have a `man` page. Please refer to this document when needed.

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
