KEY=71997e8f17d7cdb111398cb3bef4a424
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Encryption"
echo
echo "plain text" | valgrind ./ripe -e --key $KEY
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Decryption"
echo
echo "W5AzyNWoxcXAzZQm1EWJUA==" | valgrind ./ripe -d --key $KEY --iv b9664b67f223fb18764dfa9e53ef9692 --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Decryption (echo)"
echo
echo "b9664b67f223fb18764dfa9e53ef9692:W5AzyNWoxcXAzZQm1EWJUA==" | valgrind ./ripe -d --key $KEY --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Key Generation"
valgrind ./ripe -g --aes 128
valgrind ./ripe -g --aes 192
valgrind ./ripe -g --aes 256
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Keypair Generation"
echo
valgrind ./ripe -g --rsa --out-private private.pem --out-public public.pem
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Encryption"
echo
echo 'plain text' | valgrind ./ripe -e --rsa --in-key public.pem --out output.enc
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Decryption"
echo
valgrind ./ripe -d --rsa --in-key private.pem --in output.enc --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Base64 Encoding"
echo
echo 'plain text' | valgrind ./ripe -e --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Base64 Decoding"
echo
echo 'cGxhaW4gdGV4dAo=' | valgrind ./ripe -d --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Hex Encoding"
echo
echo 'plain text' | valgrind ./ripe -e --hex
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Hex Decoding"
echo
echo '706C61696E2074657874' | valgrind ./ripe -d --hex
echo
echo 'abcd' | valgrind ./ripe -e --zlib
echo
echo 'eNpLTEpOAQAD2AGL' | valgrind ./ripe -d --zlib --base64
echo
echo 'abcd' | valgrind ./ripe -e --zlib --base64
echo
