echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Encryption"
echo
echo "plain text" | valgrind ./ripe -e --key my_key
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Decryption"
echo
echo "EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> AES Decryption (echo)"
echo
echo "313004c475a3986d2034e77542ab1d5b:123:EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./ripe -d --key my_key --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Keypair Generation"
echo
valgrind --leak-check=full --show-leak-kinds=all ./ripe -g --rsa --out-private private.pem --out-public public.pem
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Encryption"
echo
echo 'plain text' | valgrind --leak-check=full --show-leak-kinds=all ./ripe -e --rsa --in-key public.pem --out output.enc
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RSA Decryption"
echo
valgrind --leak-check=full --show-leak-kinds=all ./ripe -d --rsa --in-key private.pem --in output.enc --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Base64 Encoding"
echo
echo 'plain text' | valgrind ./ripe -e --base64
echo
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Base64 Decoding"
echo
echo 'cGxhaW4gdGV4dAo=' | ripe -d --base64
echo
