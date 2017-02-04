echo "plain text" | valgrind ./build/ripe -e --key my_key
echo "EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./build/ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64
echo "313004c475a3986d2034e77542ab1d5b:123:EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./build/ripe -d --key my_key --base64
valgrind ./build/ripe -g --rsa --out-private private.pem --out-public public.pem
echo 'plain text' | valgrind ./build/ripe -e --rsa --in-key public.pem
valgrind ./build/ripe -d --rsa --in-key private.pem --in /tmp/output.enc --base64
echo 'plain text' | ./build/ripe -e --base64
echo \"EM+2WPE9fXxrna+Pyb0Ycw==\" | valgrind ./build/ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64

