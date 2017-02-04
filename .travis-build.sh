echo "plain text" | valgrind ./ripe -e --key my_key
echo "EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64
echo "313004c475a3986d2034e77542ab1d5b:123:EM+2WPE9fXxrna+Pyb0Ycw==" | valgrind ./ripe -d --key my_key --base64
valgrind ./ripe -g --rsa --out-private private.pem --out-public public.pem
echo 'plain text' | valgrind ./ripe -e --rsa --in-key public.pem
valgrind ./ripe -d --rsa --in-key private.pem --in /tmp/output.enc --base64
echo 'plain text' | ./ripe -e --base64
echo \"EM+2WPE9fXxrna+Pyb0Ycw==\" | valgrind ./ripe -d --key my_key --iv 313004c475a3986d2034e77542ab1d5b --base64

