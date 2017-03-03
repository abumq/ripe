#################################################=- KEY USING RIPE -=###################################################

# Generate keys with ripe
ripe -g --rsa --out-private private.pem --out-public public.pem

# Fix public key with openssl-cli (don't need this anymore)
# openssl rsa -in private.pem -pubout -out public.pem

# Encrypt using openssl-cli (Always 256 bytes)
echo 'plain text' | openssl rsautl -encrypt -pubin -inkey public.pem > /tmp/e.enc

# Decrypt using ripe
cat /tmp/e.enc | ripe -d --rsa --in-key private.pem

# Encrypt using ripe
echo 'plain text' | ripe -e --rsa --in-key public.pem --out /tmp/e.enc

# Decrypt using openssl-cli
cat /tmp/e.enc | ripe -d --base64 | openssl rsautl -decrypt -inkey private.pem

# Decrypt using ripe
cat /tmp/e.enc | ripe -d --rsa --in-key private.pem --base64

#################################################=- KEY USING OPENSSL -=###################################################

# Generate key pair with openssl-cli
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt using openssl-cli (Always 256 bytes)
echo 'plain text' | openssl rsautl -encrypt -pubin -inkey public.pem > /tmp/e.enc

# Decrypt using ripe
cat /tmp/e.enc | ripe -d --rsa --in-key private.pem

# Decrypt using openssl-cli
cat /tmp/e.enc | openssl rsautl -decrypt -inkey private.pem

# Encrypt using ripe
echo 'plain text' | ripe -e --rsa --in-key public.pem --out /tmp/e.enc

# Decrypt using openssl-cli
cat /tmp/e.enc | ripe -d --base64 | openssl rsautl -decrypt -inkey private.pem

# Decrypt using ripe
cat /tmp/e.enc | ripe -d --rsa --in-key private.pem --base64
