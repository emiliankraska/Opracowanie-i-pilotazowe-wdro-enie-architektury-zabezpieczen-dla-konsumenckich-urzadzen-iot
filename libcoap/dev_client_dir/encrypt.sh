!/bin/bash

set -euo pipefail
SECRET=$(tpm2_nvread 0x1500016 -C 0x1500016 -P pcr:sha256:0,1,2=measured.pcrvalues)

echo "The secret is: ${SECRET}"

AES_KEY=$(echo -n "$SECRET" | openssl dgst -sha256 -binary)


echo "The AES_KEY is: ${AES_KEY}"

openssl enc -aes256 -pbkdf2 -in client-dev.key -out client-dev.key.enc -pass "pass:${AES_KEY}"