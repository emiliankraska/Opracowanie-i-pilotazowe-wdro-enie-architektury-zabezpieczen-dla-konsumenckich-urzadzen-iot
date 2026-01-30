#!/bin/bash

set -euo pipefail
SECRET=$(tpm2_nvread 0x1500016 -C 0x1500016 -P pcr:sha256:1=certs/measured.pcrvalues)
PCR1=$(tpm2_pcrread |grep "1 :" | awk -F' ' '{print $3}')
echo "The secret is: ${SECRET}"

AES_KEY=$(echo -n "$SECRET" | openssl dgst -sha256 -binary)


%echo "The AES_KEY is: ${AES_KEY}"


UNENCRYPTED_KEY="$(openssl enc -d -aes256 -pbkdf2 -in certs/client-dev.key.enc -pass "pass:${AES_KEY}")"

export UNENCRYPTED_KEY
export PCR1

./bin/client-dev

unset PCR1
unset UNENCRYPTED_KEY 





