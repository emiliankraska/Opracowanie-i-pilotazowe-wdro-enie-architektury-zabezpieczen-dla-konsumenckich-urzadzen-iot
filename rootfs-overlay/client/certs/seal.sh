!/bin/bash
tpm2_pcrread -o measured.pcrvalues sha256:1

tpm2_createpolicy --policy-pcr -l sha256:1 -f measured.pcrvalues -L measured.policy


tpm2_nvdefine 0x1500016 -C o -s 32 -L measured.policy -a "policyread|policywrite"

tpm2_nvwrite 0x1500016 -C 0x1500016 -P pcr:sha256:1=measured.pcrvalues -i secret.bin
