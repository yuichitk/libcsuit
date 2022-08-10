#!/bin/bash

CBOR=./testfiles/suit_manifest_exp$1.cbor
MD=./testfiles/suit_manifest_exp$1.md
TITLE=$2
PARSER=./bin/suit_manifest_parser

ENVELOPE=`${PARSER} ${CBOR} 2 | egrep "^    " | sed -e "s/^    //g" -e "s/(verified)//g"`
HEX=`xxd -p ${CBOR}`

echo -e "\n## $2\n{: numbered='no'}\n\n### CBOR Diagnostic Notation of SUIT Manifest\n{: numbered='no'}\n\n~~~~\n${ENVELOPE}\n~~~~\n\n\n### CBOR Binary in Hex\n{: numbered='no'}\n\n~~~~\n${HEX}\n~~~~" > ${MD}
