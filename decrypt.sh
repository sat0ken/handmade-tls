#!/bin/bash

key=$(yq .handshake.serverkey key.yaml)
iv=$(yq .handshake.serveriv key.yaml)

#certificate=$(yq 'select(document_index == 3)' shello.yaml | yq .encryptedApplicationData)
#echo $certificate

readarray certificate < <(yq 'select(document_index == 3)' shello.yaml)
for cert in "${certificate[@]}"; do
    encryptMessage+=$(echo $cert | cut -d":" -f2 | grep -v ^\# | grep -v ^$ | sed -e "s/ //g")
done

./tools/encrypt -key $key -iv $iv -seqnum 1 -dec $encryptMessage

