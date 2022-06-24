#!/bin/bash

data=$(cat resp.bin)
IFS=, packet=(${data//1[4,6,7]0303/,})

#for p in "${packet[@]}"; do
#    if [ -n $p ]; then
#        echo $p
#    fi
#done

serverhello=$(printf "160303%s" ${packet[1]})
ccspec=$(printf "140303%s" ${packet[2]})
encExtension=$(printf "170303%s" ${packet[3]})
certificate=$(printf "170303%s" ${packet[4]})
verify=$(printf "170303%s" ${packet[5]})
finished=$(printf "170303%s" ${packet[6]})


# ServerHello
yq -n ".ContentType = ${serverhello:0:2}"
yq -n ".Version = ${serverhello:2:4}"
length="${serverhello:6:4}" yq -n '.Length = env(length)'
yq -n ".HandshakeProtocol.HandshakeType = ${serverhello:10:2}"
printf "  Length: %s\n" "${serverhello:12:6}" 
printf "  Version: %s\n" "${serverhello:18:4}" 
printf "  Random: %s\n" "${serverhello:22:64}"
printf "  SessionIDLength: %s\n" "${serverhello:86:2}"
printf "  SessionID: %s\n" "${serverhello:88:64}"
printf "  CipherSuite: %s\n" "${serverhello:152:4}"
printf "  CompressionMethod: %s\n" "${serverhello:156:2}"
printf "  ExtensionLength: %s\n" "${serverhello:158:4}"

#echo $ccspec
#echo $encExtension
#echo $certificate
#echo $verify
#echo $finished
