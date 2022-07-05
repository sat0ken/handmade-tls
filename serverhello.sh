#!/bin/bash

data=$1
IFS=, packet=(${data//1[4,6,7]0303/,})

serverhello=$(printf "160303%s" ${packet[1]})
ccspec=$(printf "140303%s" ${packet[2]})
encextension=$(printf "170303%s" ${packet[3]})
certificate=$(printf "170303%s" ${packet[4]})
verify=$(printf "170303%s" ${packet[5]})
finished=$(printf "170303%s" ${packet[6]})

# print ServerHello
yq -n ".contentType = ${serverhello:0:2}"
yq -n ".version = ${serverhello:2:4}"
length="${serverhello:6:4}" yq -n '.length = env(length)'
random="${serverhello:22:64}" exlength="${serverhello:158:4}" version="${serverhello:162:4}" \
    group="${serverhello:182:4}" keyshare="${serverhello:190:64}" yq -n "
    (.handshakeProtocol.handshakeType = "${serverhello:10:2}") |
    (.handshakeProtocol.length = "${serverhello:12:6}") |
    (.handshakeProtocol.version = "${serverhello:18:4}") |
    (.handshakeProtocol.random) = env(random) |
    (.handshakeProtocol.sessionIDLength = "${serverhello:86:2}") |
    (.handshakeProtocol.sessionID = "${serverhello:88:64}") |
    (.handshakeProtocol.cipherSuite = "${serverhello:152:4}") |
    (.handshakeProtocol.compressionMethod = "${serverhello:156:2}") |
    (.handshakeProtocol.extensionLength = env(exlength)) |
    (.handshakeProtocol.extension[0].type = env(version)) |
    (.handshakeProtocol.extension[0].length = "${serverhello:166:4}") |
    (.handshakeProtocol.extension[0].supportedVersion= "${serverhello:170:4}") |
    (.handshakeProtocol.extension[1].type = "${serverhello:174:4}") |
    (.handshakeProtocol.extension[1].length= "${serverhello:178:4}") |
    (.handshakeProtocol.extension[1].keyShareExtension.group = env(group)) |
    (.handshakeProtocol.extension[1].keyShareExtension.keyExchangeLength = "${serverhello:186:4}") |
    (.handshakeProtocol.extension[1].keyShareExtension.keyExchange = env(keyshare))
"

echo ---

# print ChangeCipherSpec
yq -n ".contentType = ${ccspec:0:2}"
yq -n ".version = ${ccspec:2:4}"
yq -n ".length = ${ccspec:4:4}"
yq -n ".changeCipherSpecMessage = ${ccspec:8:2}"



#echo $encextension
#echo $certificate
#echo $verify
#echo $finished
