#!/bin/bash

data=$(cat resp.bin)
IFS=, packet=(${data//1[4,6,7]0303/,})

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
random="${serverhello:22:64}" exlength="${serverhello:158:4}" yq -n "
    (.HandshakeProtocol.HandshakeType = "${serverhello:10:2}") |
    (.HandshakeProtocol.Length = "${serverhello:12:6}") |
    (.HandshakeProtocol.Version = "${serverhello:18:4}") |
    (.HandshakeProtocol.Random) = env(random) |
    (.HandshakeProtocol.SessionIDLength = "${serverhello:86:2}") |
    (.HandshakeProtocol.SessionID = "${serverhello:88:64}") |
    (.HandshakeProtocol.CipherSuite = "${serverhello:152:4}") |
    (.HandshakeProtocol.CompressionMethod = "${serverhello:156:2}") |
    (.HandshakeProtocol.ExtensionLength = env(exlength))
"
version="${serverhello:162:4}" yq -n ".HandshakeProtocol.Extension[0].SupportedVersion = env(version)"


#echo $ccspec
#echo $encExtension
#echo $certificate
#echo $verify
#echo $finished
