#!/bin/bash

data=$(cat resp.bin)
IFS=, packet=(${data//1[4,6,7]0303/,})

serverhello=$(printf "160303%s" ${packet[1]})
ccspec=$(printf "140303%s" ${packet[2]})
encExtension=$(printf "170303%s" ${packet[3]})
certificate=$(printf "170303%s" ${packet[4]})
verify=$(printf "170303%s" ${packet[5]})
finished=$(printf "170303%s" ${packet[6]})

# print ServerHello
yq -n ".ContentType = ${serverhello:0:2}"
yq -n ".Version = ${serverhello:2:4}"
length="${serverhello:6:4}" yq -n '.Length = env(length)'
random="${serverhello:22:64}" exlength="${serverhello:158:4}" version="${serverhello:162:4}" \
    group="${serverhello:182:4}" keyshare="${serverhello:190:64}" yq -n "
    (.HandshakeProtocol.HandshakeType = "${serverhello:10:2}") |
    (.HandshakeProtocol.Length = "${serverhello:12:6}") |
    (.HandshakeProtocol.Version = "${serverhello:18:4}") |
    (.HandshakeProtocol.Random) = env(random) |
    (.HandshakeProtocol.SessionIDLength = "${serverhello:86:2}") |
    (.HandshakeProtocol.SessionID = "${serverhello:88:64}") |
    (.HandshakeProtocol.CipherSuite = "${serverhello:152:4}") |
    (.HandshakeProtocol.CompressionMethod = "${serverhello:156:2}") |
    (.HandshakeProtocol.ExtensionLength = env(exlength)) |
    (.HandshakeProtocol.Extension[0].Type = env(version)) |
    (.HandshakeProtocol.Extension[0].Length = "${serverhello:166:4}") |
    (.HandshakeProtocol.Extension[0].SupportedVersion= "${serverhello:170:4}") |
    (.HandshakeProtocol.Extension[1].Type = "${serverhello:174:4}") |
    (.HandshakeProtocol.Extension[1].Length= "${serverhello:178:4}") |
    (.HandshakeProtocol.Extension[1].KeyShareExtension.Group = env(group)) |
    (.HandshakeProtocol.Extension[1].KeyShareExtension.KeyExchangeLength = "${serverhello:186:4}") |
    (.HandshakeProtocol.Extension[1].KeyShareExtension.KeyExchange = env(keyshare))
"

echo ---

# print ChangeCipherSpec
yq -n ".ContentType = ${ccspec:0:2}"
yq -n ".Version = ${ccspec:2:4}"
yq -n ".Length = ${ccspec:4:4}"
yq -n ".ChangeCipherSpecMessage = ${ccspec:8:2}"



#echo $encExtension
#echo $certificate
#echo $verify
#echo $finished
