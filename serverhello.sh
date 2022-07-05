#!/bin/bash

data=$1
IFS=, packet=(${data//1[4,6,7]0303/,})

serverhello=$(printf "160303%s" ${packet[1]})
ccspec=$(printf "140303%s" ${packet[2]})
encextension=$(printf "170303%s" ${packet[3]})
certificate=$(printf "170303%s" ${packet[4]})
verify=$(printf "170303%s" ${packet[5]})
finished=$(printf "170303%s" ${packet[6]})

if [ -e "./shello.yaml" ]; then
  rm ./shello.yaml
fi

# print ServerHello
echo "# ServreHello" >> shello.yaml
yq -n ".contentType = ${serverhello:0:2}" >> shello.yaml
yq -n ".version = ${serverhello:2:4}" >> shello.yaml
length="${serverhello:6:4}" yq -n '.length = env(length)' >> shello.yaml

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
" >> shello.yaml

# print ChangeCipherSpec
echo --- >> shello.yaml
echo "# ChangeCipherSpec" >> shello.yaml
yq -n ".contentType = ${ccspec:0:2}" >> shello.yaml
yq -n ".version = ${ccspec:2:4}" >> shello.yaml
yq -n ".length = ${ccspec:4:4}" >> shello.yaml
yq -n ".changeCipherSpecMessage = ${ccspec:8:2}" >> shello.yaml

# print Encrypted Extensions
echo --- >> shello.yaml
echo "# ApplicationData(暗号化されたEncryptedExtensions)" >> shello.yaml
yq -n ".opaqueType = ${encextension:0:2}" >> shello.yaml
yq -n ".version = ${encextension:2:4}" >> shello.yaml
yq -n ".length = ${encextension:6:4}" >> shello.yaml
appdata="${encextension:10:64}" yq -n ".encryptedApplicationData = env(appdata)" >> shello.yaml

#print ServerCertificate
echo --- >> shello.yaml
echo "# ApplicationData(暗号化されたCertificate)" >> shello.yaml
yq -n ".opaqueType = ${certificate:0:2}" >> shello.yaml
yq -n ".version = ${certificate:2:4}" >> shello.yaml
#yq -n ".length = ${certificate:6:4}" >> shello.yaml
echo "length: ${certificate:6:4}" >> shello.yaml
length=$(expr $(printf %d "0x${certificate:6:4}") \* 2)
appdata="${certificate:10:$length}" yq -n ".encryptedApplicationData = env(appdata)" >> shello.yaml

#print ServerCertificateVerify
echo --- >> shello.yaml
echo "# ApplicationData(暗号化されたCertificateVerify)" >> shello.yaml
yq -n ".opaqueType = ${verify:0:2}" >> shello.yaml
yq -n ".version = ${verify:2:4}" >> shello.yaml
echo "length: ${verify:6:4}" >> shello.yaml
length=$(expr $(printf %d "0x${verify:6:4}") \* 2)
appdata="${verify:10:$length}" yq -n ".encryptedApplicationData = env(appdata)" >> shello.yaml

#print Finished
echo --- >> shello.yaml
echo "# ApplicationData(暗号化されたFinished message)" >> shello.yaml
yq -n ".opaqueType = ${finished:0:2}" >> shello.yaml
yq -n ".version = ${finished:2:4}" >> shello.yaml
echo "length: ${finished:6:4}" >> shello.yaml
length=$(expr $(printf %d "0x${finished:6:4}") \* 2)
appdata="${finished:10:$length}" yq -n ".encryptedApplicationData = env(appdata)" >> shello.yaml
