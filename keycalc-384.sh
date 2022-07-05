#!/bin/bash

# https://tls13.xargs.org/
# RFC8448の3. Simple 1-RTT Handshake

clientserverhello=$(./clienthello.sh | tail -c +11)
clientserverhello+=$1
sha384HashedMessage=$(echo -n $clientserverhello | xxd -r -p |openssl sha384 | awk '{print $2}')

clientPrivateKey=$(openssl pkey -noout -text < private.key | grep priv -A3 | grep -v priv | sed -e "s/://g" -e "s/ //g" -z -e "s/\\n//g")
length=${#1}
startlength=$(expr $length - 64)
# ServerHelloの末尾にある32byteのKeyshareをセット
serverPublicKey=${1:$startlength:64}

# ECDHE鍵交換
sharedSecret=$(./tools/x25519 -priv $clientPrivateKey -pub $serverPublicKey)
#printf "sharedSecret is $sharedSecret\n"

zerokey=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# early secretを作成
earlySecret=$(./hkdf-384.sh extract 00 $zerokey)
emptyHash=$(openssl sha384 < /dev/null | awk '{print $2}')

# derived secretを作成
derivedSecret=$(./hkdf-384.sh expandlabel $earlySecret "derived" $emptyHash 48)

# handshake secretを作成
handshakeSecret=$(./hkdf-384.sh extract $derivedSecret $sharedSecret)

clientHandshakeTraffic=$(./hkdf-384.sh expandlabel $handshakeSecret "c hs traffic" $sha384HashedMessage 48)
serverHandshakeTraffic=$(./hkdf-384.sh expandlabel $handshakeSecret "s hs traffic" $sha384HashedMessage 48)

clientFinishedKey=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "finished" "" 32)
serverFinishedKey=$(./hkdf-384.sh expandlabel $serverHandshakeTraffic "finished" "" 32)

clientHandshakeKey=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "key" "" 32)
serverHandshakeKey=$(./hkdf-384.sh  expandlabel $serverHandshakeTraffic "key" "" 32)

clientHandshakeIV=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "iv" "" 12)
serverHandshakeIV=$(./hkdf-384.sh expandlabel $serverHandshakeTraffic "iv" "" 12)

#printf "derivedSecret is $derivedSecret\n"
#printf "handshakeSecret is $handshakeSecret\n"
#printf "sha384HashedMessage is $sha384HashedMessage\n"
#printf "clientHandshakeTraffic is $clientHandshakeTraffic\n"
#printf "serverHandshakeTraffic is $serverHandshakeTraffic\n"
#printf "clientHandshakeKey is $clientHandshakeKey\n"
#printf "clientHandshakeIV is $clientHandshakeIV\n"
#printf "serverHandshakeKey is $serverHandshakeKey\n"
#printf "serverHandshakeIV is $serverHandshakeIV\n"

if [ -e "./key.yaml" ]; then
  rm ./key.yaml
fi

ckey="${clientHandshakeKey}" civ="${clientHandshakeIV}" skey="${serverHandshakeKey}" siv="${serverHandshakeIV}" yq -n "
    (.handshake.clientkey = env(ckey)) |
    (.handshake.clientiv = env(civ))|
    (.handshake.serverkey = env(skey)) |
    (.handshake.serveriv = env(siv))
" >> key.yaml

cfin="${clientFinishedKey}" sfin="${serverFinishedKey}" yq -n "
    (.finished.clientkey = env(cfin)) |
    (.finished.serverkey =env(sfin))
" >> key.yaml
