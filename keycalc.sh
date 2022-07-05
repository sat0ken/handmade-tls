#!/bin/bash

# https://tls13.xargs.org/
# RFC8448の3. Simple 1-RTT Handshake

# TODO: opensslコマンドでセットするように要変更
#clientPrivateKey=0000000000000000000000000000000000000000000000000000000000000000
clientPrivateKey=$(openssl pkey -noout -text < private.key | grep priv -A3 | grep -v priv | sed -e "s/://g" -e "s/ //g" -z -e "s/\\n//g")
#clientPrivateKeyByte=$(echo -n $clientPrivateKey | xxd -r -p)

# TODO: yqコマンドでセットするように要変更
serverPublicKey=4f5ae45f0c7d382386de60d4486d7f56a9599f6a9faf326b10d894c1f9126553

# ECDHE鍵交換
sharedSecret=$(./x25519 -priv $clientPrivateKey -pub $serverPublicKey)
printf "sharedSecret is $sharedSecret\n"

# TODO: 要変更 
clientserverhello=010000c3030300000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000002130101000078000500050100000000000a00040002001d000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683200120000002b0003020304003300260024001d0020807777060bdd942ecf28cb50788e5b3245df28a4093a708f6e80669ce0cd241702000076030323551709f787a0f318c122ebd7d8be98d2b0809dcc1922d4e301e9c407bc257b200000000000000000000000000000000000000000000000000000000000000000130100002e002b0002030400330024001d00204f5ae45f0c7d382386de60d4486d7f56a9599f6a9faf326b10d894c1f9126553
sha256HashedMessage=$(echo -n $clientserverhello | xxd -r -p |openssl sha256 | awk '{print $2}')

zerokey=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# early secretを作成
earlySecret=$(./hkdf.sh extract 00 $zerokey)
emptyHash=$(openssl sha256 < /dev/null | awk '{print $2}')

# derived secretを作成
derivedSecret=$(./hkdf.sh expandlabel $earlySecret "derived" $emptyHash 32)
printf "derivedSecret is $derivedSecret\n"
# handshake secretを作成
handshakeSecret=$(./hkdf.sh extract $derivedSecret $sharedSecret)
printf "handshakeSecret is $handshakeSecret\n"

clientHandshakeTraffic=$(./hkdf.sh expandlabel $handshakeSecret "c hs traffic" $sha256HashedMessage 32)
serverHandshakeTraffic=$(./hkdf.sh expandlabel $handshakeSecret "s hs traffic" $sha256HashedMessage 32)

clientFinishedKey=$(./hkdf.sh expandlabel $clientHandshakeTraffic "finished" "" 32)
serverFinishedKey=$(./hkdf.sh expandlabel $serverHandshakeTraffic "finished" "" 32)

clientHandshakeKey=$(./hkdf.sh expandlabel $clientHandshakeTraffic "key" "" 32)
serverHandshakeKey=$(./hkdf.sh  expandlabel $serverHandshakeTraffic "key" "" 32)

clientHandshakeIV=$(./hkdf.sh expandlabel $clientHandshakeTraffic "iv" "" 12)
serverHandshakeIV=$(./hkdf.sh expandlabel $serverHandshakeTraffic "iv" "" 12)

printf "sha256HashedMessage is $sha256HashedMessage\n"
printf "clientHandshakeTraffic is $clientHandshakeTraffic\n"
printf "serverHandshakeTraffic is $serverHandshakeTraffic\n"
printf "clientHandshakeKey is $clientHandshakeKey\n"
printf "clientHandshakeIV is $clientHandshakeIV\n"
printf "serverHandshakeKey is $serverHandshakeKey\n"
printf "serverHandshakeIV is $serverHandshakeIV\n"

#echo $clientFinishedKey
#echo $serverFinishedKey

ckey="${clientHandshakeKey}" civ="${clientHandshakeIV}" skey="${serverHandshakeKey}" siv="${serverHandshakeIV}" yq -n "
    (.handshake.clientkey = env(ckey)) |
    (.handshake.clientiv = env(civ))|
    (.handshake.serverkey = env(skey)) |
    (.handshake.serveriv = env(siv))
"
cfin="${clientFinishedKey}" sfin="${serverFinishedKey}" yq -n "
    (.finished.clientkey = env(cfin)) |
    (.finished.serverkey =env(sfin))
"
