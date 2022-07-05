#!/bin/bash

# https://tls13.xargs.org/
# RFC8448の3. Simple 1-RTT Handshake

# TODO: opensslコマンドでセットするように要変更
#clientPrivateKey=0000000000000000000000000000000000000000000000000000000000000000
clientPrivateKey=$(openssl pkey -noout -text < private.key | grep priv -A3 | grep -v priv | sed -e "s/://g" -e "s/ //g" -z -e "s/\\n//g")

# TODO: yqコマンドでセットするように要変更 
serverPublicKey=325fa98558215b6e4b1af9d6ea4ba835b751ef5b050a78a1312c62e449df874e

# ECDHE鍵交換
sharedSecret=$(./x25519 -priv $clientPrivateKey -pub $serverPublicKey)
printf "sharedSecret is $sharedSecret\n"

# TODO: 要変更 
clientserverhello=010000c3030300000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000002130201000078000500050100000000000a00040002001d000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000100005000302683200120000002b0003020304003300260024001d0020807777060bdd942ecf28cb50788e5b3245df28a4093a708f6e80669ce0cd241702000076030301348be1037755cfb50a8671f5dea469392b4be02cbb2013ba0c55db2ff12ca6200000000000000000000000000000000000000000000000000000000000000000130200002e002b0002030400330024001d0020325fa98558215b6e4b1af9d6ea4ba835b751ef5b050a78a1312c62e449df874e
sha384HashedMessage=$(echo -n $clientserverhello | xxd -r -p |openssl sha384 | awk '{print $2}')

zerokey=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# early secretを作成
earlySecret=$(./hkdf-384.sh extract 00 $zerokey)
emptyHash=$(openssl sha384 < /dev/null | awk '{print $2}')

# derived secretを作成
derivedSecret=$(./hkdf-384.sh expandlabel $earlySecret "derived" $emptyHash 48)
printf "derivedSecret is $derivedSecret\n"
# handshake secretを作成
handshakeSecret=$(./hkdf-384.sh extract $derivedSecret $sharedSecret)
printf "handshakeSecret is $handshakeSecret\n"

clientHandshakeTraffic=$(./hkdf-384.sh expandlabel $handshakeSecret "c hs traffic" $sha384HashedMessage 48)
serverHandshakeTraffic=$(./hkdf-384.sh expandlabel $handshakeSecret "s hs traffic" $sha384HashedMessage 48)

clientFinishedKey=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "finished" "" 32)
serverFinishedKey=$(./hkdf-384.sh expandlabel $serverHandshakeTraffic "finished" "" 32)

clientHandshakeKey=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "key" "" 32)
serverHandshakeKey=$(./hkdf-384.sh  expandlabel $serverHandshakeTraffic "key" "" 32)

clientHandshakeIV=$(./hkdf-384.sh expandlabel $clientHandshakeTraffic "iv" "" 12)
serverHandshakeIV=$(./hkdf-384.sh expandlabel $serverHandshakeTraffic "iv" "" 12)

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
