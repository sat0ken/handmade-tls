#!/bin/bash

# https://tls13.xargs.org/
# RFC8448の3. Simple 1-RTT Handshake

# TODO: opensslコマンドでセットするように要変更
clietPrivateKey=49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005

# TODO: yqコマンドでセットするように要変更 
serverPublicKey=c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f

# ECDHE鍵交換
sharedSecret=$(./x25519 -priv $clietPrivateKey -pub $serverPublicKey)

# TODO: 要変更 
clientserverhello=010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304

sha256HashedMessage=$(echo -n $clientserverhello | xxd -r -p |openssl sha256 | awk '{print $2}')

zerokey=0000000000000000000000000000000000000000000000000000000000000000

# early secretを作成
earlySecret=$(./hkdf.sh extract 00 $zerokey)
emptyHash=$(openssl sha256 < /dev/null | awk '{print $2}')

# derived secretを作成
derivedSecret=$(./hkdf.sh expandlabel $earlySecret "derived" $emptyHash 32)

# handshake secretを作成
handshakeSecret=$(./hkdf.sh extract $derivedSecret $sharedSecret)

clientHandshakeTraffic=$(./hkdf.sh expandlabel $handshakeSecret "c hs traffic" $sha256HashedMessage 32)
serverHandshakeTraffic=$(./hkdf.sh expandlabel $handshakeSecret "s hs traffic" $sha256HashedMessage 32)

clientFinishedKey=$(./hkdf.sh expandlabel $clientHandshakeTraffic "finished" "" 32)
serverFinishedKey=$(./hkdf.sh expandlabel $serverHandshakeTraffic "finished" "" 32)

clientHandshakeKey=$(./hkdf.sh expandlabel $clientHandshakeTraffic "key" "" 32)
serverHandshakeKey=$(./hkdf.sh expandlabel $serverHandshakeTraffic "key" "" 32)

clientHandshakeIV=$(./hkdf.sh expandlabel $clientHandshakeTraffic "iv" "" 12)
serverHandshakeIV=$(./hkdf.sh expandlabel $serverHandshakeTraffic "iv" "" 12)

#echo $derivedSecret
#echo $handshakeSecret
#echo $sha256HashedMessage
#echo $clientHandshakeTraffic
#echo $serverHandshakeTraffic
#echo $clientHandshakeKey
#echo $clientHandshakeIV
#echo $serverHandshakeKey
#echo $serverHandshakeIV
#
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
