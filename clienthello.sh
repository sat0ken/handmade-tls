#!/bin/bash

# DH鍵交換用に公開鍵を読み込む
keyshare=$(openssl pkey -noout -text < private.key | grep pub -A3 | grep -v pub | sed -e "s/://g" -e "s/ //g" -z -e "s/\\n//g")

# 公開鍵をTLS ExtensionのKeyshareにセットする
sed -i -e "s/KeyExchange: .*/KeyExchange: $keyshare/" chello.yaml

# CLiehtHelloメッセージを作成していく
chMessage=$(yq '[.HandshakeProtocol.Version, .HandshakeProtocol.Random]' chello.yaml | yq 'join("")')
chMessage+=$(yq '[.HandshakeProtocol.SessionIDLength, .HandshakeProtocol.SessionID]' chello.yaml | yq 'join("")')
chMessage+=$(yq '[.HandshakeProtocol.CipherSuitesLength]' chello.yaml | yq 'join("")')
chMessage+=$(yq '[.HandshakeProtocol.CipherSuites[0].CipherSuite]' chello.yaml | yq 'join("")')
chMessage+=$(yq '[.HandshakeProtocol.CompressionMethodLength, .HandshakeProtocol.CompressionMethod]' chello.yaml | yq 'join("")')

# TLS Extensionを読み込む
readarray tlsExtensions < <(yq '.HandshakeProtocol.Extension[]' chello.yaml)
for ex in "${tlsExtensions[@]}"; do
    extension+=$(echo $ex | cut -d":" -f2 | grep -v ^$ | sed -e "s/ //g")
done

extLen=$(expr $(echo ${#extension}) / 2)

chMessage+=$(printf "00%x" $extLen)
chMessage+=$extension

chMessageLen=$(expr $(echo ${#chMessage}) / 2)
chMessageLen=$(expr $(echo $chMessageLen))

# TLSレコードヘッダを作成
recordlayer=$(yq .ContentType chello.yaml)
recordlayer+=$(yq .Version chello.yaml)
recordlayer+=$(printf "00%x" $(expr $(echo $chMessageLen) + 4))
# レコードヘッダにClientHelloメッセージを追加
recordlayer+=$(yq .HandshakeProtocol.HandshakeType chello.yaml)
recordlayer+=$(printf "0000%x" $chMessageLen)
recordlayer+=$chMessage

echo $recordlayer
