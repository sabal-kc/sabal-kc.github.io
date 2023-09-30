---
layout: post
title: Exploring a solution for a limitation of RSA encryption
date: 2023-06-01
description:
tags: golang encryption
categories: programming
featured: true
---

RSA algorithm is an asymmetric cryptography algorithm that consists of two different keys i.e. Public Key and Private Key. It is one of the most widely used encryption methods to securely transmit information. But it does have some limitations. In this article, I will aim to explain a solution to a problem that arose when trying to encrypt a response payload with this algorithm in golang.

To encrypt a response payload with a public key, the approach is to use the EncryptOAEP method from the "crypto/rsa" package. It is an Optimal Asymmetric Encryption Padding (OAEP) algorithm that takes in a random hash as the first parameter (sha256 hash is passed here). The second parameter consists of a random parameter to ensure entropy. Following these two parameters are the public key and the payload (bytes) that is to be encrypted. The final parameter is a label parameter (which does not get encrypted), this is passed as nil.

```go
rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, payload, nil)
```

This is a sound working approach. However, a limitation is that the message must be no longer than the length of the RSA modulus minus
twice the hash length, minus a further 2. Although it works perfectly fine for normal length messages, some payloads exceeded this limit and an error gets thrown: RS256 message too long for RSA public key size.

The two common solutions to this problem are:

1. Hybrid Encryption: In hybrid encryption, a combination of symmetric and asymmetric encryption is used. RSA is used to securely exchange a symmetric encryption key, which is then used to encrypt the actual message. This approach is commonly used in protocols like SSL/TLS for secure communication over the internet.

2. Chunking: Instead of encrypting the entire message as one block, the message is divided into smaller chunks or blocks. Each block is individually encrypted.
   The encryption is pretty straightforward, where we encrypt m bytes at a time as shown below:

```go
h := sha256.New()
m := maxPayloadSize(publicKey, h)
for len(payload) > 0 {
    // For the last chunk, go upto the length
    if m > len(payload) {
        m = len(payload)
    }

    // Encrypt m bytes at a time
    encChunk, err := rsa.EncryptOAEP(h, rand.Reader, publicKey, payload[:m], nil)
    if err != nil {
        return "", err
    }

    // Write to some output buffer
    encBytes.Write(encChunk)

    // Move forward
    payload = payload[m:]
}
```

Here, the max payload size is given by:

```go
func maxPayloadSize(key *rsa.PublicKey, hash hash.Hash) int {
	return key.Size() - 2*hash.Size() - 2
}
```

However, for decryption, the chunks must be traversed at a gap of the public key's length to get the correct result, not the max payload size, since the encrypted result would be of a different size in comparison to the original payload.

```go
h := sha256.New()
m := privateKey.PublicKey.Size()

for len(encBytes) > 0 {
    // For the last chunk, go upto the length
    if m > len(encBytes) {
        m = len(encBytes)
    }

    // Encrypt m bytes at a time
    decChunk, err := rsa.DecryptOAEP(h, nil, privateKey, encBytes[:m], nil)
    if err != nil {
        return nil, err
    }

    // Write to some output buffer
    decBytes.Write(decChunk)

    // Move forward
    encBytes = encBytes[m:]
}
```
