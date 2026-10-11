# LibP2PCrypto

[![](https://img.shields.io/badge/made%20by-Breth-blue.svg?style=flat-square)](https://breth.app)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats)
[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-blue.svg?style=flat-square)](https://github.com/apple/swift-package-manager)
![Build & Test (macos and linux)](https://github.com/swift-libp2p/swift-libp2p-crypto/actions/workflows/build+test.yml/badge.svg)

> Core LibP2P cryptography API for interacting with various Keys, Hashes and Ciphers 

## Table of Contents

- [Overview](#overview)
- [Disclaimer](#disclaimer)
- [Install](#install)
- [Usage](#usage)
  - [Example](#example)
  - [API](#api)
- [Contributing](#contributing)
- [Credits](#credits)
- [Resources](#resources)
  - [Links](#links) 
- [License](#license)

## Overview
LibP2PCrypto is an API / abstraction layer for commonly used cryptography within the LibP2P ecosystem. 
This library...
- Wraps Public Private Key Pairs such as RSA, ED25519, Secp256k1 and ECDSA (P-256, P-384 & P-521) keys in a common KeyPair class that can perform signing and signature verification without having to worry about the nuances of each algorithm. 
- Tries to make importing PEM, CERTIFICATES and DER files a little easier. 
- Provides methods for Marshaling Public and Private Keys for use in LibP2P PeerIDs and CIDs. 
- Makes various HMAC and AES Ciphers available under a common API as well.

#### Note:
This package currently doesn't support Blake2b, Blake2s & Blake3. If you're up for the challenge, please feel free to add support!

#### Secp256k1 Signatures:
As specified by libp2p, Secp256k1 signatures are ECDSA signatures over the SHA-256 hash of the message, DER encoded, and non-canonical (high-S) signatures are rejected. The pre 0.3.0 releases produced keccak256 hashed, 65 byte `v || r || s` recoverable signatures, which aren't compatible with other libp2p implementations and are no longer accepted.

#### ECDSA Keys:
ECDSA keys follow the libp2p spec and go-libp2p, public keys are marshaled as DER encoded SubjectPublicKeyInfo structures, private keys as DER encoded SEC1 ECPrivateKey structures, and messages are hashed with SHA-256 (regardless of the curve) before being signed, producing DER encoded signatures. P-256 is the default curve.

#### RSA Keys:
RSA keys are backed by swift-crypto's `_RSA` on every platform. Signatures are RSASSA-PKCS1-v1_5 over SHA-256 and encryption uses RSAES-PKCS1-v1_5, as specified by libp2p. Keys must be between 2048 and 8192 bits (`RSABitLength.supportedBitRange`), matching go-libp2p, both when generating and when importing keys.

#### Encrypted PEMs:
Encrypted private key PEMs are PKCS#8 `ENCRYPTED PRIVATE KEY` (PBES2) files. New exports default to PBKDF2-HMAC-SHA256 (310,000 iterations, 16 byte salt) with AES-256-CBC, matching OpenSSL 3's `openssl pkcs8 -topk8`. Imports support PBKDF2 with HMAC-SHA1/224/256/384/512 and AES-128/256-CBC.

## Install

Include the following dependency in your Package.swift file
```Swift
let package = Package(
    ...
    dependencies: [
        ...
        .package(url: "https://github.com/swift-libp2p/swift-libp2p-crypto.git", .upToNextMinor(from: "0.3.0"))
    ],
    ...
        .target(
            ...
            dependencies: [
                ...
                .product(name: "LibP2PCrypto", package: "swift-libp2p-crypto"),
            ]),
    ...
)
```

## Usage

### Example 
check out the [tests](https://github.com/SwiftEthereum/libp2p-crypto/blob/main/Tests/libp2p-cryptoTests/libp2p_cryptoTests.swift) for more examples

```Swift

import LibP2PCrypto

/// Generate a new Public / Private Key Pair
let rsaKeyPair = try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .b2048))
rsaKeyPair.keyType          // -> .rsa
rsaKeyPair.publicKey        // -> CommonPublicKey
rsaKeyPair.publicKey.data   // -> raw public key data
rsaKeyPair.privateKey       // -> optional(CommonPrivateKey)
rsaKeyPair.attributes()     // -> RSA (2048 bit) private key (2048 bits)

/// Key Types
try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .b2048))    // RSA w/ Bit Options... 2048, 3072, 4096, 8192 or .custom(bits:) (2048-8192)
try LibP2PCrypto.Keys.generateKeyPair(.ed25519)              // Ed25519 Elliptic Key
try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)            // Secp256k1 Key
try LibP2PCrypto.Keys.generateKeyPair(.ecdsa(curve: .p256))  // ECDSA w/ Curve Options... p256 (default), p384, p521

/// Wrap a key you already have
let keyPair = try LibP2PCrypto.Keys.KeyPair(privateKey: P256.Signing.PrivateKey())

/// Importing Marshalled Keys (if you pass in a public key, the private key will be nil, if you pass in a private key, both public and private keys will be imported/extracted)
let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKeyData)
let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKeyData)
let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKeyAsBase64String, base: .base64Pad) // Or you can use a String encoding of the key data

/// Importing PEM files (PEM, Encrypted PEM, DER and CERTIFICATES are supported. See the tests for more examples...)
let pem = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
-----END PUBLIC KEY-----
"""

let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

keyPair.keyType     // -> .ed25519
keyPair.publicKey   // -> Public Key (can be used for verifying signed messages...)
keyPair.privateKey  // -> nil (private key is nil when importing public keys...)

/// You can import encrypted PEM files as well...
let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: encryptedPem, password: "mypassword")

/// Or import a PEM directly into a specific key type
let publicKey = try Curve25519.Signing.PublicKey(pem: pem)

/// Once you have a KeyPair, you can use it to.... 

/// Sign & Verify Messages 
let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
let message = Data("Hello, world!".utf8)
let signedData = try keyPair.sign(message: message)

if try keyPair.verify(signature: signedData, for: message) {
 // The signature is valid! It means that the public key used to verify the signed message was derived from the same private key that signed the message
} else { 
 // Invalid signature. This public key does not belong to the private key that signed the message. 
}

/// If you want to share the public key, you can export it by marshaling it 
try keyPair.publicKey.marshal()

/// If you want to safely store the Private key between sessions you can export it as an encrypted PEM String
/// (PBKDF2-HMAC-SHA256 + AES-256-CBC by default, see `usingPBKDF:` and `andCipher:` to customize)
try keyPair.exportEncryptedPrivatePEMString(withPassword: "mypassword")

/// AES-CBC Cipher
let message = "Hello World!"
let key256  = "12345678901234561234567890123456"   // 32 bytes for AES256 (or 16 bytes for AES128)
let iv      = "abcdefghijklmnop"                   // 16 bytes

let aes256Key = try LibP2PCrypto.AES.AESKey(key: key256, iv: iv)

let encrypted = try aes256Key.encrypt(message)                         // The IV is prepended to the ciphertext
let decrypted = try aes256Key.decrypt(encrypted, intoString: .utf8)    // So any AESKey with the same key can decrypt it

/// AES GCM 
let message = "Hello World!"
let encrypted = try message.encryptGCM(password: "mypassword")
let decrypted = try encrypted.decryptGCM(password: "mypassword")

/// HMAC (Hashed Message Authentication Codes)
let message = "Hello World!"
let key = "secret"   // The secret can also be `Data` or a `SymmetricKey`
let hmacKeyLocal = LibP2PCrypto.HMAC.HMACKey(algorithm: .sha256, secret: key)
let hmacKeyRemote = LibP2PCrypto.HMAC.HMACKey(algorithm: .sha256, secret: key)

let code = hmacKeyLocal.authenticationCode(for: message)

hmacKeyRemote.verify(message, hash: code)          // -> Returns true. Correct data + correct HMAC == true 
hmacKeyRemote.verify("HellØ world!", hash: code)   // -> Returns false. Corrupted data + correct HMAC == false 

```

### API
```Swift

/// Generate Keys
LibP2PCrypto.Keys.generateKeyPair(_ type: KeyPairType) throws -> KeyPair
LibP2PCrypto.Keys.generateKeyPair(_ type: KeyPairType) async throws -> KeyPair
LibP2PCrypto.Keys.KeyPair(privateKey: CommonPrivateKey) throws
LibP2PCrypto.Keys.KeyPair(publicKey: CommonPublicKey) throws

/// Import Marshaled Keys
LibP2PCrypto.Keys.KeyPair(marshaledPublicKey str: String, base: BaseEncoding) throws
LibP2PCrypto.Keys.KeyPair(marshaledPublicKey data: Data) throws
LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey str: String, base: BaseEncoding) throws
LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey data: Data) throws

/// Import PEM formatted Keys
LibP2PCrypto.Keys.KeyPair(pem: String, password: String? = nil) throws
LibP2PCrypto.Keys.KeyPair(pem: Data, password: String? = nil) throws
DERDecodable(pem: String, password: String? = nil) throws   // ex: RSAPublicKey(pem:), P256.Signing.PrivateKey(pem:password:)

/// Export Keys
LibP2PCrypto.Keys.KeyPair.marshalPublicKey() throws -> Data
LibP2PCrypto.Keys.KeyPair.marshalPrivateKey() throws -> Data
LibP2PCrypto.Keys.KeyPair.exportPublicPEMString(withHeaderAndFooter: Bool = true) throws -> String
LibP2PCrypto.Keys.KeyPair.exportEncryptedPrivatePEMString(withPassword: String, usingPBKDF: PEM.PBKDFAlgorithm? = nil, andCipher: PEM.CipherAlgorithm? = nil) throws -> String

/// Sign & Verify
LibP2PCrypto.Keys.KeyPair.sign(message: Data) throws -> Data
LibP2PCrypto.Keys.KeyPair.verify(signature: Data, for data: Data) throws -> Bool

/// AES CIPHER
LibP2PCrypto.AES.AESKey(key: String, iv: String) throws
LibP2PCrypto.AES.AESKey.encrypt(_ data: Data) throws -> Data
LibP2PCrypto.AES.AESKey.decrypt(_ data: Data) throws -> Data

/// HMAC
LibP2PCrypto.HMAC.HMACKey(algorithm: CryptoAlgorithm, secret: String)   // or `secret: Data`, or `key: SymmetricKey`
LibP2PCrypto.HMAC.HMACKey.authenticationCode(for message: Data) -> Data
LibP2PCrypto.HMAC.HMACKey.verify(_ data: Data, hash: Data) -> Bool

```

## Contributing

Contributions are welcomed! This code is very much a proof of concept. I can guarantee you there's a better / safer way to accomplish the same results. Any suggestions, improvements, or even just critiques, are welcome! 

Let's make this code better together! 🤝

## Credits
- [swift-crypto](https://github.com/apple/swift-crypto.git)
- [krzyzanowskim - CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)
- [21-DOT-DEV - swift-secp256k1](https://github.com/21-DOT-DEV/swift-secp256k1)
- [siemensikkema - JWT-Kit](https://github.com/vapor/jwt-kit.git) 
- [RSA Import/Export](https://github.com/nextincrement/rsa-public-key-importer-exporter.git)

## Resources
### Links
- [JWK to PEM](https://github.com/ibm-cloud-security/Swift-JWK-to-PEM)
- [OpenSSL](https://stackoverflow.com/questions/31380713/how-to-add-openssl-to-a-swift-project)
- [SecItemExport](https://developer.apple.com/documentation/security/1394828-secitemexport?language=objc)
- [SwiftyRSA](https://github.com/TakeScoop/SwiftyRSA)
- [Swift Sodium (Blake2B)](https://github.com/jedisct1/swift-sodium#hashing)
- [Create a SecKey from a Cert](https://stackoverflow.com/questions/10579985/how-can-i-get-seckeyref-from-der-pem-file)
- [PEM Thread](https://developer.apple.com/forums/thread/96278)
- [SECKey from PEM](https://developer.apple.com/forums/thread/104753)
- [How SwiftyRSA does it](https://github.com/TakeScoop/SwiftyRSA/blob/master/Source/SwiftyRSA.swift#L44)
- [More PEM Discussion](https://developer.apple.com/forums/thread/85915?answerId=256298022#256298022)
- [PEM and DER Format](https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem)
- [ASN.1 Overview](https://www.obj-sys.com/asn1tutorial/node4.html)

## License

[MIT](LICENSE) © 2026 Breth Inc.























