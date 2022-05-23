import XCTest
@testable import LibP2PCrypto
import secp256k1
import Multibase
import Crypto
import CryptoSwift
import JWTKit
import Multihash

final class libp2p_cryptoTests: XCTestCase {
    
    /// RSA
    func testRSA1024() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B1024))
       
        print(keyPair)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 140)
        //XCTAssertGreaterThanOrEqual(keyPair.privateKey!.data.count, 608)
        //XCTAssertLessThanOrEqual(keyPair.privateKey!.data.count, 610)
        
        let attributes = keyPair.attributes()
        print(attributes ?? "NIL")
        XCTAssertEqual(attributes?.size, 1024)
        XCTAssertEqual(attributes?.isPrivate, true)
    }
    
    func testRSA2048() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B2048))
        print(keyPair)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 270)
        //XCTAssertGreaterThanOrEqual(keyPair.privateKey!.data.count, 1193)
        //XCTAssertLessThanOrEqual(keyPair.privateKey!.data.count, 1194)
        
        let attributes = keyPair.attributes()
        XCTAssertEqual(attributes?.size, 2048)
        XCTAssertEqual(attributes?.isPrivate, true)
    }
    
    func testRSA3072() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B3072))
        print(keyPair)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 398)
        //XCTAssertGreaterThanOrEqual(keyPair.privateKey!.data.count, 1768)
        //XCTAssertLessThanOrEqual(keyPair.privateKey!.data.count, 1768)
        
        let attributes = keyPair.attributes()
        XCTAssertEqual(attributes?.size, 3072)
        XCTAssertEqual(attributes?.isPrivate, true)
    }
    
    func testRSA4096() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B4096))
        print(keyPair)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 526)
        //XCTAssertGreaterThanOrEqual(keyPair.privateKey!.data.count, 2349)
        //XCTAssertLessThanOrEqual(keyPair.privateKey!.data.count, 2349)
        
        let attributes = keyPair.attributes()
        XCTAssertEqual(attributes?.size, 4096)
        XCTAssertEqual(attributes?.isPrivate, true)
    }

    func testED25519() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.Ed25519)
        print(keyPair)
        XCTAssert(keyPair.keyType == .ed25519)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 32)
    }

    func testSecp256k1() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.Secp256k1)
        print(keyPair)
        XCTAssert(keyPair.keyType == .secp256k1)
        XCTAssertNotNil(keyPair.privateKey)
        //XCTAssertEqual(keyPair.publicKey.data.count, 64)
    }
    
    /// Ensures that we can move between the Raw Representation of a Public/Private Key and back into the actaul Class/Struct
    func testRSARawRepresentationRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.RSA(bits: .B1024))
        
        let rawPublicKey = keyPair.publicKey.rawRepresentation
        let rawPrivateKey = keyPair.privateKey!.rawRepresentation
        
        /// Instantiate the pubkey
        let recoveredPubKey = try RSAPublicKey(rawRepresentation: rawPublicKey)
        let recoveredPrivKey = try RSAPrivateKey(rawRepresentation: rawPrivateKey)
        
        let recoveredPublicKeyPair = try LibP2PCrypto.Keys.KeyPair(publicKey: recoveredPubKey)
        let recoveredPrivateKeyPair = try LibP2PCrypto.Keys.KeyPair(privateKey: recoveredPrivKey)
        
        XCTAssertEqual(try keyPair.rawID(), try recoveredPublicKeyPair.rawID())
        XCTAssertEqual(try keyPair.rawID(), try recoveredPrivateKeyPair.rawID())
    }
    
    func testEd25519RawRepresentationRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.Ed25519)
        
        let rawPublicKey = keyPair.publicKey.rawRepresentation
        let rawPrivateKey = keyPair.privateKey!.rawRepresentation
        
        /// Instantiate the pubkey
        let recoveredPubKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey)
        let recoveredPrivKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        
        let recoveredPublicKeyPair = try LibP2PCrypto.Keys.KeyPair(publicKey: recoveredPubKey)
        let recoveredPrivateKeyPair = try LibP2PCrypto.Keys.KeyPair(privateKey: recoveredPrivKey)
        
        XCTAssertEqual(try keyPair.rawID(), try recoveredPublicKeyPair.rawID())
        XCTAssertEqual(try keyPair.rawID(), try recoveredPrivateKeyPair.rawID())
    }
    
    func testSecP256k1RawRepresentationRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.Secp256k1)
        
        let rawPublicKey = keyPair.publicKey.rawRepresentation
        let rawPrivateKey = keyPair.privateKey!.rawRepresentation
        
        /// Instantiate the pubkey
        let recoveredPubKey = try Secp256k1PublicKey(rawRepresentation: rawPublicKey)
        let recoveredPrivKey = try Secp256k1PrivateKey(rawRepresentation: rawPrivateKey)
        
        let recoveredPublicKeyPair = try LibP2PCrypto.Keys.KeyPair(publicKey: recoveredPubKey)
        let recoveredPrivateKeyPair = try LibP2PCrypto.Keys.KeyPair(privateKey: recoveredPrivKey)
        
        XCTAssertEqual(try keyPair.rawID(), try recoveredPublicKeyPair.rawID())
        XCTAssertEqual(try keyPair.rawID(), try recoveredPrivateKeyPair.rawID())
    }
    
    func testRSAMarshaledRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.RSA(bits: .B1024))
        
        let marshaledPublicKey = try keyPair.marshalPublicKey()
        print(marshaledPublicKey.asString(base: .base16))
        print(keyPair.publicKey.rawRepresentation.asString(base: .base16))
        
        let recoveredKeyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey)
        
        XCTAssertEqual(keyPair.publicKey.rawRepresentation, recoveredKeyPair.publicKey.rawRepresentation)
    }
    
    func testRSAMashallingRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B1024))

        print("Public Key: \(keyPair.publicKey.asString(base: .base16))")

        let marshaledPubKey = try keyPair.publicKey.marshal()
        print("Marshaled PubKey Bytes: \(marshaledPubKey)")

        let unmarshaledPubKey = try LibP2PCrypto.Keys.unmarshalPublicKey(buf: marshaledPubKey.bytes, into: .base16)

        print("Public Key: \(unmarshaledPubKey)")
        XCTAssertEqual(unmarshaledPubKey, keyPair.publicKey.asString(base: .base16))

        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPubKey).publicKey
        
        XCTAssertEqual(pubKey.data, keyPair.publicKey.data)
    }
    
    func testED25519MarshallingRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.Ed25519)
        
        print("Public Key: \(keyPair.publicKey.asString(base: .base16))")
        
        let marshaledPubKey = try keyPair.publicKey.marshal()
        print("Marshaled PubKey Bytes: \(marshaledPubKey.asString(base: .base16))")
        
        let unmarshaledPubKey = try LibP2PCrypto.Keys.unmarshalPublicKey(buf: marshaledPubKey.bytes, into: .base16)

        print("Public Key: \(unmarshaledPubKey)")
        XCTAssertEqual(unmarshaledPubKey, keyPair.publicKey.asString(base: .base16))
        
        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPubKey).publicKey
        
        XCTAssertEqual(pubKey.data, keyPair.publicKey.data)
    }
    
    func testSecp256k1MarshallingRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.Secp256k1)
        
        print("Public Key: \(keyPair.publicKey.asString(base: .base16))")
        
        let marshaledPubKey = try keyPair.publicKey.marshal()
        print("Marshaled PubKey Bytes: \(marshaledPubKey.asString(base: .base16))")
        
        let unmarshaledPubKey = try LibP2PCrypto.Keys.unmarshalPublicKey(buf: marshaledPubKey.bytes, into: .base16)

        print("Public Key: \(unmarshaledPubKey)")
        XCTAssertEqual(unmarshaledPubKey, keyPair.publicKey.asString(base: .base16))
        
        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPubKey).publicKey
        
        XCTAssertEqual(pubKey.data, keyPair.publicKey.data)
    }
    
//    /// Eliptic Curves
//    func testEC256() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.EC(curve: .P256))
//        print(keyPair)
//    }
//
//    func testEC256KeyPair() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.EC(curve: .P256))
//        XCTAssertFalse(keyPair.publicKey.isRSAKey)
//        XCTAssertTrue(keyPair.publicKey.isPublicKey)
//        XCTAssertFalse(keyPair.privateKey.isPublicKey)
//    }
//
//    func testECDSA256() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.ECDSA(curve: .P256))
//        print(keyPair)
//    }
//
//    func testECDSA384() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.ECDSA(curve: .P384))
//        print(keyPair)
//    }
//
//    func testECDSA521() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.ECDSA(curve: .P521))
//        print(keyPair)
//    }
//
//    func testECSecPrimeRandom() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.ECSECPrimeRandom())
//        print(keyPair)
//    }

//    func testEphemeralMashallingRoundTrip() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawEphemeralKeyPair(curve: .P256)
//
//        print("Public Key: \(keyPair.publicKey.asString(base: .base16))")
//
//        let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(raw: keyPair.publicKey, keyType: .ECDSA(curve: .P256))
//        print("Marshaled PubKey Bytes: \(marshaledPubKey)")
//
//        let unmarshaledPubKey = try LibP2PCrypto.Keys.unmarshalPublicKey(buf: marshaledPubKey, into: .base16)
//
//        print("Public Key: \(unmarshaledPubKey)")
//        XCTAssertEqual(unmarshaledPubKey, keyPair.publicKey.asString(base: .base16))
//    }
//
    
    // - MARK: Marshaling
    
    // Manual
    func testImportFromMarshalledPublicKey_Manual() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_1024, as: .base64Pad)
        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledData.data)

        /// We've imported a Public Key!  🥳
        print(pubKey)

        /// Now lets try and re-marshal the imported key and make sure it matches the original data...
        let marshaledKey = try pubKey.marshalPublicKey() // LibP2PCrypto.Keys.marshalPublicKey(pubKey, keyType: .RSA(bits: .B1024))

        let base64MarshaledPublicKey = marshaledKey.asString(base: .base64Pad)

        print(base64MarshaledPublicKey)
        XCTAssertEqual(base64MarshaledPublicKey, MarshaledData.PUBLIC_RSA_KEY_1024)
    }
    
//    func testImportFromMarshalledPublicKey() throws {
//        let pubKey = try RawPublicKey(marshaledKey: MarshaledData.PUBLIC_KEY, base: .base64Pad)
//
//        /// We've imported a Public Key!  🥳
//        print(pubKey)
//
//        /// Now lets try and re-marshal the imported key and make sure it matches the original data...
//        let base64MarshaledPublicKey = try pubKey.marshalPublicKey().asString(base: .base64Pad)
//
//        XCTAssertEqual(base64MarshaledPublicKey, MarshaledData.PUBLIC_KEY)
//    }
    
    func testCreateKeyPairFromMarshalledPublicKey_1024() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_1024, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNil(keyPair.privateKey)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_1024)
    }
    
    func testCreateKeyPairFromMarshalledPublicKey_2048() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_2048, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNil(keyPair.privateKey)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_2048)
    }
    
    func testCreateKeyPairFromMarshalledPublicKey_3072() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_3072, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNil(keyPair.privateKey)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_3072)
    }
    
    func testCreateKeyPairFromMarshalledPublicKey_4096() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_4096, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNil(keyPair.privateKey)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_4096)
    }
    
    func testImportFromMarshalledPrivateKey_Manual() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_1024, as: .base64Pad)
        let privKey = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledData.data) //LibP2PCrypto.Keys.importMarshaledPrivateKey(marshaledData.data.bytes)

        print(privKey)
    }
    
    func testImportFromMarshalledPrivateKey() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_1024, base: .base64Pad)  //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertEqual(keyPair.keyType, .rsa)
        
        /// Ensures that the private key was instantiated properly and then we can derive the public key from it and then marshal it
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_1024)
    }

    // - MARK: SIGN & VERIFY
    
    func testRSAMessageSignVerify() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!

        let rsa = try LibP2PCrypto.Keys.generateKeyPair(.RSA(bits: .B1024))

        let signedData = try rsa.privateKey!.sign(message: message)
                
        print(signedData.asString(base: .base16))
        
        XCTAssertNotEqual(message, signedData)
        
        // This just ensures that a newly instantiated Pub SecKey matches the derived pubkey from the keypair...
        let recoveredPubKey:RSAPublicKey = try RSAPublicKey(rawRepresentation: rsa.publicKey.data)
        XCTAssertEqual(rsa.publicKey.data, recoveredPubKey.rawRepresentation)
        
        // Ensure the rsaSignatureMessagePKCS1v15SHA256 algorithm works with our RSA KeyPair
        //XCTAssertTrue(SecKeyIsAlgorithmSupported(recoveredPubKey, .verify, .rsaSignatureMessagePKCS1v15SHA256))
        
        // Ensure the Signed Data is Valid for the given message
        XCTAssertTrue(try rsa.publicKey.verify(signature: signedData, for: message))
        
        // Ensure that the signature is no longer valid if it is tweaked in any way
        XCTAssertThrowsError(try rsa.publicKey.verify(signature: Data(signedData.shuffled()), for: message))
        XCTAssertThrowsError(try rsa.publicKey.verify(signature: Data(signedData.dropFirst()), for: message))
        
        // Ensure that the signature is no longer valid if the message is tweaked in any way
        XCTAssertThrowsError(try rsa.publicKey.verify(signature: signedData, for: Data(message.shuffled())))
        XCTAssertThrowsError(try rsa.publicKey.verify(signature: signedData, for: Data(message.dropFirst())))
    }
    
    func testED25519MessageSignVerify() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!
        
        let ed = try LibP2PCrypto.Keys.generateKeyPair(.Ed25519)
        
        let signedData = try ed.privateKey!.sign(message: message)
                
        XCTAssertNotEqual(message, signedData)
        
        XCTAssertTrue(try ed.publicKey.verify(signature: signedData, for: message))
        
        XCTAssertFalse(try ed.publicKey.verify(signature: Data(signedData.shuffled()), for: message))
        XCTAssertFalse(try ed.publicKey.verify(signature: Data(signedData.dropFirst()), for: message))
        
        XCTAssertFalse(try ed.publicKey.verify(signature: signedData, for: Data(message.shuffled())))
        XCTAssertFalse(try ed.publicKey.verify(signature: signedData, for: Data(message.shuffled())))
    }
    
    // TODO EC Keys
    
    // Secp256k1 Keys
    func testSecp256k1MessageSignVerify() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!
        
        let secp = try LibP2PCrypto.Keys.generateKeyPair(.Secp256k1)
        
        let signedData = try secp.privateKey!.sign(message: message)
                
        XCTAssertNotEqual(message, signedData)
        
        XCTAssertTrue(try secp.publicKey.verify(signature: signedData, for: message))
        
        var alertedSignedData = signedData
        alertedSignedData[32] = 0
        XCTAssertFalse(try secp.publicKey.verify(signature: alertedSignedData, for: message))  //We dont simply shuffle the data because it will most likely throw an error (due to invalid first byte 'v')
        XCTAssertThrowsError(try secp.publicKey.verify(signature: Data(signedData.dropFirst()), for: message)) //Invalid length will throw error...
        
        XCTAssertFalse(try secp.publicKey.verify(signature: signedData, for: Data(message.shuffled())))
        XCTAssertFalse(try secp.publicKey.verify(signature: signedData, for: Data(message.shuffled())))
    }
    
    
    // - MARK: AES Cipher Tests
    
    func testAESEncryption128() throws {
        let message = "Hello World!"
        let key128  = "1234567890123456"                   // 16 bytes for AES128
        let iv      = "abcdefghijklmnop"                   // 16 bytes for AES128

        let aes128Key = try LibP2PCrypto.AES.createKey(key: key128, iv: iv)

        let encrypted = try aes128Key.encrypt(message)
        print(encrypted.asString(base: .base16))
        let decrypted:String = try aes128Key.decrypt(encrypted)

        XCTAssertEqual(decrypted, message)
    }

    func testAESEncryption256() throws {
        let message = "Hello World!"
        let key256  = "12345678901234561234567890123456"   // 32 bytes for AES256
        let iv      = "abcdefghijklmnop"                   // 16 bytes for AES128

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256, iv: iv)
        let aes256KeyDup = try LibP2PCrypto.AES.createKey(key: key256, iv: iv)

        let encrypted = try aes256Key.encrypt(message)
        let encrypted2 = try aes256KeyDup.encrypt(message)
        print(encrypted.asString(base: .base16))
        print(encrypted2.asString(base: .base16))
        let decrypted:String = try aes256Key.decrypt(encrypted)

        XCTAssertEqual(decrypted, message)
        XCTAssertEqual(encrypted, encrypted2) //Same Key & IV => Same Encrypted data
    }

    func testAESEncryption256AutoIV() throws {
        let message = "Hello World!"
        let key256  = "12345678901234561234567890123456"   // 32 bytes for AES256

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256)

        let encrypted = try aes256Key.encrypt(message)
        print(encrypted.asString(base: .base16))
        let decrypted:String = try aes256Key.decrypt(encrypted)

        XCTAssertEqual(decrypted, message)
    }

    func testAESEncryption256AutoIVDifferent() throws {
        let message = "Hello World!"
        let key256  = "12345678901234561234567890123456"   // 32 bytes for AES256

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256)
        let aes256Key2 = try LibP2PCrypto.AES.createKey(key: key256)

        let encrypted = try aes256Key.encrypt(message)
        let encrypted2 = try aes256Key2.encrypt(message)
        print(encrypted.asString(base: .base16))
        print(encrypted2.asString(base: .base16))
        let decrypted:String = try aes256Key.decrypt(encrypted)
        let decrypted2:String = try aes256Key2.decrypt(encrypted2)

        XCTAssertNotEqual(encrypted, encrypted2) //Ensure that the encrypted data is different using different keys
        XCTAssertEqual(decrypted, message) //Ensure we can decrypt the data with the proper key
        XCTAssertEqual(decrypted2, message) //Ensure we can decrypt the data with the proper key

        //Ensure that decryption fails when we use the wrong key
        let decryptedWrongKey:String? = try? aes256Key.decrypt(encrypted2) //Usually results in an String.Encoding Error (cause gibberish)
        XCTAssertNotEqual(decryptedWrongKey, message)
    }
    
    func testAESGCMEncryptionRoundTrip() throws {
        
        let message = "Hello World!"
        
        let encrypted = try message.encryptGCM(password: "mypassword")
        
        print(encrypted.asString(base: .base32))
        
        let decrypted = try encrypted.decryptGCM(password: "mypassword")
        
        let msg = String(data: decrypted, encoding: .utf8)
        print(msg ?? "NIL")
        
        XCTAssertEqual(msg, message)
    }

    
    // - MARK: Hashed Message Authentication Codes (HMAC)
    
    func testHMAC() throws {
        let message = "Hello World"
        let key = "secret"
        let hmac = LibP2PCrypto.HMAC.encrypt(message: message, algorithm: .SHA256, key: key)
        let hmac2 = LibP2PCrypto.HMAC.encrypt(message: message, algorithm: .SHA256, key: key)
        let hmac3 = LibP2PCrypto.HMAC.encrypt(message: message, algorithm: .SHA256, key: "Secret")

        XCTAssertEqual(hmac, hmac2) //Same message, same key -> Same hash
        XCTAssertNotEqual(hmac, hmac3) //Same message, different key -> Different hash
    }

    func testHMACKey() throws {
        let message = "Hello World"
        let key = "secret"
        let hmacKey = LibP2PCrypto.HMAC.create(algorithm: .SHA256, secret: key)

        let encrypted = hmacKey.encrypt(message)
        let encrypted2 = hmacKey.encrypt(message)

        XCTAssertEqual(encrypted, encrypted2)
    }

    func testHMACBaseEncoded() throws {
        let message = "Hello World"
        let key = "secret"
        let hmac = LibP2PCrypto.HMAC.encrypt(message: message, algorithm: .SHA256, key: key)

        print(hmac.asString(base: .base16))
        print(hmac.asString(base: .base32Hex))
        print(hmac.asString(base: .base64Pad))
    }

    func testHMACVerify() throws {
        let message = "Hello World"
        let key = "secret"
        let hmacKeyLocal = LibP2PCrypto.HMAC.create(algorithm: .SHA256, secret: key)
        let hmacKeyRemote = LibP2PCrypto.HMAC.create(algorithm: .SHA256, secret: key)

        let encrypted = hmacKeyLocal.encrypt(message)

        XCTAssertTrue(hmacKeyRemote.verify(message, hash: encrypted)) // Correct data, hash matches...
        XCTAssertFalse(hmacKeyRemote.verify("HellØ world", hash: encrypted)) // Corrupted data, hash doesn't match...
    }


//    func testAES() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair()
//    }
//    func testAES() throws {
//        let bits = [256, 512, 1024, 2048]
//        for bitLength in bits {
//            do {
//                let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.AES(bits: bitLength))
//                print(keyPair)
//            } catch {
//                print(error)
//            }
//        }
//    }

//    func testThreeDES() throws {
//        let keyPair = try LibP2PCrypto.Keys.generateRawKeyPair(.ThreeDES)
//        print(keyPair)
//    }

    /// RSA Object Identifier --> 2a 86 48 86 f7 0d 01 01 01 (bit length independent, pub/priv key independent)
    /// ECDSA P384 --> 2a 86 48 ce 3d 02 01
    func testPemParsing() throws {

//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcZ/r0nvJyHUUstIB5BqCUJ1CC
//        Cd1nzle4bEpPQJ/S0Wn7mV2FDAeh+UcbVhZu9n+5zypYNjeZKapPqBLoT8eCK51y
//        Kpzeb8LuEm3P8PK4xN18XBrIF1GprN8IIgSdK9f5SwnemutcURrY+PlWnvj7N5s/
//        03RlJA3/NHVXpPW/VQIDAQAB
//        -----END PUBLIC KEY-----
//        """

        let pem = """
        -----BEGIN PRIVATE KEY-----
        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
        4pMwXeXP+LO8NIfRXV8mgrm86g==
        -----END PRIVATE KEY-----
        """

//        /// EC P256 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb4nB0k8CBVnKCHVHkxuXAkSlZuO5
//        Nsev1rzcRv5QHiJuWUKomFGadQlMSGwoDOHEDdW3ujcA6t0ADteHw6KrZg==
//        -----END PUBLIC KEY-----
//        """

//        /// EC P384 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBwY0l7mq7hSBEZRld5ISWfSoFsYN3wwM
//        hdD3cMU95DmYXzbqVHB4dCfsy7bexm4h9c0zs4CyTPzy3DV3vfmv1akQJIQv7l08
//        lx/YXNeGXTN4Gr9r4rwA5GvRl1p6plPL
//        -----END PUBLIC KEY-----
//        """

//        /// EC P521 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAp3v1UQWvSyQnkAUEBu+x/7ZrPtNJ
//        SCUk9kMvuZMyGP1idwvspALuJjzrSFFlXObjlOjxucSbWhTYF/o3nc0XzpAA3dxA
//        BYiMqH9vrVePoJMpv+DMdkUiUJ/WqHSOu9bJEi1h4fdqh5HHx4QZJY/iX/59VAi1
//        uSbAhALvbdGFbVpkcOs=
//        -----END PUBLIC KEY-----
//        """

        /// EC P256 Private Key
//        let pem = """
//        -----BEGIN PRIVATE KEY-----
//        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZjQLlzempZx7YF1F
//        +MK1HWZTNgLcC1MAufb/2/YZYk6hRANCAAQwgn0PfkIHiZ/K+3zA//CoDqU2PqDc
//        aA3U5R68jmlZQITvMyBlMJl9Mjh0biIe88dAfRKeUm9FVMD2ErJ/006V
//        -----END PRIVATE KEY-----
//        """

        /// PEMP384PKCS8
//        let pem = """
//        -----BEGIN PRIVATE KEY-----
//        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB7ERKhMR+mvz1NQ+oL
//        i6ZJMACOcwbUetWcNnB4Mnx3j4XuhpkkHEW8E1+rXyjZ3UmhZANiAASYH+emlyXM
//        kBSFJl0BiopDVuIIR47M4pLl00YNnuu/Rp5VHeVAHrP67i2Q92u5fk34eOSwQvkO
//        VvktWsgtzAomIam4SHqE9bhvrHy6kW6QzxlERHTL+YkXEX8c6t8VOxk=
//        -----END PRIVATE KEY-----
//        """

        let chunks = pem.split(separator: "\n")
        guard chunks.count > 3,
              let f = chunks.first, f.hasPrefix("-----BEGIN"),
              let l = chunks.last, l.hasSuffix("-----") else {
            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
        }

        //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
        //print(raw.data)

        //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)

        let asn = try Asn1Parser.parse(data: raw.data)
        //let asn = try Asn1Parser.parse(data: key)

        print("*****")
        print(asn)
        print("*****")

        var bitString:Data? = nil
        var oct:Data? = nil
        if case .sequence(let nodes) = asn {
            nodes.forEach {
                switch $0 {
                case .objectIdentifier(let data):
                    print("Got our obj id: \(data.asString(base: .base64))")
                    print(String(data: data, encoding: .utf8) ?? "NIL")
                case .bitString(let data):
                    print("Got our bit string: \(data.asString(base: .base64))")
                    bitString = data
                case .sequence(let nodes):
                    nodes.forEach { n in
                        switch n {
                        case .objectIdentifier(let data):
                            print("Got our obj id: \(data.asString(base: .base16))")
                            print(data.bytes.map { "\($0)"}.joined(separator: ",") )
                        case .octetString(let data):
                            oct = data
                            //oct = raw.data
                        default:
                            print(n)
                        }
                    }
                case .octetString(let data):
                    //bitString = data
                    oct = data
                    //oct = raw.data
                default:
                    print($0)
                }
            }
        }

        if let bits = bitString {
            print("Trying to Init RSA from bitString")
            let sk = try RSAPrivateKey(rawRepresentation: bits)
            //let sk = try LibP2PCrypto.Keys.secKeyFrom(data: bits, isPrivateKey: true, keyType: .EC(curve: .P256))
            print(sk)
        } else if let oct = oct {
            print("Trying to Init RSA from OctetString")
            let sk = try RSAPrivateKey(rawRepresentation: oct)
            //print(ec.bytes.map { "\($0)"}.joined(separator: ",") )
//            var ec2 = ec.bytes
//            ec2.insert(0, at: 0)
//            let sk = try LibP2PCrypto.Keys.secKeyFrom(data: Data(ec2), isPrivateKey: true, keyType: .EC(curve: .P256))
            print(sk)
        }
    }
    
    // - MARK: PEM Decoding
    func testPemParsing_RSA_1024_Public() throws {

        let pem = """
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcZ/r0nvJyHUUstIB5BqCUJ1CC
        Cd1nzle4bEpPQJ/S0Wn7mV2FDAeh+UcbVhZu9n+5zypYNjeZKapPqBLoT8eCK51y
        Kpzeb8LuEm3P8PK4xN18XBrIF1GprN8IIgSdK9f5SwnemutcURrY+PlWnvj7N5s/
        03RlJA3/NHVXpPW/VQIDAQAB
        -----END PUBLIC KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(keyPair)
        print(keyPair.attributes() ?? "NIL")

        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 1024)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_1024_Public_2() throws {
        let pem = """
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBANxn+vSe8nIdRSy0gHkGoJQnUIIJ3WfOV7hsSk9An9LRafuZXY
        UMB6H5RxtWFm72f7nPKlg2N5kpqk+oEuhPx4IrnXIqnN5vwu4Sbc/w8rjE
        3XxcGsgXUams3wgiBJ0r1/lLCd6a61xRGtj4+Vae+Ps3mz/TdGUkDf80dV
        ek9b9VAgMBAAE=
        -----END RSA PUBLIC KEY-----
        """

        /// Import DER directly
        let key = try LibP2PCrypto.Keys.importPublicDER(pem)

        /// Let the parsePem method determine that it's a DER file and handle it accordingly
        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.publicKey.data, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 1024)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_2048_Public() throws {

        /// Import PEM directly
        let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_2048_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_2048_PUBLIC)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 2048)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_3072_Public() throws {

        /// Import PEM directly
        let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_3072_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_3072_PUBLIC)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 3072)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_4096_Public() throws {

        /// Import PEM directly
        let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_4096_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_4096_PUBLIC)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 4096)
        XCTAssertNil(keyPair.privateKey)
    }

//    func testPemParsing_EC_P256_Public() throws {
//        /// EC P256 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb4nB0k8CBVnKCHVHkxuXAkSlZuO5
//        Nsev1rzcRv5QHiJuWUKomFGadQlMSGwoDOHEDdW3ujcA6t0ADteHw6KrZg==
//        -----END PUBLIC KEY-----
//        """
//
//        let key = try LibP2PCrypto.Keys.importPublicPem(pem)
//
//        print(key)
//    }
//
//    func testPemParsing_EC_P384_Public() throws {
//        /// EC P384 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBwY0l7mq7hSBEZRld5ISWfSoFsYN3wwM
//        hdD3cMU95DmYXzbqVHB4dCfsy7bexm4h9c0zs4CyTPzy3DV3vfmv1akQJIQv7l08
//        lx/YXNeGXTN4Gr9r4rwA5GvRl1p6plPL
//        -----END PUBLIC KEY-----
//        """
//
//        let key = try LibP2PCrypto.Keys.importPublicPem(pem)
//
//        print(key)
//    }
//
//    func testPemParsing_EC_P521_Public() throws {
//        /// EC P521 Public Key
//        let pem = """
//        -----BEGIN PUBLIC KEY-----
//        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAp3v1UQWvSyQnkAUEBu+x/7ZrPtNJ
//        SCUk9kMvuZMyGP1idwvspALuJjzrSFFlXObjlOjxucSbWhTYF/o3nc0XzpAA3dxA
//        BYiMqH9vrVePoJMpv+DMdkUiUJ/WqHSOu9bJEi1h4fdqh5HHx4QZJY/iX/59VAi1
//        uSbAhALvbdGFbVpkcOs=
//        -----END PUBLIC KEY-----
//        """
//
//        let key = try LibP2PCrypto.Keys.importPublicPem(pem)
//
//        print(key)
//    }



    ///[42,134,72,134,247,13,1,1,1]
    func testRSAOpenSSLPemImport() throws {

        /// Generated with
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:3072
        ///   -pkeyopt rsa_keygen_pubexp:65537
        let pem = """
        -----BEGIN PRIVATE KEY-----
        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
        4pMwXeXP+LO8NIfRXV8mgrm86g==
        -----END PRIVATE KEY-----
        """

        /// Import PEM directly
        let key = try LibP2PCrypto.Keys.importPrivatePem(pem)

        /// Let the parsePem method determine the format and handle it accordingly
        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.privateKey?.rawRepresentation)
        XCTAssertEqual(try key.derivePublicKey().rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 3072)
        XCTAssertNotNil(keyPair.privateKey)
    }

    // Manual PEM import process
    func testED25519PemImport_Public_Manual() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
        -----END PUBLIC KEY-----
        """

        let data = try pemToData(pem)

        let asn = try Asn1Parser.parse(data: data)

        print(asn)

        guard case .sequence(let top) = asn, case .bitString(let pubKeyData) = top.last else {
            return XCTFail("Failed to extract our PubKey bit string")
        }

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData.bytes)

        print(pubKey)

        print(pubKey.rawRepresentation.asString(base: .base64Pad))

        /// Ensure that we reached the same results using both methods
        XCTAssertEqual(pubKey.rawRepresentation, try LibP2PCrypto.Keys.parsePem(pem).publicKey.data)
    }

    func testED25519PemImport_Public() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
        -----END PUBLIC KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .ed25519)
        XCTAssertNil(keyPair.privateKey)
    }


    /// This document defines what that is for Ed25519 private keys:
    /// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
    ///
    /// What it says is that inside the OCTET STRING is another OCTET STRING for the private key data. The ASN.1 tag for OCTET STRING is 0x04, and the length of that string is 32 bytes (0x20 in hex).
    /// So in the above string the leading 0420 is the OCTET STRING tag and length. The remaining 32 bytes are the key itself.
    func testED25519PemImport_Private_Manual() throws {
        let pem = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIOkK9EOHRqD5QueUrMZbia55UWpokoFpWco4r2GnRVZ+
        -----END PRIVATE KEY-----
        """

        let data = try pemToData(pem)

        let asn = try Asn1ParserECPrivate.parse(data: data)

        print(asn)

//        sequence(nodes: [
//            libp2p_crypto.Asn1Parser.Node.integer(data: 1 bytes),
//            libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 3 bytes)]
//            ),
//            libp2p_crypto.Asn1Parser.Node.octetString(data: 34 bytes) <- This is actually another octetString
//        ])

        guard case .sequence(let top) = asn, case .octetString(var privKeyData) = top.last else {
            return XCTFail("Failed to extract our PrivKey bit string")
        }

        while privKeyData.count > 32 {
            privKeyData.removeFirst()
        }

        print(privKeyData.count)

        let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privKeyData.bytes)

        print(privKey)

        XCTAssertEqual("CM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=", privKey.publicKey.rawRepresentation.asString(base: .base64Pad))

    }

    func testED25519PemImport_Private() throws {
        let pem = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIOkK9EOHRqD5QueUrMZbia55UWpokoFpWco4r2GnRVZ+
        -----END PRIVATE KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .ed25519)
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertEqual(keyPair.publicKey.asString(base: .base64Pad), "CM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=")
    }


    func testSecp256k1PemImport_Public_Manual() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
        xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END PUBLIC KEY-----
        """

        let data = try pemToData(pem)

        let asn = try Asn1ParserECPrivate.parse(data: data)

        print(asn)

//        sequence(nodes: [
//            libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 7 bytes),  :id-ecPublicKey
//                libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 5 bytes)   :secp256k1
//            ]),
//            libp2p_crypto.Asn1Parser.Node.bitString(data: 65 bytes)
//        ])

        guard case .sequence(let top) = asn, case .bitString(let pubKeyData) = top.last else {
            return XCTFail("Failed to extract our Public Key bit/octet string")
        }

        let pubKey = try Secp256k1PublicKey(pubKeyData.bytes)

        print(pubKey)

        print(pubKey.rawPublicKey.asString(base: .base64Pad))
    }

    func testSecp256k1PemImport_Public() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
        xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END PUBLIC KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .secp256k1)
        XCTAssertNil(keyPair.privateKey)
        print(keyPair.attributes() ?? "NIL")
    }

    func testSecp256k1PemImport_Private_Manual() throws {
        let pem = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """

        let data = try pemToData(pem)

        let asn = try Asn1ParserECPrivate.parse(data: data)

        print(asn)

//        sequence(nodes: [
//            libp2p_crypto.Asn1ParserECPrivate.Node.integer(data: 1 bytes),
//            libp2p_crypto.Asn1ParserECPrivate.Node.octetString(data: 32 bytes),      // private key data
//            libp2p_crypto.Asn1ParserECPrivate.Node.objectIdentifier(data: 7 bytes),  :secp256k1
//            libp2p_crypto.Asn1ParserECPrivate.Node.bitString(data: 67 bytes)
//        ])

        guard case .sequence(let top) = asn, case .octetString(let privKeyData) = top[1] else {
            return XCTFail("Failed to extract our PrivKey bit/octet string")
        }

        let privKey = try Secp256k1PrivateKey(privKeyData.bytes)

        print(privKey)

        /// Assert that we can derive the public from the private key
        XCTAssertEqual("IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==", privKey.publicKey.rawPublicKey.asString(base: .base64Pad))

    }

    func testSecp256k1PemImport_Private() throws {
        let pem = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.parsePem(pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .secp256k1)
        XCTAssertNotNil(keyPair.privateKey)
        /// Assert that we can derive the public from the private key
        XCTAssertEqual(keyPair.publicKey.asString(base: .base64Pad), "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==")
    }


//    func testPemParsing_EC_256_Private_Key() throws {
//        let pem = """
//        -----BEGIN EC PRIVATE KEY-----
//        MHcCAQEEIHwS3r7tdBfDPSOaT/x6A2qvXFFXlGmnaYkxzrj1CQUHoAoGCCqGSM49
//        AwEHoUQDQgAE79HvsMQC9IyhZ7yCCYKmgz9zewM4KziWoVMXKN+7Cd5Ds+jK8V5q
//        hD6YVbbo/v1udmM5DfhHJiUW3Ww5++suRg==
//        -----END EC PRIVATE KEY-----
//        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        let asn = try Asn1ParserECPrivate.parse(data: raw.data)
//        print(asn)
//
//        var asnOctetString = try LibP2PCrypto.Keys.parseASN1ECPrivate(pemData: raw.data)
//
//        print(asnOctetString.count)
//
//        while asnOctetString.count < 32 {
//            asnOctetString.insert(0, at: 0)
//        }
//
//        let importedKey = try P256.Signing.PrivateKey(rawRepresentation: asnOctetString)
//
//        print(importedKey)
//
//        print("----")
//    }
//
//    func testPemParsing_EC_384_Private_Key() throws {
//        let pem = """
//        -----BEGIN EC PRIVATE KEY-----
//        MIGkAgEBBDDrN+qjvW7TqcXrKlTFbSP8AdbsIdqvRAgWHlaBicP7dkx+HKQidSiS
//        B2RLWyjSrs6gBwYFK4EEACKhZANiAAQrRiaztGpInYo1XqMnNokWY6g1TcgMuzgq
//        Ug6LzFQbCAqCrcnM9+c9Z4/63dC06ulL/KbLQgThjSiqRzgbzvmOvB0OzlpX1weK
//        usFrF4Pi0B9pKPmVCAlSzaxVEmRsbmw=
//        -----END EC PRIVATE KEY-----
//        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        var asnOctetString = try LibP2PCrypto.Keys.parseASN1ECPrivate(pemData: raw.data)
//
//        print(asnOctetString.count)
//
//        while asnOctetString.count < 48 {
//            asnOctetString.insert(0, at: 0)
//        }
//
//        let importedKey = try P384.Signing.PrivateKey(rawRepresentation: asnOctetString)
//
//        print(importedKey)
//
//        print("----")
//    }
//
//
//    func testPemParsing_EC_521_Private_Key() throws {
//        let pem = """
//        -----BEGIN EC PRIVATE KEY-----
//        MIHbAgEBBEFaaU0VdcgDi+me65TnhRo9+AodcV5DOfbi8UteeDpojXW5PfkKXNQ+
//        qJlAyA0nVmkJlrwSOlqSH7XGzHuOTu+nd6AHBgUrgQQAI6GBiQOBhgAEAZMhoDRn
//        GAeReuc4sKEq3fznP1rPZ4QDdwpNfxQbPLe0rzg4fk+J6BPlyQs74RfHtXxiHOiL
//        3GZJLzo/pPbi96z7AG1AEABHWCcmi/uclGsjg0wNuKuWHwY8bJGvHZIBtd+px5+L
//        6L0wg93uMy3o2nMEJd01n18LGvjdl3GUvgq2kXQN
//        -----END EC PRIVATE KEY-----
//        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        var asnOctetString = try LibP2PCrypto.Keys.parseASN1ECPrivate(pemData: raw.data)
//
//        while asnOctetString.count < 66 {
//            asnOctetString.insert(0, at: 0)
//        }
//
//        let importedKey = try P521.Signing.PrivateKey(rawRepresentation: asnOctetString)
//
//        print(importedKey)
//
//        print("----")
//    }
//
//    func testRSAEncryptedPrivateKeyPem() throws {
//        /*
//        * Generated with
//        * openssl genpkey -algorithm RSA
//        *   -pkeyopt rsa_keygen_bits:1024
//        *   -pkeyopt rsa_keygen_pubexp:65537
//        *   -out foo.pem
//        * openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
//        */
//        let pem = """
//        -----BEGIN ENCRYPTED PRIVATE KEY-----
//        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIP5QK2RfqUl4CAggA
//        MB0GCWCGSAFlAwQBAgQQj3OyM9gnW2dd/eRHkxjGrgSCAoCpM5GZB0v27cxzZsGc
//        O4/xqgwB0c/bSJ6QogtYU2KVoc7ZNQ5q9jtzn3I4ONvneOkpm9arzYz0FWnJi2C3
//        BPiF0D1NkfvjvMLv56bwiG2A1oBECacyAb2pXYeJY7SdtYKvcbgs3jx65uCm6TF2
//        BylteH+n1ewTQN9DLfASp1n81Ajq9lQGaK03SN2MUtcAPp7N9gnxJrlmDGeqlPRs
//        KpQYRcot+kE6Ew8a5jAr7mAxwpqvr3SM4dMvADZmRQsM4Uc/9+YMUdI52DG87EWc
//        0OUB+fnQ8jw4DZgOE9KKM5/QTWc3aEw/dzXr/YJsrv01oLazhqVHnEMG0Nfr0+DP
//        q+qac1AsCsOb71VxaRlRZcVEkEfAq3gidSPD93qmlDrCnmLYTilcLanXUepda7ez
//        qhjkHtpwBLN5xRZxOn3oUuLGjk8VRwfmFX+RIMYCyihjdmbEDYpNUVkQVYFGi/F/
//        1hxOyl9yhGdL0hb9pKHH10GGIgoqo4jSTLlb4ennihGMHCjehAjLdx/GKJkOWShy
//        V9hj8rAuYnRNb+tUW7ChXm1nLq14x9x1tX0ciVVn3ap/NoMkbFTr8M3pJ4bQlpAn
//        wCT2erYqwQtgSpOJcrFeph9TjIrNRVE7Zlmr7vayJrB/8/oPssVdhf82TXkna4fB
//        PcmO0YWLa117rfdeNM/Duy0ThSdTl39Qd+4FxqRZiHjbt+l0iSa/nOjTv1TZ/QqF
//        wqrO6EtcM45fbFJ1Y79o2ptC2D6MB4HKJq9WCt064/8zQCVx3XPbb3X8Z5o/6koy
//        ePGbz+UtSb9xczvqpRCOiFLh2MG1dUgWuHazjOtUcVWvilKnkjCMzZ9s1qG0sUDj
//        nPyn
//        -----END ENCRYPTED PRIVATE KEY-----
//        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        let password: [UInt8] = Array("mypassword".utf8)
//
//        // The salt is the first 16 bytes of the encrypted key
//        let salt: [UInt8] = Array(raw.data.bytes.prefix(16))
//
//        // The remainder of the bytes make up the cipher text and nonce
//        let cipherTextAndNonce = Array(raw.data.bytes.dropFirst(16))
//        let nonce = Array(cipherTextAndNonce.prefix(12))
//        var cipherTextAndTag = Array(cipherTextAndNonce.dropFirst(12))
//
//        /* Generate a key from a `password`. Optional if you already have a key */
//        let key = try PKCS5.PBKDF2(
//            password: password,
//            salt: salt,
//            iterations: 1024,
//            keyLength: 16, /* 16 == AES-128, 32 == AES-256 */
//            variant: .sha256
//        ).calculate()
//
//        /* Generate random IV value. IV is public value. Either need to generate, or get it from elsewhere */
//        //let iv = AES.randomIV(AES.blockSize)
//
////        /* AES cryptor instance */
//        //let aes = try AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding)
//
//        // In combined mode, the authentication tag is appended to the encrypted message. This is usually what you want.
//        let gcm = GCM(iv: nonce, mode: .combined)
//        //let decipherIV = CTR(iv: nonce, counter: 0)
//        let aes = try AES(key: key, blockMode: gcm, padding: .noPadding)
//        print(cipherTextAndTag.count)
//        while cipherTextAndTag.count % AES.blockSize != 0 {
//            cipherTextAndTag.insert(0, at: 0)
//        }
//        let unencryptedKey = try aes.decrypt(cipherTextAndTag)
//
//        // Raw Representation of our key
//        print(unencryptedKey.asString(base: .base16))
//
//        //Import Unencrypted Key as SecKey...
//
////        /* Encrypt Data */
////        let inputData = Data()
////        let encryptedBytes = try aes.encrypt(inputData.bytes)
////        let encryptedData = Data(encryptedBytes)
////
////        /* Decrypt Data */
////        let decryptedBytes = try aes.decrypt(encryptedData.bytes)
////        let decryptedData = Data(decryptedBytes)
//
//
//    }
    
    // - MARK: Encrypted PEM Imports
    
    /// Tests importing encrypted PEM private key with a plaintext password
    ///
    /// To decrypt an encrypted private RSA key...
    /// 1) Strip the headers of the PEM and base64 decode the data
    /// 2) Parse the data via ASN1 looking for the encryption algo, salt, iv and itterations used, and the ciphertext (aka octet string)
    /// 3) Derive the encryption key using PBKDF2 (sha1, salt and itterations)
    /// 4) Use encryption key to instantiate the AES CBC Cipher along with the IV
    /// 5) Decrypt the encrypted octet string
    /// 6) The decrypted octet string can be ASN1 parsed again for the private key octet string
    /// 7) This raw data can be used to instantiate a SecKey
    func testRSAEncryptedPrivateKeyPem2_Manual() throws {

        // Generated with
        // openssl genpkey -algorithm RSA
        //   -pkeyopt rsa_keygen_bits:1024
        //   -pkeyopt rsa_keygen_pubexp:65537
        //   -out foo.pem
        let unencryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.UNENCRYPTED

        // Encrypted with
        // openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
        let encryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED

        let asn = try Asn1Parser.parse(data: pemToData(encryptedPem))

        print(asn)

//        sequence(nodes: [
//            libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes), //[42,134,72,134,247,13,1,5,13]
//                libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                    libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                        libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
//                        libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                            libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),       //SALT
//                            libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
//                        ])
//                    ]),
//                    libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//                        libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc [96,134,72,1,101,3,4,1,2]
//                        libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)           //IV
//                    ])
//                ])
//            ]),
//            libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
//        ])

        var saltData:Data? = nil
        var ivData:Data? = nil
        var itterationsData:Int? = nil
        var ciphertextData:Data? = nil

        if case .sequence(let top) = asn {
            if case .sequence(let top1) = top.first {
                if case .sequence(let top2) = top1.last {
                    if case .sequence(let top3) = top2.first {
                        if case .sequence(let top4) = top3.last {
                            if case .octetString(let salt) = top4.first {
                                print("Found the salt: \(salt.asString(base: .base16))")
                                saltData = salt
                            }
                            if case .integer(let int) = top4.last {
                                print("Found the itterations: \(int.asString(base: .base16))")
                                itterationsData = Int(int.asString(base: .base16), radix: 16)
                            }
                        }
                    }
                    if case .sequence(let bottom3) = top2.last {
                        if case .octetString(let iv) = bottom3.last {
                            print("Found the IV: \(iv.asString(base: .base16))")
                            ivData = iv
                        }
                    }
                }
            }
            if case .octetString(let cipherText) = top.last {
                print("Found the ciphertext: \(cipherText.count)")
                ciphertextData = cipherText
            }
        }

        // Ensure we have everything we need to proceed...
        guard let salt = saltData, let iv = ivData, let itterations = itterationsData, let ciphertext = ciphertextData else {
            return XCTFail("Failed to parse our pcks#8 key")
        }

        // Attempt to derive the aes encryption key from the password and salt
        // PBKDF2-SHA1
        guard let key = PBKDF2.SHA1(password: "mypassword", salt: salt, keyByteCount: 16, rounds: itterations) else {
            return XCTFail("Failed to derive key from password and salt")
        }
        
        // This also works, but it is incredibly slow...
//        let key2 = try PKCS5.PBKDF2(
//            password: Array("mypassword".utf8),
//            salt: salt.bytes,
//            iterations: itterations,
//            keyLength: 16, /* 16 == AES-128, 32 == AES-256 */
//            variant: .sha256
//        ).calculate()

        // These should be the same
        print("Key 1 -> \(key.asString(base: .base16))")
        //print("Key 2 -> \(key2.asString(base: .base16))")

        //Create our CBC AES Cipher
        let aes = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .noPadding)

        // Try GCM
        //let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .detached), padding: .noPadding)

        let decryptedKey = try aes.decrypt(ciphertext.bytes)

        print(decryptedKey.asString(base: .base64))

        let deASN = try Asn1Parser.parse(data: Data(decryptedKey))
        print(deASN)
        print("-----")
        let unASN = try Asn1Parser.parse(data: pemToData(unencryptedPem))
        print(unASN)

        /// sequence(nodes: [
        ///     libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///         libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),   // [42,134,72,134,247,13,1,1,1] => RSA Private Key
        ///         libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),
        ///                 libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                     libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),
        ///                     libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)
        ///                 ])
        ///             ]),
        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),
        ///                 libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)
        ///             ])
        ///         ]),
        ///         libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
        ///     ])
        /// ])

        var unencRawPrivateKeyData:Data? = nil
        if case .sequence(let top) = unASN {
            if case .octetString(let d) = top.last {
                print("Found our unenc octetString")
                unencRawPrivateKeyData = d
            }
        }

        var decRawPrivateKeyData:Data? = nil
        if case .sequence(let top) = deASN {
            if case .octetString(let d) = top.last {
                print("Found our dec octetString")
                decRawPrivateKeyData = d
            }
        }

        guard let uRawPrivKeyData = unencRawPrivateKeyData else {
            return XCTFail("Failed to parse our unencrypted private pem key...")
        }

        guard let dRawPrivKeyData = decRawPrivateKeyData else {
            return XCTFail("Failed to parse our decrypted private pem key...")
        }

        print(uRawPrivKeyData.asString(base: .base64))
        print(dRawPrivKeyData.asString(base: .base64))

        print(dRawPrivKeyData.count)
        print(uRawPrivKeyData.count)

        let og = try RSAPrivateKey(rawRepresentation: uRawPrivKeyData)
        let de = try RSAPrivateKey(rawRepresentation: dRawPrivKeyData)

        print(og)

        print(de)

        XCTAssertEqual(uRawPrivKeyData, dRawPrivKeyData)
        XCTAssertEqual(og, de)


        //XCTAssertEqual(uRawPrivKeyData.bytes, decryptedKey, "Not Equal")

    }
    
    func testRSAEncryptedPrivateKeyPem2() throws {

        // Generated with
        // openssl genpkey -algorithm RSA
        //   -pkeyopt rsa_keygen_bits:1024
        //   -pkeyopt rsa_keygen_pubexp:65537
        //   -out foo.pem
        let unencryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.UNENCRYPTED

        // Encrypted with
        // openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
        let encryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED

        let fromDecrypted = try LibP2PCrypto.Keys.parsePem(unencryptedPem)
        let fromEncrypted = try LibP2PCrypto.Keys.parseEncryptedPem(encryptedPem, password: "mypassword")

        XCTAssertNotNil(fromDecrypted.privateKey)
        XCTAssertNotNil(fromEncrypted.privateKey)

        XCTAssertTrue(fromDecrypted.keyType == .rsa)
        XCTAssertTrue(fromEncrypted.keyType == .rsa)

        XCTAssertEqual(fromDecrypted.privateKey?.rawRepresentation, fromEncrypted.privateKey?.rawRepresentation)
        XCTAssertEqual(fromDecrypted.publicKey.data, fromEncrypted.publicKey.data)

        let attributes = fromEncrypted.attributes()
        XCTAssertEqual(attributes!.size, 1024)
        XCTAssertTrue(attributes!.isPrivate)
    }
    
    private func pemToData(_ str:String) throws -> Data {
        let chunks = str.split(separator: "\n")
        guard chunks.count > 2,
              let f = chunks.first, f.hasPrefix("-----BEGIN"),
              let l = chunks.last, l.hasSuffix("-----") else {
            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
        }

        return try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64).data
    }
//
//    /*
//
//     /**
//        * Attempts to decrypt a base64 encoded PrivateKey string
//        * with the given password. The privateKey must have been exported
//        * using the same password and underlying cipher (aes-gcm)
//        *
//        * @param {string} privateKey A base64 encoded encrypted key
//        * @param {string} password
//        * @returns {Promise<Uint8Array>} The private key protobuf
//        */
//       import: async function (privateKey, password) {
//         const base64 = multibase.names.base64
//         const encryptedKey = base64.decode(privateKey)
//         const cipher = ciphers.create()
//         return await cipher.decrypt(encryptedKey, password)
//       }
//
//     function create ({
//       algorithmTagLength = 16,
//       nonceLength = 12,
//       keyLength = 16,
//       digest = 'sha256',
//       saltLength = 16,
//       iterations = 32767
//     } = {}) {
//       const algorithm = 'aes-128-gcm'
//
//     /**
//        * Decrypts the given cipher text with the provided key. The `key` should
//        * be a cryptographically safe key and not a plaintext password. To use
//        * a plaintext password, use `decrypt`. The options used to create
//        * this decryption cipher must be the same as those used to create
//        * the encryption cipher.
//        *
//        * @private
//        * @param {Uint8Array} ciphertextAndNonce The data to decrypt
//        * @param {Uint8Array} key
//        * @returns {Promise<Uint8Array>}
//        */
//       async function decryptWithKey (ciphertextAndNonce, key) { // eslint-disable-line require-await
//         // Create Uint8Arrays of nonce, ciphertext and tag.
//         const nonce = ciphertextAndNonce.slice(0, nonceLength)
//         const ciphertext = ciphertextAndNonce.slice(nonceLength, ciphertextAndNonce.length - algorithmTagLength)
//         const tag = ciphertextAndNonce.slice(ciphertext.length + nonceLength)
//
//         // Create the cipher instance.
//         const cipher = crypto.createDecipheriv(algorithm, key, nonce)
//
//         // Decrypt and return result.
//         cipher.setAuthTag(tag)
//         return uint8ArrayConcat([cipher.update(ciphertext), cipher.final()])
//       }
//
//       /**
//        * Uses the provided password to derive a pbkdf2 key. The key
//        * will then be used to decrypt the data. The options used to create
//        * this decryption cipher must be the same as those used to create
//        * the encryption cipher.
//        *
//        * @param {Uint8Array} data The data to decrypt
//        * @param {string|Uint8Array} password A plain password
//        */
//       async function decrypt (data, password) { // eslint-disable-line require-await
//         // Create Uint8Arrays of salt and ciphertextAndNonce.
//         const salt = data.slice(0, saltLength)
//         const ciphertextAndNonce = data.slice(saltLength)
//
//         if (typeof password === 'string' || password instanceof String) {
//           password = uint8ArrayFromString(password)
//         }
//
//         // Derive the key using PBKDF2.
//         const key = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest)
//
//         // Decrypt and return result.
//         return decryptWithKey(ciphertextAndNonce, key)
//       }
//     */
//
//
//    /// Private Key
//    /// Raw Bytes: [1, 187, 116, 255, 157, 152, 71, 218, 87, 128, 62, 200, 148, 52, 164, 109, 237, 133, 89, 216, 240, 207, 80, 244, 60, 41, 32, 117, 184, 2, 231, 7, 9, 237, 110, 180, 86, 120, 103, 133, 84, 215, 104, 137, 101, 171, 127, 154, 54, 153, 229, 201, 46, 20, 1, 221, 211, 59, 129, 102, 129, 5, 76, 249, 30, 182]
//    /// Bytes: 66
//    /// ---
//    /// Public Key
//    /// Raw Bytes: [0, 110, 196, 197, 185, 248, 73, 76, 67, 3, 127, 38, 67, 168, 163, 6, 20, 223, 146, 233, 198, 22, 77, 105, 120, 172, 14, 6, 95, 144, 206, 161, 48, 16, 46, 29, 26, 53, 177, 60, 132, 212, 146, 37, 203, 104, 104, 81, 129, 246, 149, 222, 98, 0, 249, 7, 134, 50, 83, 122, 75, 74, 242, 216, 234, 152, 0, 196, 255, 251, 57, 249, 20, 79, 95, 72, 156, 153, 174, 189, 153, 145, 253, 72, 69, 57, 114, 180, 179, 100, 173, 183, 100, 235, 84, 42, 66, 116, 93, 139, 64, 190, 225, 15, 90, 159, 178, 212, 204, 25, 174, 159, 36, 177, 45, 227, 230, 147, 191, 167, 141, 103, 47, 96, 183, 159, 143, 89, 155, 144, 199, 38]
//    /// Bytes: 132
//    /// ---
//    func testECRawRep() throws {
//        let key = P521.Signing.PrivateKey()
//
//        let rawPrivKey = key.rawRepresentation
//        let rawPubKey = key.publicKey.rawRepresentation
//
//        //print(key.x963Representation.asString(base: .base64))
//        print("Private Key")
//        print("Raw Bytes: \(rawPrivKey.bytes)")
//        print("Bytes: \(rawPrivKey.bytes.count)")
//        print("---")
//        //print(rawRep.asString(base: .base64))
//        print("Public Key")
//        print("Raw Bytes: \(rawPubKey.bytes)")
//        print("Bytes: \(rawPubKey.bytes.count)")
//        print("---")
//
//        let importedKey = try P521.Signing.PrivateKey(rawRepresentation: rawPrivKey)
//
//        print(importedKey)
//    }
//
//    func testImportEncryptedPemKey() throws {
//        /*
//         * Generated with
//         * openssl genpkey -algorithm RSA
//         *   -pkeyopt rsa_keygen_bits:1024
//         *   -pkeyopt rsa_keygen_pubexp:65537
//         *   -out foo.pem
//         * openssl pkcs8 -in foo.pem -topk8 -v2 des3 -passout pass:mypassword
//         */
//        let pem = """
//        -----BEGIN ENCRYPTED PRIVATE KEY-----
//        MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQISznrfHd+D58CAggA
//        MBQGCCqGSIb3DQMHBAhx0DnnUvDiHASCAoCceplm+Cmwlgvn4hNsv6e4c/S1iA7w
//        2hU7Jt8JgRCIMWjP2FthXOAFLa2fD4g3qncYXcDAFBXNyoh25OgOwstO14YkxhDi
//        wG4TeppGUt9IlyyCol6Z4WhQs1TGm5OcD5xDta+zBXsBnlgmKLD5ZXPEYB+3v/Dg
//        SvM4sQz6NgkVHN52hchERsnknwSOghiK9mIBH0RZU5LgzlDy2VoBCiEPVdZ7m4F2
//        dft5e82zFS58vwDeNN/0r7fC54TyJf/8k3q94+4Hp0mseZ67LR39cvnEKuDuFROm
//        kLPLekWt5R2NGdunSQlA79BkrNB1ADruO8hQOOHMO9Y3/gNPWLKk+qrfHcUni+w3
//        Ofq+rdfakHRb8D6PUmsp3wQj6fSOwOyq3S50VwP4P02gKcZ1om1RvEzTbVMyL3sh
//        hZcVB3vViu3DO2/56wo29lPVTpj9bSYjw/CO5jNpPBab0B/Gv7JAR0z4Q8gn6OPy
//        qf+ddyW4Kcb6QUtMrYepghDthOiS3YJV/zCNdL3gTtVs5Ku9QwQ8FeM0/5oJZPlC
//        TxGuOFEJnYRWqIdByCP8mp/qXS5alSR4uoYQSd7vZG4vkhkPNSAwux/qK1IWfqiW
//        3XlZzrbD//9IzFVqGRs4nRIFq85ULK0zAR57HEKIwGyn2brEJzrxpV6xsHBp+m4w
//        6r0+PtwuWA0NauTCUzJ1biUdH8t0TgBL6YLaMjlrfU7JstH3TpcZzhJzsjfy0+zV
//        NT2TO3kSzXpQ5M2VjOoHPm2fqxD/js+ThDB3QLi4+C7HqakfiTY1lYzXl9/vayt6
//        DUD29r9pYL9ErB9tYko2rat54EY7k7Ts6S5jf+8G7Zz234We1APhvqaG
//        -----END ENCRYPTED PRIVATE KEY-----
//        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        let asn = try Asn1Parser.parse(data: raw.data)
//
//        var bitString:Data? = nil
//        var oct:Data? = nil
//        if case .sequence(let nodes) = asn {
//            nodes.forEach {
//                switch $0 {
//                case .objectIdentifier(let data):
//                    print("Got our obj id: \(data.asString(base: .base64))")
//                    print(String(data: data, encoding: .utf8) ?? "NIL")
//                case .bitString(let data):
//                    print("Got our bit string: \(data.asString(base: .base64))")
//                    bitString = data
//                case .sequence(let nodes):
//                    nodes.forEach { n in
//                        switch n {
//                        case .objectIdentifier(let data):
//                            print("Got our obj id: \(data.asString(base: .base16))")
//                            print(data.bytes.map { "\($0)"}.joined(separator: ",") )
//                        case .octetString(let data):
//                            oct = data
//                            //oct = raw.data
//                        default:
//                            print(n)
//                        }
//                    }
//                case .octetString(let data):
//                    //bitString = data
//                    oct = data
//                    //oct = raw.data
//                default:
//                    print($0)
//                }
//            }
//        }
//
//        if let bits = bitString {
//            print("Trying to Init Encrypted RSA Key from bitString")
//            let sk = try RSAPrivate(rawRepresentation: bits)
//            print(sk)
//        } else if let oct = oct {
//            print("Trying to Init Encrypted EC Key from octetString")
//            let sk = try RSAPrivate(rawRepresentation: oct)
//            print(sk)
//        }
//
//    }

////    func testSimplePEMP384SEC1PrivateKey() throws {
////        let pemPrivateKey = """
////        -----BEGIN EC PRIVATE KEY-----
////        MIGkAgEBBDDrN+qjvW7TqcXrKlTFbSP8AdbsIdqvRAgWHlaBicP7dkx+HKQidSiS
////        B2RLWyjSrs6gBwYFK4EEACKhZANiAAQrRiaztGpInYo1XqMnNokWY6g1TcgMuzgq
////        Ug6LzFQbCAqCrcnM9+c9Z4/63dC06ulL/KbLQgThjSiqRzgbzvmOvB0OzlpX1weK
////        usFrF4Pi0B9pKPmVCAlSzaxVEmRsbmw=
////        -----END EC PRIVATE KEY-----
////        """
////
////        // Test the working private keys.
////        let signingKey = try orFail { try P384.Signing.PrivateKey(pemRepresentation: pemPrivateKey) }
////        let keyAgreementKey = try orFail { try P384.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey) }
////        XCTAssertEqual(signingKey.rawRepresentation, keyAgreementKey.rawRepresentation)
////
////        // Now the non-matching private keys.
////        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
////        XCTAssertThrowsError(try P256.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
////        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: pemPrivateKey))
////        XCTAssertThrowsError(try P521.KeyAgreement.PrivateKey(pemRepresentation: pemPrivateKey))
////
////        // Now the public keys, which all fail.
////        XCTAssertThrowsError(try P256.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////        XCTAssertThrowsError(try P256.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////        XCTAssertThrowsError(try P384.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////        XCTAssertThrowsError(try P384.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////        XCTAssertThrowsError(try P521.Signing.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////        XCTAssertThrowsError(try P521.KeyAgreement.PublicKey(pemRepresentation: pemPrivateKey)) { error in
////            XCTAssertEqual(error as? CryptoKitASN1Error, .invalidPEMDocument)
////        }
////
////        // We can't reserialize the SEC1 keys, we don't emit them.
////    }


    func testRSA_Pem_Parsing_Public() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_1024_PUBLIC)

        print(parsed)
    }

    func testRSA_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_1024_PRIVATE)

        print(parsed)
    }

//    func testEC_Pem_Parsing_Public() throws {
//        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.EC_256_PUBLIC)
//
//        print(parsed)
//    }
//
//    func testEC_Pem_Parsing_Private() throws {
//        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.EC_256_PRIVATE)
//
//        print(parsed)
//    }

    func testEd25519_Pem_Parsing_Public() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.Ed25519_KeyPair.PUBLIC)

        print(parsed)
    }

    func testEd25519_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.Ed25519_KeyPair.PRIVATE)

        print(parsed)
    }

    func testSecp256k1_Pem_Parsing_Public() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.SECP256k1_KeyPair.PUBLIC)

        print(parsed)
    }

    func testSecp256k1_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.SECP256k1_KeyPair.PRIVATE)

        print(parsed)
    }
    
    /// -----BEGIN PGP PUBLIC KEY BLOCK-----
    /// Comment: C459 E542 8084 7C93 79BE  9AED DA30 E629 61F6 0A75
    /// Comment: Alice Wonderland <wonderland.alice@gmail.com>
    ///
    /// xsDNBGH7EL8BDADovR5cjh9P26RJ2uNxHuaEmdSFTY6q2uE5s4C6G+JEmtyuqhC9
    /// HEHgl7hv9LbsskLs50J0cCH9KQzMSl2OxztVGR8ABV06oDB+7fhHEPXNA4m1cLmQ
    /// zGCp9uDxCs3tuDJRkEMSo97T6AnQwDsl5rBBMqR9c/B7Ozml1aER6ehtxSQt7tuu
    /// x/9oD+9zFyUsBOuO20d/Km629h6IHfF+BadbJpzAqHunq+w2P4ks7XYlhFJdhMIq
    /// W0h31rI1CO4tM+DG7+6Osz6EJeHWZOc9tWM/5YxmJOA7SZU4t+yedif4bzC4+aCH
    /// W2AYlrWKivNOe4n46u1J+xlCtnLyK9Si39ylDuem118diaW1Qs99PkTbWawagYyc
    /// c+0flTYeWugLxc2LDUfq9b6r7tfu9hyez0TghdRwlvrQlnZCmEt/Ndg0YF0N3BFE
    /// dAzdpsiddEytH28L7hwHE5lECam4mGxBe8uNGYlDu8Viq7IYhyfCM0CNGlEwUQIW
    /// I7ahSbKTX66aZxcAEQEAAc0lTG93ZWxsIFRvbXMgPGxvd2VsbHMudmF1bHRAZ21h
    /// aWwuY29tPsLBFAQTAQoAPhYhBMRZ5UKAhHyTeb6a7dow5ilh9gp1BQJh+xC/AhsD
    /// BQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJENow5ilh9gp1sNoMAItC
    /// peoNv5MLrf5XJzP+bi+qmyAkiQSQ+0Jd17G1bUgrmpjeWXUqxu3fWgdxC6+CQLM9
    /// Fj69v11G1nrNlII0vyUN0nxPf9LS5qPMQKXZeAvT+lYrPaNWoE4ShI7MnJhxbME9
    /// TlQNikjOYgWt5dNlO+XqWAqP9ECQ0D2x2ulypVvhYPpvslp0+dQJGfIteTzqHHIY
    /// Cu7drWh5Sjy2pvIKOIjjrKapjwqidy6laDi4NDhbu/JWp4im1ZRpIU6qTZgH4b+U
    /// kCiAScNbnkYWtlIJ73j+Mh62FzZFQ+lSlVI8Fe/POyCwphVUw9smaEMO1WCsg0zP
    /// LLAfnVLhWXdaB1QfchlWU1C/zVtnyCZvkVzDTFCa4IyBrAqUCnXfJHOgivtUU4rl
    /// FvgynrDmeKjUqxJsVpEDS524nxR7aVdnfj34879SlJdliHeuwgpYF1q3eQYJMrR/
    /// wDCRBxbGpHTCOVjtU6GEeE9mV93SwVFAFHokD/iJMNTmGiUxFubHQXqCuAKuCc7A
    /// zQRh+xC/AQwA0NZs9RjrGAicIFIp6C7NHheyFDL8tet5ZDPO2Lya22AXgnWo3/bs
    /// QGXOlxhHJB7TK3Ma5wHAUKJ4BEvxpMtSwHnkFf/EAFZug2AXIvhJpdT8j/Lct6er
    /// VusrPxfDmlTH0QeKl3IklnvowyO3r6VeI2Lxga0gWlV+/gRq0vzwXM4vqeXzjNFo
    /// cCuNq4jSFT+zztYkud8GbAULBB5oeAp1Dhp+Uk84tu2Lg8rbBhK/H/ax4ozUrWi2
    /// G6azGx9psW9yq+LnQXaCSeGTn8XMqXzuwiD87TZgvuih/8iyMDoaFnuSKCw4v1WQ
    /// 8wWusZ2e0a05SCiRpYDlv+CJ93J5F1ApZXjD9NpYcU0O53zl+wqqNbj1HtxoGPrT
    /// EHvKPYZru/Dtea+sAxEXpYpUXFamQq4zIaI+dagD3vzSmFLRuCtaZElHhsS3t91K
    /// tQBKon1ZEN/VwdO7tix6gfDMMa3BpnllI2eaw2X+Ucdkm/jJHuPoxfy1lbFP8byy
    /// fDXvhR8Pnk8TABEBAAHCwPwEGAEKACYWIQTEWeVCgIR8k3m+mu3aMOYpYfYKdQUC
    /// YfsQvwIbDAUJA8JnAAAKCRDaMOYpYfYKddh5DADGLKm9AmtCh7bUR+r+MKdCyjTO
    /// LSiu0WACRUHIw+RLu5J5/haa7xZKPo6iN955oUS3j9CK0NTr/+ZxdDFwVc7kAjOn
    /// eoZefac0CFRtLO26LQcVh5jc6YV0ZVtchvbnWCOfwtsvVfsQUCo7oIfP2CacEGq2
    /// EIqYLTJ7leVgo3AqlR5MmPA+umMKVcb/KDkesMnhgThw3F+81cocRhxWVlNQam0/
    /// PAj2uprXt+yWU8K94gojmolBuSdBBMZGArjBr/oCAhBrWarg4gEnC0tGQBBLU1Us
    /// YEdv+2OYokrlIU96P2mtCDX+9GId+idUlgEPc+CQr3Um9W/syyxGI2e2wSlAlkjh
    /// +h84GvLvZpM9HU4HrHF5AxmXoEe2BF7ICHHju0vdignpEdtQ/XHckSLlxcJz8i2S
    /// XkMi7m1i5U0OWEXVr+Z3jeW2HVVEvEJ7aXL3oLLAVz3TROFY0M41zjrstyjg0sg5
    /// 5H93wgN5hgZ8MeDFEWbEh3p7e/MP9I/lo70bkA0=
    /// =n56n
    /// -----END PGP PUBLIC KEY BLOCK-----
//    func testOpen_ASC_PGP_PublicKey() throws {
//        let urls = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)
//        let downloadsFolder = urls[0]
//
//        print(downloadsFolder)
//        let fileURL = downloadsFolder.appendingPathComponent("C459E54280847C9379BE9AEDDA30E62961F60A75.asc")
//
//        let pubKey = try String(contentsOf: fileURL, encoding: .utf8)
//
//        print(pubKey)
//
//        //let keyPair = try LibP2PCrypto.Keys.parsePem(pubKey)
//        let keyPair = try LibP2PCrypto.Keys.importPublicPem(pubKey)
//
//        print(keyPair)
//    }
    
//    func testOpen_PGP_PublicKey() throws {
//        
//        let pubKey = """
//        xsDNBGH7EL8BDADovR5cjh9P26RJ2uNxHuaEmdSFTY6q2uE5s4C6G+JEmtyuqhC9
//        HEHgl7hv9LbsskLs50J0cCH9KQzMSl2OxztVGR8ABV06oDB+7fhHEPXNA4m1cLmQ
//        zGCp9uDxCs3tuDJRkEMSo97T6AnQwDsl5rBBMqR9c/B7Ozml1aER6ehtxSQt7tuu
//        x/9oD+9zFyUsBOuO20d/Km629h6IHfF+BadbJpzAqHunq+w2P4ks7XYlhFJdhMIq
//        W0h31rI1CO4tM+DG7+6Osz6EJeHWZOc9tWM/5YxmJOA7SZU4t+yedif4bzC4+aCH
//        W2AYlrWKivNOe4n46u1J+xlCtnLyK9Si39ylDuem118diaW1Qs99PkTbWawagYyc
//        c+0flTYeWugLxc2LDUfq9b6r7tfu9hyez0TghdRwlvrQlnZCmEt/Ndg0YF0N3BFE
//        dAzdpsiddEytH28L7hwHE5lECam4mGxBe8uNGYlDu8Viq7IYhyfCM0CNGlEwUQIW
//        I7ahSbKTX66aZxcAEQEAAc0lTG93ZWxsIFRvbXMgPGxvd2VsbHMudmF1bHRAZ21h
//        aWwuY29tPsLBFAQTAQoAPhYhBMRZ5UKAhHyTeb6a7dow5ilh9gp1BQJh+xC/AhsD
//        BQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJENow5ilh9gp1sNoMAItC
//        peoNv5MLrf5XJzP+bi+qmyAkiQSQ+0Jd17G1bUgrmpjeWXUqxu3fWgdxC6+CQLM9
//        Fj69v11G1nrNlII0vyUN0nxPf9LS5qPMQKXZeAvT+lYrPaNWoE4ShI7MnJhxbME9
//        TlQNikjOYgWt5dNlO+XqWAqP9ECQ0D2x2ulypVvhYPpvslp0+dQJGfIteTzqHHIY
//        Cu7drWh5Sjy2pvIKOIjjrKapjwqidy6laDi4NDhbu/JWp4im1ZRpIU6qTZgH4b+U
//        kCiAScNbnkYWtlIJ73j+Mh62FzZFQ+lSlVI8Fe/POyCwphVUw9smaEMO1WCsg0zP
//        LLAfnVLhWXdaB1QfchlWU1C/zVtnyCZvkVzDTFCa4IyBrAqUCnXfJHOgivtUU4rl
//        FvgynrDmeKjUqxJsVpEDS524nxR7aVdnfj34879SlJdliHeuwgpYF1q3eQYJMrR/
//        wDCRBxbGpHTCOVjtU6GEeE9mV93SwVFAFHokD/iJMNTmGiUxFubHQXqCuAKuCc7A
//        zQRh+xC/AQwA0NZs9RjrGAicIFIp6C7NHheyFDL8tet5ZDPO2Lya22AXgnWo3/bs
//        QGXOlxhHJB7TK3Ma5wHAUKJ4BEvxpMtSwHnkFf/EAFZug2AXIvhJpdT8j/Lct6er
//        VusrPxfDmlTH0QeKl3IklnvowyO3r6VeI2Lxga0gWlV+/gRq0vzwXM4vqeXzjNFo
//        cCuNq4jSFT+zztYkud8GbAULBB5oeAp1Dhp+Uk84tu2Lg8rbBhK/H/ax4ozUrWi2
//        G6azGx9psW9yq+LnQXaCSeGTn8XMqXzuwiD87TZgvuih/8iyMDoaFnuSKCw4v1WQ
//        8wWusZ2e0a05SCiRpYDlv+CJ93J5F1ApZXjD9NpYcU0O53zl+wqqNbj1HtxoGPrT
//        EHvKPYZru/Dtea+sAxEXpYpUXFamQq4zIaI+dagD3vzSmFLRuCtaZElHhsS3t91K
//        tQBKon1ZEN/VwdO7tix6gfDMMa3BpnllI2eaw2X+Ucdkm/jJHuPoxfy1lbFP8byy
//        fDXvhR8Pnk8TABEBAAHCwPwEGAEKACYWIQTEWeVCgIR8k3m+mu3aMOYpYfYKdQUC
//        YfsQvwIbDAUJA8JnAAAKCRDaMOYpYfYKddh5DADGLKm9AmtCh7bUR+r+MKdCyjTO
//        LSiu0WACRUHIw+RLu5J5/haa7xZKPo6iN955oUS3j9CK0NTr/+ZxdDFwVc7kAjOn
//        eoZefac0CFRtLO26LQcVh5jc6YV0ZVtchvbnWCOfwtsvVfsQUCo7oIfP2CacEGq2
//        EIqYLTJ7leVgo3AqlR5MmPA+umMKVcb/KDkesMnhgThw3F+81cocRhxWVlNQam0/
//        PAj2uprXt+yWU8K94gojmolBuSdBBMZGArjBr/oCAhBrWarg4gEnC0tGQBBLU1Us
//        YEdv+2OYokrlIU96P2mtCDX+9GId+idUlgEPc+CQr3Um9W/syyxGI2e2wSlAlkjh
//        +h84GvLvZpM9HU4HrHF5AxmXoEe2BF7ICHHju0vdignpEdtQ/XHckSLlxcJz8i2S
//        XkMi7m1i5U0OWEXVr+Z3jeW2HVVEvEJ7aXL3oLLAVz3TROFY0M41zjrstyjg0sg5
//        5H93wgN5hgZ8MeDFEWbEh3p7e/MP9I/lo70bkA0=
//        =n56n
//        """
//        
//        let data = try BaseEncoding.decode(pubKey, as: .base64)
//        print(data)
//        
//        //let keyPair = try LibP2PCrypto.Keys.parsePem(pubKey)
//        //let keyPair = try LibP2PCrypto.Keys.importPublicPem(pubKey)
//        //let keyPair = try LibP2PCrypto.Keys.importPublicDER(pubKey)
//        //let keyPair = try LibP2PCrypto.Keys.
//        
//        //print(keyPair)
//    }
    
    /// Is the public key embedded in these IDs??
    /// Dialed: 12D3KooWAfPDpPRRRBrmqy9is2zjU5srQ4hKuZitiGmh4NTTpS2d
    /// Provided: QmPoHmYtUt8BU9eiwMYdBfT6rooBnna5fdAZHUaZASGQY8
    ///           QmPoHmYtUt8BU9eiwMYdBfT6rooBnna5fdAZHUaZASGQY8
    ///
    /// Dialed: 12D3KooWF5Qbrbvhhha1AcqRULWAfYzFEnKvWVGBUjw489hpo5La
    /// Provided: Qmbp3SxL2SYcH6Ly4r5SGQwfxkDCJPuhJG35GCZimcTiBc
    ///           Qmbp3SxL2SYcH6Ly4r5SGQwfxkDCJPuhJG35GCZimcTiBc
    func testEmbeddedEd25519PublicKey() throws {
        
        let multi = try Multihash(b58String: "12D3KooWF5Qbrbvhhha1AcqRULWAfYzFEnKvWVGBUjw489hpo5La")
        print(multi)
        print("\(multi.value) (\(multi.value.count))")
        print("\(multi.digest!) (\(multi.digest!.count))")
        
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: multi.digest!.dropFirst(4))
        print(key)
        
        let kp = try LibP2PCrypto.Keys.KeyPair(publicKey: key)
        
        print(kp)
        
        print(try kp.id(withMultibasePrefix: false))
        
        let marshed = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: Data(multi.digest!))
        print(marshed)
        
        print(marshed.keyType)
        print(marshed.publicKey)
        print(try marshed.id(withMultibasePrefix: false))
        
    }

    static var allTests = [
        ("testRSA1024", testRSA1024),
        ("tesED25519", testED25519),
        ("testSecp256k1", testSecp256k1),
        ("testRSARawRepresentationRoundTrip", testRSARawRepresentationRoundTrip),
        ("testEd25519RawRepresentationRoundTrip", testEd25519RawRepresentationRoundTrip),
        ("testSecP256k1RawRepresentationRoundTrip", testSecP256k1RawRepresentationRoundTrip),
        ("testRSAMarshaledRoundTrip", testRSAMarshaledRoundTrip),
        ("testRSAMashallingRoundTrip", testRSAMashallingRoundTrip),
        ("testED25519MarshallingRoundTrip", testED25519MarshallingRoundTrip),
        ("testSecp256k1MarshallingRoundTrip", testSecp256k1MarshallingRoundTrip),
        ("testImportFromMarshalledPublicKey_Manual", testImportFromMarshalledPublicKey_Manual),
        ("testCreateKeyPairFromMarshalledPublicKey_1024", testCreateKeyPairFromMarshalledPublicKey_1024),
        ("testCreateKeyPairFromMarshalledPublicKey_2048", testCreateKeyPairFromMarshalledPublicKey_2048),
        ("testCreateKeyPairFromMarshalledPublicKey_3072", testCreateKeyPairFromMarshalledPublicKey_3072),
        ("testCreateKeyPairFromMarshalledPublicKey_4096", testCreateKeyPairFromMarshalledPublicKey_4096),
        ("testImportFromMarshalledPrivateKey_Manual", testImportFromMarshalledPrivateKey_Manual),
        ("testImportFromMarshalledPrivateKey", testImportFromMarshalledPrivateKey),
        ("testRSAMessageSignVerify", testRSAMessageSignVerify),
        ("testED25519MessageSignVerify", testED25519MessageSignVerify),
        ("testSecp256k1MessageSignVerify", testSecp256k1MessageSignVerify),
        ("testAESEncryption128", testAESEncryption128),
        ("testAESEncryption256", testAESEncryption256),
        ("testAESEncryption256AutoIV", testAESEncryption256AutoIV),
        ("testAESEncryption256AutoIVDifferent", testAESEncryption256AutoIVDifferent),
        ("testAESGCMEncryptionRoundTrip", testAESGCMEncryptionRoundTrip),
        ("testHMAC", testHMAC),
        ("testHMACKey", testHMACKey),
        ("testHMACBaseEncoded", testHMACBaseEncoded),
        ("testHMACVerify", testHMACVerify),
        ("testPemParsing", testPemParsing),
        ("testPemParsing_RSA_1024_Public", testPemParsing_RSA_1024_Public),
        ("testPemParsing_RSA_1024_Public_2", testPemParsing_RSA_1024_Public_2),
        ("testPemParsing_RSA_2048_Public", testPemParsing_RSA_2048_Public),
        ("testPemParsing_RSA_3072_Public", testPemParsing_RSA_3072_Public),
        ("testPemParsing_RSA_4096_Public", testPemParsing_RSA_4096_Public),
        ("testRSAOpenSSLPemImport", testRSAOpenSSLPemImport),
        ("testED25519PemImport_Public_Manual", testED25519PemImport_Public_Manual),
        ("testED25519PemImport_Public", testED25519PemImport_Public),
        ("testED25519PemImport_Private_Manual", testED25519PemImport_Private_Manual),
        ("testED25519PemImport_Private", testED25519PemImport_Private),
        ("testSecp256k1PemImport_Public_Manual", testSecp256k1PemImport_Public_Manual),
        ("testSecp256k1PemImport_Public", testSecp256k1PemImport_Public),
        ("testSecp256k1PemImport_Private_Manual", testSecp256k1PemImport_Private_Manual),
        ("testSecp256k1PemImport_Private", testSecp256k1PemImport_Private),
        ("testRSAEncryptedPrivateKeyPem2_Manual", testRSAEncryptedPrivateKeyPem2_Manual),
        ("testRSAEncryptedPrivateKeyPem2", testRSAEncryptedPrivateKeyPem2),
        ("testRSA_Pem_Parsing_Public", testRSA_Pem_Parsing_Public),
        ("testRSA_Pem_Parsing_Private", testRSA_Pem_Parsing_Private),
        ("testEd25519_Pem_Parsing_Public", testEd25519_Pem_Parsing_Public),
        ("testEd25519_Pem_Parsing_Private", testEd25519_Pem_Parsing_Private),
        ("testSecp256k1_Pem_Parsing_Public", testSecp256k1_Pem_Parsing_Public),
        ("testSecp256k1_Pem_Parsing_Private", testSecp256k1_Pem_Parsing_Private),
        ("testEmbeddedEd25519PublicKey", testEmbeddedEd25519PublicKey)
    ]
}
