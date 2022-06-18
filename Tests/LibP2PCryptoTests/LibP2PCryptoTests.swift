import XCTest
@testable import LibP2PCrypto
import Multibase
import Crypto
import CryptoSwift
import Multihash


/// Secp - https://techdocs.akamai.com/iot-token-access-control/docs/generate-ecdsa-keys
/// JWT - https://techdocs.akamai.com/iot-token-access-control/docs/generate-jwt-ecdsa-keys
/// Fixtures - http://cryptomanager.com/tv.html
/// RSA (Sign+Verify) - https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
/// PEM+DER (PKCS1&8) - https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
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
    
    /// These tests are skipped on Linux when using CryptoSwift due to very slow key generation times.
    #if canImport(Security)
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
    #endif

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
    
    func testImportFromMarshalledPrivateKey_1024() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_1024, base: .base64Pad)  //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertTrue(keyPair.hasPrivateKey)
          
        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        XCTAssertEqual(try keyPair.privateKey?.marshal().asString(base: .base64Pad), MarshaledData.PRIVATE_RSA_KEY_1024)
        
        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_1024)
    }
    
    func testImportFromMarshalledPrivateKey_2048() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_2048, base: .base64Pad)  //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertTrue(keyPair.hasPrivateKey)
           
        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        XCTAssertEqual(try keyPair.privateKey?.marshal().asString(base: .base64Pad), MarshaledData.PRIVATE_RSA_KEY_2048)
        
        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_2048)
    }
    
    func testImportFromMarshalledPrivateKey_3072() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_3072, base: .base64Pad)  //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertTrue(keyPair.hasPrivateKey)
    
        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        XCTAssertEqual(try keyPair.privateKey?.marshal().asString(base: .base64Pad), MarshaledData.PRIVATE_RSA_KEY_3072)
        
        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_3072)
    }
    
    func testImportFromMarshalledPrivateKey_4096() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_4096, base: .base64Pad)  //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)

        print(keyPair)
        
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertNotNil(keyPair.publicKey)
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertTrue(keyPair.hasPrivateKey)
        
        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        XCTAssertEqual(try keyPair.privateKey?.marshal().asString(base: .base64Pad), MarshaledData.PRIVATE_RSA_KEY_4096)
                
        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        XCTAssertEqual(try keyPair.publicKey.marshal().asString(base: .base64Pad), MarshaledData.PUBLIC_RSA_KEY_4096)
    }

    // - MARK: SIGN & VERIFY
    
    func testRSAMessageSignVerify_StaticKey() throws {
        let message = TestFixtures.RSA_1024.rawMessage.data(using: .utf8)!

        let rsa = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: TestFixtures.RSA_1024.privateMarshaled, base: .base64Pad)

        let signedData = try rsa.privateKey!.sign(message: message)
                
        print(signedData.asString(base: .base64Pad))
        
        XCTAssertEqual(signedData.asString(base: .base64Pad), TestFixtures.RSA_1024.signedMessages["algid:sign:RSA:message-PKCS1v15:SHA256"])
        XCTAssertNotEqual(message, signedData)
        
        // This just ensures that a newly instantiated Pub SecKey matches the derived pubkey from the keypair...
        let recoveredPubKey:RSAPublicKey = try RSAPublicKey(rawRepresentation: rsa.publicKey.data)
        XCTAssertEqual(rsa.publicKey.data, recoveredPubKey.rawRepresentation)
        XCTAssertEqual(try rsa.marshalPublicKey().asString(base: .base64Pad), TestFixtures.RSA_1024.publicMarshaled)
        
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
    
    func testRSAMessageSignVerify_DynamicKey() throws {
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

        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        
        print(keyPair)
        print(keyPair.attributes() ?? "NIL")

        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 1024)
        XCTAssertNil(keyPair.privateKey)
        
        XCTAssertEqual(try keyPair.exportPublicPEMString(), pem)
    }
    
    func testPemParsing_RSA_1024_Private() throws {

        let pem = TestPEMKeys.RSA_1024_PRIVATE

        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        
        print(keyPair)
        print(keyPair.attributes() ?? "NIL")

        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 1024)
        XCTAssertNotNil(keyPair.privateKey)
        
        XCTAssertEqual(try keyPair.exportPrivatePEMString(), pem)
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
        //let key = try LibP2PCrypto.Keys.importPublicDER(pem)
        let key = try RSAPublicKey(pem: pem, asType: RSAPublicKey.self)
        
        /// Let the parsePem method determine that it's a DER file and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        
        print(key)
        print(keyPair)

        XCTAssertEqual(key.data, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 1024)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_2048_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_2048_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_2048_PUBLIC, asType: RSAPublicKey.self)
        
        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_2048_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_2048_PUBLIC)
        
        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 2048)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_3072_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_3072_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_3072_PUBLIC, asType: RSAPublicKey.self)
        
        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_3072_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_3072_PUBLIC)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 3072)
        XCTAssertNil(keyPair.privateKey)
    }

    func testPemParsing_RSA_4096_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_4096_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_4096_PUBLIC, asType: RSAPublicKey.self)
        
        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_4096_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_4096_PUBLIC)

        print(key)
        print(keyPair)

        XCTAssertEqual(key.rawRepresentation, keyPair.publicKey.data)
        XCTAssert(keyPair.keyType == .rsa)
        XCTAssertEqual(keyPair.attributes()?.size, 4096)
        XCTAssertNil(keyPair.privateKey)
    }

    ///[42,134,72,134,247,13,1,1,1]
    func testRSAOpenSSLPemImport() throws {

        /// Generated with
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:3072
        ///   -pkeyopt rsa_keygen_pubexp:65537
        let pem = """
        -----BEGIN PRIVATE KEY-----
        MIIG/wIBADANBgkqhkiG9w0BAQEFAASCBukwggblAgEAAoIBgQDp0Whyqa8KmdvK
        0MsQGJEBzDAEHAZc0C6cr0rkb6Xwo+yB5kjZBRDORk0UXtYGE1pYt4JhUTmMzcWO
        v2xTIsdbVMQlNtput2U8kIqS1cSTkX5HxOJtCiIzntMzuR/bGPSOexkyFQ8nCUqb
        ROS7cln/ixprra2KMAKldCApN3ue2jo/JI1gyoS8sekhOASAa0ufMPpC+f70sc75
        Y53VLnGBNM43iM/2lsK+GI2a13d6rRy86CEM/ygnh/EDlyNDxo+SQmy6GmSv/lmR
        xgWQE2dIfK504KIxFTOphPAQAr9AsmcNnCQLhbz7YTsBz8WcytHGQ0Z5pnBQJ9AV
        CX9E6DFHetvs0CNLVw1iEO06QStzHulmNEI/3P8I1TIxViuESJxSu3pSNwG1bSJZ
        +Qee24vvlz/slBzK5gZWHvdm46v7vl5z7SA+whncEtjrswd8vkJk9fI/YTUbgOC0
        HWMdc2t/LTZDZ+LUSZ/b2n5trvdJSsOKTjEfuf0wICC08pUUk8MCAwEAAQKCAYEA
        ywve+DQCneIezHGk5cVvp2/6ApeTruXalJZlIxsRr3eq2uNwP4X2oirKpPX2RjBo
        NMKnpnsyzuOiu+Pf3hJFrTpfWzHXXm5Eq+OZcwnQO5YNY6XGO4qhSNKT9ka9Mzbo
        qRKdPrCrB+s5rryVJXKYVSInP3sDSQ2IPsYpZ6GW6Mv56PuFCpjTzElzejV7M0n5
        0bRmn+MZVMVUR54KYiaCywFgUzmr3yfs1cfcsKqMRywt2J58lRy/chTLZ6LILQMv
        4V01neVJiRkTmUfIWvc1ENIFM9QJlky9AvA5ASvwTTRz8yOnxoOXE/y4OVyOePjT
        cz9eumu9N5dPuUIMmsYlXmRNaeGZPD9bIgKY5zOlfhlfZSuOLNH6EHBNr6JAgfwL
        pdP43sbg2SSNKpBZ0iSMvpyTpbigbe3OyhnFH/TyhcC2Wdf62S9/FRsvjlRPbakW
        YhKAA2kmJoydcUDO5ccEga8b7NxCdhRiczbiU2cj70pMIuOhDlGAznyxsYbtyxaB
        AoHBAPy6Cbt6y1AmuId/HYfvms6i8B+/frD1CKyn+sUDkPf81xSHV7RcNrJi1S1c
        V55I0y96HulsR+GmcAW1DF3qivWkdsd/b4mVkizd/zJm3/Dm8p8QOnNTtdWvYoEB
        VzfAhBGaR/xflSLxZh2WE8ZHQ3IcRCXV9ZFgJ7PMeTprBJXzl0lTptvrHyo9QK1v
        obLrL/KuXWS0ql1uSnJr1vtDI5uW8WU4GDENeU5b/CJHpKpjVxlGg+7pmLknxlBl
        oBnZnQKBwQDs2Ky29qZ69qnPWowKceMJ53Z6uoUeSffRZ7xuBjowpkylasEROjuL
        nyAihIYB7fd7R74CnRVYLI+O2qXfNKJ8HN+TgcWv8LudkRcnZDSvoyPEJAPyZGfr
        olRCXD3caqtarlZO7vXSAl09C6HcL2KZ8FuPIEsuO0Aw25nESMg9eVMaIC6s2eSU
        NUt6xfZw1JC0c+f0LrGuFSjxT2Dr5WKND9ageI6afuauMuosjrrOMl2g0dMcSnVz
        KrtYa7Wi1N8CgcBFnuJreUplDCWtfgEen40f+5b2yAQYr4fyOFxGxdK73jVJ/HbW
        wsh2n+9mDZg9jIZQ/+1gFGpA6V7W06dSf/hD70ihcKPDXSbloUpaEikC7jxMQWY4
        uwjOkwAp1bq3Kxu21a+bAKHO/H1LDTrpVlxoJQ1I9wYtRDXrvBpxU2XyASbeFmNT
        FhSByFn27Ve4OD3/NrWXtoVwM5/ioX6ZvUcj55McdTWE3ddbFNACiYX9QlyOI/TY
        bhWafDCPmU9fj6kCgcEAjyQEfi9jPj2FM0RODqH1zS6OdG31tfCOTYicYQJyeKSI
        /hAezwKaqi9phHMDancfcupQ89Nr6vZDbNrIFLYC3W+1z7hGeabMPNZLYAs3rE60
        dv4tRHlaNRbORazp1iTBmvRyRRI2js3O++3jzOb2eILDUyT5St+UU/LkY7R5EG4a
        w1df3idx9gCftXufDWHqcqT6MqFl0QgIzo5izS68+PPxitpRlR3M3Mr4rCU20Rev
        blphdF+rzAavYyj1hYuRAoHBANmxwbq+QqsJ19SmeGMvfhXj+T7fNZQFh2F0xwb2
        rMlf4Ejsnx97KpCLUkoydqAs2q0Ws9Nkx2VEVx5KfUD7fWhgbpdnEPnQkfeXv9sD
        vZTuAoqInN1+vj1TME6EKR/6D4OtQygSNpecv23EuqEvyXWqRVsRt9Qd2B0H4k7h
        gnjREs10u7zyqBIZH7KYVgyh27WxLr859ap8cKAH6Fb+UOPtZo3sUeeume60aebn
        4pMwXeXP+LO8NIfRXV8mgrm86g==
        -----END PRIVATE KEY-----
        """

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPrivatePem(pem)
        let key = try RSAPrivateKey(pem: pem, asType: RSAPrivateKey.self)
        
        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

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

        let (_, bytes, _) = try PEM.pemToData(pem.bytes)

        let asn = try ASN1.Decoder.decode(data: Data(bytes))

        print(asn)

        guard case .sequence(let top) = asn, case .bitString(let pubKeyData) = top.last else {
            return XCTFail("Failed to extract our PubKey bit string")
        }

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubKeyData.bytes)

        print(pubKey)

        print(pubKey.rawRepresentation.asString(base: .base64Pad))

        /// Ensure that we reached the same results using both methods
        XCTAssertEqual(pubKey.rawRepresentation, try LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.data)
    }

    func testED25519PemImport_Public() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
        -----END PUBLIC KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .ed25519)
        XCTAssertNil(keyPair.privateKey)
        
        XCTAssertEqual(try keyPair.exportPublicPEMString(), pem)
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

        let (_, bytes, _) = try PEM.pemToData(pem.bytes)

        let asn = try ASN1.Decoder.decode(data: Data(bytes))

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

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .ed25519)
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertEqual(keyPair.publicKey.asString(base: .base64Pad), "CM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=")
        
        XCTAssertEqual(try keyPair.exportPrivatePEMString(), pem)
    }

    func testSecp256k1PemImport_Public_Manual() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
        xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END PUBLIC KEY-----
        """

        let (_, bytes, _) = try PEM.pemToData(pem.bytes)

        let asn = try ASN1.Decoder.decode(data: Data(bytes))

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

        XCTAssertEqual(pubKey.rawPublicKey.asString(base: .base64Pad), "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==")
        XCTAssertEqual(pubKey.rawRepresentation, try LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.rawRepresentation)
    }

    func testSecp256k1PemImport_Public() throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
        xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END PUBLIC KEY-----
        """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .secp256k1)
        XCTAssertNil(keyPair.privateKey)
        print(keyPair.attributes() ?? "NIL")
        
        XCTAssertEqual(try keyPair.exportPublicPEMString(), pem)
    }
    
    func testSecp256k1PemImport_Private_Manual() throws {
        let pem = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """

        let (_, bytes, _) = try PEM.pemToData(pem.bytes)

        let asn = try ASN1.Decoder.decode(data: Data(bytes))

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

        XCTAssertEqual(privKey.rawRepresentation.asString(base: .base64Pad), "mZunAPeZmGUS2IbOaCuikn+dJ7BzxQ/IET3CJvvjaxo=")
                
        /// Assert that we can derive the public from the private key
        XCTAssertEqual("IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==", privKey.publicKey.rawPublicKey.asString(base: .base64Pad))
        XCTAssertEqual(privKey.rawRepresentation, try LibP2PCrypto.Keys.KeyPair(pem: pem).privateKey?.rawRepresentation)
        XCTAssertEqual(privKey.publicKey.rawRepresentation, try LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.rawRepresentation)
    }

    func testSecp256k1PemImport_Private() throws {
        let pem = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """
        
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        XCTAssert(keyPair.keyType == .secp256k1)
        XCTAssertNotNil(keyPair.privateKey)
        XCTAssertEqual(keyPair.privateKey?.rawRepresentation.asString(base: .base64Pad), "mZunAPeZmGUS2IbOaCuikn+dJ7BzxQ/IET3CJvvjaxo=")
        /// Assert that we can derive the public from the private key
        XCTAssertEqual(keyPair.publicKey.asString(base: .base64Pad), "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==")
        
        print(try keyPair.exportPrivatePEM().asString(base: .base16))
        
        XCTAssertEqual(try keyPair.exportPrivatePEMString(), pem)
    }
    
    func testTempSecp() throws {
        let pemOG = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """
        /// Sequence:
        ///     Integer: 01
        ///     OctetString: 999ba700f799986512d886ce682ba2927f9d27b073c50fc8113dc226fbe36b1a
        ///     ObjectID: 06052b8104000a
        ///     BitString: 4200042200beb1c3052d405d7773a5328769e926c46811ab1f2cf0c437af8ec6d4d603a1763bbe15065a00bc1f5fb5e6b0784a145358a554b419784c333cc57f52ddef
        
        let pemRECON = """
        -----BEGIN EC PRIVATE KEY-----
        MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        oUQAQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        -----END EC PRIVATE KEY-----
        """
        /// Sequence:
        ///     Integer: 01
        ///     OctetString: 999ba700f799986512d886ce682ba2927f9d27b073c50fc8113dc226fbe36b1a
        ///     ObjectID: 06052b8104000a
        ///     BitString: 4200042200beb1c3052d405d7773a5328769e926c46811ab1f2cf0c437af8ec6d4d603a1763bbe15065a00bc1f5fb5e6b0784a145358a554b419784c333cc57f52ddef
        
        
        let chunks = pemOG.bytes.split(separator: 0x0a)
        let base64 = String(data: Data(chunks[1..<chunks.count-1].joined()), encoding: .utf8)!
        let pemData = Data(base64Encoded: base64)!
      
        let asn = try ASN1.Decoder.decode(data: pemData)
        
        //let asn = try ASN1.Decoder.decode(data: BaseEncoding.decode(pem).data)
        
        print(asn)
    }



    func testRSAEncryptedPrivateKeyPem() throws {
        /*
        * Generated with
        * openssl genpkey -algorithm RSA
        *   -pkeyopt rsa_keygen_bits:1024
        *   -pkeyopt rsa_keygen_pubexp:65537
        *   -out foo.pem
        * openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
        */
        let pem = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIP5QK2RfqUl4CAggA
        MB0GCWCGSAFlAwQBAgQQj3OyM9gnW2dd/eRHkxjGrgSCAoCpM5GZB0v27cxzZsGc
        O4/xqgwB0c/bSJ6QogtYU2KVoc7ZNQ5q9jtzn3I4ONvneOkpm9arzYz0FWnJi2C3
        BPiF0D1NkfvjvMLv56bwiG2A1oBECacyAb2pXYeJY7SdtYKvcbgs3jx65uCm6TF2
        BylteH+n1ewTQN9DLfASp1n81Ajq9lQGaK03SN2MUtcAPp7N9gnxJrlmDGeqlPRs
        KpQYRcot+kE6Ew8a5jAr7mAxwpqvr3SM4dMvADZmRQsM4Uc/9+YMUdI52DG87EWc
        0OUB+fnQ8jw4DZgOE9KKM5/QTWc3aEw/dzXr/YJsrv01oLazhqVHnEMG0Nfr0+DP
        q+qac1AsCsOb71VxaRlRZcVEkEfAq3gidSPD93qmlDrCnmLYTilcLanXUepda7ez
        qhjkHtpwBLN5xRZxOn3oUuLGjk8VRwfmFX+RIMYCyihjdmbEDYpNUVkQVYFGi/F/
        1hxOyl9yhGdL0hb9pKHH10GGIgoqo4jSTLlb4ennihGMHCjehAjLdx/GKJkOWShy
        V9hj8rAuYnRNb+tUW7ChXm1nLq14x9x1tX0ciVVn3ap/NoMkbFTr8M3pJ4bQlpAn
        wCT2erYqwQtgSpOJcrFeph9TjIrNRVE7Zlmr7vayJrB/8/oPssVdhf82TXkna4fB
        PcmO0YWLa117rfdeNM/Duy0ThSdTl39Qd+4FxqRZiHjbt+l0iSa/nOjTv1TZ/QqF
        wqrO6EtcM45fbFJ1Y79o2ptC2D6MB4HKJq9WCt064/8zQCVx3XPbb3X8Z5o/6koy
        ePGbz+UtSb9xczvqpRCOiFLh2MG1dUgWuHazjOtUcVWvilKnkjCMzZ9s1qG0sUDj
        nPyn
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: "mypassword")
        
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertEqual(keyPair.hasPrivateKey, true)
    }
    
    func testImportEncryptedPemKey() throws {
        /*
         * Generated with
         * openssl genpkey -algorithm RSA
         *   -pkeyopt rsa_keygen_bits:1024
         *   -pkeyopt rsa_keygen_pubexp:65537
         *   -out foo.pem
         * openssl pkcs8 -in foo.pem -topk8 -v2 des3 -passout pass:mypassword
         */
        let pem = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQISznrfHd+D58CAggA
        MBQGCCqGSIb3DQMHBAhx0DnnUvDiHASCAoCceplm+Cmwlgvn4hNsv6e4c/S1iA7w
        2hU7Jt8JgRCIMWjP2FthXOAFLa2fD4g3qncYXcDAFBXNyoh25OgOwstO14YkxhDi
        wG4TeppGUt9IlyyCol6Z4WhQs1TGm5OcD5xDta+zBXsBnlgmKLD5ZXPEYB+3v/Dg
        SvM4sQz6NgkVHN52hchERsnknwSOghiK9mIBH0RZU5LgzlDy2VoBCiEPVdZ7m4F2
        dft5e82zFS58vwDeNN/0r7fC54TyJf/8k3q94+4Hp0mseZ67LR39cvnEKuDuFROm
        kLPLekWt5R2NGdunSQlA79BkrNB1ADruO8hQOOHMO9Y3/gNPWLKk+qrfHcUni+w3
        Ofq+rdfakHRb8D6PUmsp3wQj6fSOwOyq3S50VwP4P02gKcZ1om1RvEzTbVMyL3sh
        hZcVB3vViu3DO2/56wo29lPVTpj9bSYjw/CO5jNpPBab0B/Gv7JAR0z4Q8gn6OPy
        qf+ddyW4Kcb6QUtMrYepghDthOiS3YJV/zCNdL3gTtVs5Ku9QwQ8FeM0/5oJZPlC
        TxGuOFEJnYRWqIdByCP8mp/qXS5alSR4uoYQSd7vZG4vkhkPNSAwux/qK1IWfqiW
        3XlZzrbD//9IzFVqGRs4nRIFq85ULK0zAR57HEKIwGyn2brEJzrxpV6xsHBp+m4w
        6r0+PtwuWA0NauTCUzJ1biUdH8t0TgBL6YLaMjlrfU7JstH3TpcZzhJzsjfy0+zV
        NT2TO3kSzXpQ5M2VjOoHPm2fqxD/js+ThDB3QLi4+C7HqakfiTY1lYzXl9/vayt6
        DUD29r9pYL9ErB9tYko2rat54EY7k7Ts6S5jf+8G7Zz234We1APhvqaG
        -----END ENCRYPTED PRIVATE KEY-----
        """
    
        /// We don't support the DES3 Cipher yet
        XCTAssertThrowsError(try LibP2PCrypto.Keys.KeyPair(pem: pem, password: "mypassword"))
    }
    
    func testRSAEncryptedPrivateKeyPemExportManual() throws {
        /*
        * Generated with
        * openssl genpkey -algorithm RSA
        *   -pkeyopt rsa_keygen_bits:1024
        *   -pkeyopt rsa_keygen_pubexp:65537
        *   -out foo.pem
        * openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
        */
        let pem = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIP5QK2RfqUl4CAggA
        MB0GCWCGSAFlAwQBAgQQj3OyM9gnW2dd/eRHkxjGrgSCAoCpM5GZB0v27cxzZsGc
        O4/xqgwB0c/bSJ6QogtYU2KVoc7ZNQ5q9jtzn3I4ONvneOkpm9arzYz0FWnJi2C3
        BPiF0D1NkfvjvMLv56bwiG2A1oBECacyAb2pXYeJY7SdtYKvcbgs3jx65uCm6TF2
        BylteH+n1ewTQN9DLfASp1n81Ajq9lQGaK03SN2MUtcAPp7N9gnxJrlmDGeqlPRs
        KpQYRcot+kE6Ew8a5jAr7mAxwpqvr3SM4dMvADZmRQsM4Uc/9+YMUdI52DG87EWc
        0OUB+fnQ8jw4DZgOE9KKM5/QTWc3aEw/dzXr/YJsrv01oLazhqVHnEMG0Nfr0+DP
        q+qac1AsCsOb71VxaRlRZcVEkEfAq3gidSPD93qmlDrCnmLYTilcLanXUepda7ez
        qhjkHtpwBLN5xRZxOn3oUuLGjk8VRwfmFX+RIMYCyihjdmbEDYpNUVkQVYFGi/F/
        1hxOyl9yhGdL0hb9pKHH10GGIgoqo4jSTLlb4ennihGMHCjehAjLdx/GKJkOWShy
        V9hj8rAuYnRNb+tUW7ChXm1nLq14x9x1tX0ciVVn3ap/NoMkbFTr8M3pJ4bQlpAn
        wCT2erYqwQtgSpOJcrFeph9TjIrNRVE7Zlmr7vayJrB/8/oPssVdhf82TXkna4fB
        PcmO0YWLa117rfdeNM/Duy0ThSdTl39Qd+4FxqRZiHjbt+l0iSa/nOjTv1TZ/QqF
        wqrO6EtcM45fbFJ1Y79o2ptC2D6MB4HKJq9WCt064/8zQCVx3XPbb3X8Z5o/6koy
        ePGbz+UtSb9xczvqpRCOiFLh2MG1dUgWuHazjOtUcVWvilKnkjCMzZ9s1qG0sUDj
        nPyn
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: "mypassword")
        
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertEqual(keyPair.hasPrivateKey, true)
        
        /// Now lets try and reverse the process and export the encrypted private key...
        
        // Salt: [63, 148, 10, 217, 23, 234, 82, 94]
        // Iterations: 2048
        // Password: mypassword
        // Cipher IV: 128 - [143, 115, 178, 51, 216, 39, 91, 103, 93, 253, 228, 71, 147, 24, 198, 174]
        
        let cipher = PEM.CipherAlgorithm.aes_128_cbc(iv: [143, 115, 178, 51, 216, 39, 91, 103, 93, 253, 228, 71, 147, 24, 198, 174])
        
        let pbkdf = PEM.PBKDFAlgorithm.pbkdf2(salt: [63, 148, 10, 217, 23, 234, 82, 94], iterations: 2048)
        
        // Generate Encryption Key from Password (confirmed key is same)
        let key = try pbkdf.deriveKey(password: "mypassword", ofLength: cipher.desiredKeyLength)
        
        let pemData:ASN1.Node = .sequence(nodes: [
            .integer(data: Data(hex: "0x00")),
            .sequence(nodes: [
                .objectIdentifier(data: Data(hex: "2a864886f70d010101")),
                .null
            ]),
            .octetString(data: Data(hex: "3082025d02010002818100cac3f636b7733cf98fbe26aad1a6578f9889995e87b820bb729b798f5178311eb1145b9b05a8384193c7b594d03ff626b3b94f79220bbd2ad6f4e688d6d8afd3744a34afcd484809c35bdf31b9b8d2e0ebac5671f9e6eae68766c6803b074c53f663b5f689e9505d672724904a7d6ab4d1fc31cda4a169206f8f772339c9716f02030100010281807b726b084d101fe3609c48365f858271ae50b7cb519dcc6fd30acd2b705258b572e20e1387922f0dddc70cca192f97d16042461c5d9a000580f1811976945e16ad180666399cbe2e42d6a2c07a77fc8aaad950dedeec5d6576eb8fb07bb70989d273dc22e892b3df04982ba6d597ef8238b84fed5b84e493512554e43723f1c1024100f24805a6fcf6f4324f6248d6646538474c790d4111dbb2b816972a0164ea94fc3a209afe5b38d8c7ee1661610e94727669fe3261b4c112fc5c6629477e380687024100d63f23ad2abd389127009bee7bd872acdfb85b3b53d0029bcb2afc11895a8f0b6273d331d85ed39ac1b9d61afa1d72227b6dea3cec7ff78a9e277e9c3d460fd9024100bc2c8e1f4d782cdfea6226ba454d8c716c06d4f186024203d29fe3a3239342d5c7fbcd05e329facd05b1623eb4c93d41953f363846e0727388fc5bf1482a117f0240543566f1664e0f50c612b037514826f299d05d537942d5f3a42c55fd128e9c90adf6b678ee017f8c613e88cffba4dd3a7e671a5d2ddbb251328e756e358b37290241008acc81787457ab32ae0a939e13805651da3403b9ae46b7d31f1580b3fb7ca4ba109ac9b624e24d6c5ca5765c0ea09c00173eebabc283e29b25a281744dcbbbd6"))
        ])
        
        // Encrypt Plaintext
        let ciphertext = try cipher.encrypt(bytes: ASN1.Encoder.encode(pemData), withKey: key)
        
        // Ensure the ciphertext is the same...
        XCTAssertEqual(Data(ciphertext), Data(hex: "a9339199074bf6edcc7366c19c3b8ff1aa0c01d1cfdb489e90a20b58536295a1ced9350e6af63b739f723838dbe778e9299bd6abcd8cf41569c98b60b704f885d03d4d91fbe3bcc2efe7a6f0886d80d6804409a73201bda95d878963b49db582af71b82cde3c7ae6e0a6e9317607296d787fa7d5ec1340df432df012a759fcd408eaf6540668ad3748dd8c52d7003e9ecdf609f126b9660c67aa94f46c2a941845ca2dfa413a130f1ae6302bee6031c29aafaf748ce1d32f003666450b0ce1473ff7e60c51d239d831bcec459cd0e501f9f9d0f23c380d980e13d28a339fd04d6737684c3f7735ebfd826caefd35a0b6b386a5479c4306d0d7ebd3e0cfabea9a73502c0ac39bef557169195165c5449047c0ab78227523c3f77aa6943ac29e62d84e295c2da9d751ea5d6bb7b3aa18e41eda7004b379c516713a7de852e2c68e4f154707e6157f9120c602ca28637666c40d8a4d5159105581468bf17fd61c4eca5f7284674bd216fda4a1c7d74186220a2aa388d24cb95be1e9e78a118c1c28de8408cb771fc628990e59287257d863f2b02e62744d6feb545bb0a15e6d672ead78c7dc75b57d1c895567ddaa7f3683246c54ebf0cde92786d0969027c024f67ab62ac10b604a938972b15ea61f538c8acd45513b6659abeef6b226b07ff3fa0fb2c55d85ff364d79276b87c13dc98ed1858b6b5d7badf75e34cfc3bb2d13852753977f5077ee05c6a4598878dbb7e9748926bf9ce8d3bf54d9fd0a85c2aacee84b5c338e5f6c527563bf68da9b42d83e8c0781ca26af560add3ae3ff33402571dd73db6f75fc679a3fea4a3278f19bcfe52d49bf71733beaa5108e8852e1d8c1b5754816b876b38ceb547155af8a52a792308ccd9f6cd6a1b4b140e39cfca7"))
        
        //print(pbkdf.iterations.bytes(totalBytes: 2))
        
//        print("*** DER ***")
//        //print(try ASN1.Decoder.decode(data: Data(keyPair.privateKey!.exportPrivateKeyPEM(withHeaderAndFooter: false))))
//        print("***********")
//
        // Encode Encrypted PEM (including pbkdf and cipher algos used)
        let nodes:ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(hex: "2a864886f70d01050d")),
                .sequence(nodes: [
                    .sequence(nodes: [
                        .objectIdentifier(data: Data(pbkdf.objectIdentifier)),
                        .sequence(nodes: [
                            .octetString(data: Data(pbkdf.salt)),
                            .integer(data: Data( pbkdf.iterations.bytes(totalBytes: 2) ))
                        ])
                    ]),
                    .sequence(nodes: [
                        .objectIdentifier(data: Data(cipher.objectIdentifier)),
                        .octetString(data: Data(cipher.iv))
                    ])
                ])
            ]),
            .octetString(data: Data(ciphertext))
        ])

        let encoded = ASN1.Encoder.encode(nodes)
        
        //print(encoded.asString(base: .base16))
        
        // Ensure the raw ASN data is equivalent
        XCTAssertEqual(Data(encoded).asString(base: .base16), "308202cf304906092a864886f70d01050d303c301b06092a864886f70d01050c300e04083f940ad917ea525e02020800301d060960864801650304010204108f73b233d8275b675dfde4479318c6ae04820280a9339199074bf6edcc7366c19c3b8ff1aa0c01d1cfdb489e90a20b58536295a1ced9350e6af63b739f723838dbe778e9299bd6abcd8cf41569c98b60b704f885d03d4d91fbe3bcc2efe7a6f0886d80d6804409a73201bda95d878963b49db582af71b82cde3c7ae6e0a6e9317607296d787fa7d5ec1340df432df012a759fcd408eaf6540668ad3748dd8c52d7003e9ecdf609f126b9660c67aa94f46c2a941845ca2dfa413a130f1ae6302bee6031c29aafaf748ce1d32f003666450b0ce1473ff7e60c51d239d831bcec459cd0e501f9f9d0f23c380d980e13d28a339fd04d6737684c3f7735ebfd826caefd35a0b6b386a5479c4306d0d7ebd3e0cfabea9a73502c0ac39bef557169195165c5449047c0ab78227523c3f77aa6943ac29e62d84e295c2da9d751ea5d6bb7b3aa18e41eda7004b379c516713a7de852e2c68e4f154707e6157f9120c602ca28637666c40d8a4d5159105581468bf17fd61c4eca5f7284674bd216fda4a1c7d74186220a2aa388d24cb95be1e9e78a118c1c28de8408cb771fc628990e59287257d863f2b02e62744d6feb545bb0a15e6d672ead78c7dc75b57d1c895567ddaa7f3683246c54ebf0cde92786d0969027c024f67ab62ac10b604a938972b15ea61f538c8acd45513b6659abeef6b226b07ff3fa0fb2c55d85ff364d79276b87c13dc98ed1858b6b5d7badf75e34cfc3bb2d13852753977f5077ee05c6a4598878dbb7e9748926bf9ce8d3bf54d9fd0a85c2aacee84b5c338e5f6c527563bf68da9b42d83e8c0781ca26af560add3ae3ff33402571dd73db6f75fc679a3fea4a3278f19bcfe52d49bf71733beaa5108e8852e1d8c1b5754816b876b38ceb547155af8a52a792308ccd9f6cd6a1b4b140e39cfca7")
        
        let exportedPEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +  encoded.toBase64().split(intoChunksOfLength: 64).joined(separator: "\n") + "\n-----END ENCRYPTED PRIVATE KEY-----"
        
        XCTAssertEqual(exportedPEM, pem)
    }
    
    func testRSAEncryptedPrivateKeyPemExport() throws {
        /*
        * Generated with
        * openssl genpkey -algorithm RSA
        *   -pkeyopt rsa_keygen_bits:1024
        *   -pkeyopt rsa_keygen_pubexp:65537
        *   -out foo.pem
        * openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
        */
        let pem = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIP5QK2RfqUl4CAggA
        MB0GCWCGSAFlAwQBAgQQj3OyM9gnW2dd/eRHkxjGrgSCAoCpM5GZB0v27cxzZsGc
        O4/xqgwB0c/bSJ6QogtYU2KVoc7ZNQ5q9jtzn3I4ONvneOkpm9arzYz0FWnJi2C3
        BPiF0D1NkfvjvMLv56bwiG2A1oBECacyAb2pXYeJY7SdtYKvcbgs3jx65uCm6TF2
        BylteH+n1ewTQN9DLfASp1n81Ajq9lQGaK03SN2MUtcAPp7N9gnxJrlmDGeqlPRs
        KpQYRcot+kE6Ew8a5jAr7mAxwpqvr3SM4dMvADZmRQsM4Uc/9+YMUdI52DG87EWc
        0OUB+fnQ8jw4DZgOE9KKM5/QTWc3aEw/dzXr/YJsrv01oLazhqVHnEMG0Nfr0+DP
        q+qac1AsCsOb71VxaRlRZcVEkEfAq3gidSPD93qmlDrCnmLYTilcLanXUepda7ez
        qhjkHtpwBLN5xRZxOn3oUuLGjk8VRwfmFX+RIMYCyihjdmbEDYpNUVkQVYFGi/F/
        1hxOyl9yhGdL0hb9pKHH10GGIgoqo4jSTLlb4ennihGMHCjehAjLdx/GKJkOWShy
        V9hj8rAuYnRNb+tUW7ChXm1nLq14x9x1tX0ciVVn3ap/NoMkbFTr8M3pJ4bQlpAn
        wCT2erYqwQtgSpOJcrFeph9TjIrNRVE7Zlmr7vayJrB/8/oPssVdhf82TXkna4fB
        PcmO0YWLa117rfdeNM/Duy0ThSdTl39Qd+4FxqRZiHjbt+l0iSa/nOjTv1TZ/QqF
        wqrO6EtcM45fbFJ1Y79o2ptC2D6MB4HKJq9WCt064/8zQCVx3XPbb3X8Z5o/6koy
        ePGbz+UtSb9xczvqpRCOiFLh2MG1dUgWuHazjOtUcVWvilKnkjCMzZ9s1qG0sUDj
        nPyn
        -----END ENCRYPTED PRIVATE KEY-----
        """
        
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: "mypassword")
        
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertEqual(keyPair.hasPrivateKey, true)
        
        XCTAssertThrowsError(try LibP2PCrypto.Keys.KeyPair(pem: pem, password: "wrongpassword"))
        
        /// Now lets try and reverse the process and export the encrypted private key...
        
        // Salt: [63, 148, 10, 217, 23, 234, 82, 94]
        // Iterations: 2048
        // Password: mypassword
        // Cipher IV: 128 - [143, 115, 178, 51, 216, 39, 91, 103, 93, 253, 228, 71, 147, 24, 198, 174]
        
        let cipher = PEM.CipherAlgorithm.aes_128_cbc(iv: [143, 115, 178, 51, 216, 39, 91, 103, 93, 253, 228, 71, 147, 24, 198, 174])
        
        let pbkdf = PEM.PBKDFAlgorithm.pbkdf2(salt: [63, 148, 10, 217, 23, 234, 82, 94], iterations: 2048)
        
        let exportedPEM = try keyPair.exportEncryptedPrivatePEMString(withPassword: "mypassword", usingPBKDF: pbkdf, andCipher: cipher)
        
        XCTAssertEqual(exportedPEM, pem)
        
        let differentPassword = try keyPair.exportEncryptedPrivatePEMString(withPassword: "wrongpassword", usingPBKDF: pbkdf, andCipher: cipher)
        
        XCTAssertNotEqual(differentPassword, pem)
        XCTAssertEqual(differentPassword.count, pem.count)
    }
    
    func testRSAEncryptedPrivateKeyPemExport2() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED, password: "mypassword")
        
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertEqual(keyPair.hasPrivateKey, true)
        
        XCTAssertThrowsError(try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED, password: "wrongpassword"))
        
        /// Now lets try and reverse the process and export the encrypted private key...
        
        // Salt: [227, 211, 237, 63, 238, 242, 38, 104]
        // Iterations: 2048
        // Password: mypassword
        // Cipher IV: 128 - [99, 63, 232, 90, 218, 184, 170, 21, 143, 54, 176, 16, 136, 237, 226, 231]
        
        let cipher = PEM.CipherAlgorithm.aes_128_cbc(iv: [99, 63, 232, 90, 218, 184, 170, 21, 143, 54, 176, 16, 136, 237, 226, 231])
        
        let pbkdf = PEM.PBKDFAlgorithm.pbkdf2(salt: [227, 211, 237, 63, 238, 242, 38, 104], iterations: 2048)
        
        let exportedPEM = try keyPair.exportEncryptedPrivatePEMString(withPassword: "mypassword", usingPBKDF: pbkdf, andCipher: cipher)
        
        XCTAssertEqual(exportedPEM, TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED)
                
        //let differentPassword = try keyPair.exportEncryptedPrivatePEMString(withPassword: "wrongpassword", usingPBKDF: pbkdf, andCipher: cipher)
        
        //XCTAssertNotEqual(differentPassword, TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED)
        //XCTAssertEqual(differentPassword.count, TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED.count)
    }
    
    func testRSAEncryptedPrivateKeyPemRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.RSA(bits: .B2048))
        
        XCTAssertEqual(keyPair.keyType, .rsa)
        XCTAssertEqual(keyPair.hasPrivateKey, true)
        
        let exportedPEM = try keyPair.exportEncryptedPrivatePEMString(withPassword: "mypassword")
        
        
        let recoveredKey = try LibP2PCrypto.Keys.KeyPair(pem: exportedPEM, password: "mypassword")
        
        XCTAssertEqual(recoveredKey.keyType, .rsa)
        XCTAssertEqual(recoveredKey.hasPrivateKey, true)
        
        XCTAssertEqual(keyPair.privateKey?.rawRepresentation, recoveredKey.privateKey?.rawRepresentation)
        XCTAssertEqual(keyPair.publicKey.rawRepresentation, recoveredKey.publicKey.rawRepresentation)
        XCTAssertEqual(try keyPair.id(), try recoveredKey.id())
        //let differentPassword = try keyPair.exportEncryptedPrivatePEMString(withPassword: "wrongpassword", usingPBKDF: pbkdf, andCipher: cipher)
        
        //XCTAssertNotEqual(differentPassword, TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED)
        //XCTAssertEqual(differentPassword.count, TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED.count)
    }
    
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
//    func testRSAEncryptedPrivateKeyPem2_Manual() throws {
//
//        // Generated with
//        // openssl genpkey -algorithm RSA
//        //   -pkeyopt rsa_keygen_bits:1024
//        //   -pkeyopt rsa_keygen_pubexp:65537
//        //   -out foo.pem
//        let unencryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.UNENCRYPTED
//
//        // Encrypted with
//        // openssl pkcs8 -in foo.pem -topk8 -v2 aes-128-cbc -passout pass:mypassword
//        let encryptedPem = TestPEMKeys.RSA_1024_PRIVATE_ENCRYPTED_PAIR.ENCRYPTED
//
//        let asn = try Asn1Parser.parse(data: pemToData(encryptedPem))
//
//        print(asn)
//
////        sequence(nodes: [
////            libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
////                libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes), //[42,134,72,134,247,13,1,5,13]
////                libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
////                    libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
////                        libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
////                        libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
////                            libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),       //SALT
////                            libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
////                        ])
////                    ]),
////                    libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
////                        libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc [96,134,72,1,101,3,4,1,2]
////                        libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)           //IV
////                    ])
////                ])
////            ]),
////            libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
////        ])
//
//        var saltData:Data? = nil
//        var ivData:Data? = nil
//        var itterationsData:Int? = nil
//        var ciphertextData:Data? = nil
//
//        if case .sequence(let top) = asn {
//            if case .sequence(let top1) = top.first {
//                if case .sequence(let top2) = top1.last {
//                    if case .sequence(let top3) = top2.first {
//                        if case .sequence(let top4) = top3.last {
//                            if case .octetString(let salt) = top4.first {
//                                print("Found the salt: \(salt.asString(base: .base16))")
//                                saltData = salt
//                            }
//                            if case .integer(let int) = top4.last {
//                                print("Found the itterations: \(int.asString(base: .base16))")
//                                itterationsData = Int(int.asString(base: .base16), radix: 16)
//                            }
//                        }
//                    }
//                    if case .sequence(let bottom3) = top2.last {
//                        if case .octetString(let iv) = bottom3.last {
//                            print("Found the IV: \(iv.asString(base: .base16))")
//                            ivData = iv
//                        }
//                    }
//                }
//            }
//            if case .octetString(let cipherText) = top.last {
//                print("Found the ciphertext: \(cipherText.count)")
//                ciphertextData = cipherText
//            }
//        }
//
//        // Ensure we have everything we need to proceed...
//        guard let salt = saltData, let iv = ivData, let itterations = itterationsData, let ciphertext = ciphertextData else {
//            return XCTFail("Failed to parse our pcks#8 key")
//        }
//
//        // Attempt to derive the aes encryption key from the password and salt
//        // PBKDF2-SHA1
//        guard let key = PBKDF2.SHA1(password: "mypassword", salt: salt, keyByteCount: 16, rounds: itterations) else {
//            return XCTFail("Failed to derive key from password and salt")
//        }
//
//        // This also works, but it is incredibly slow...
////        let key2 = try PKCS5.PBKDF2(
////            password: Array("mypassword".utf8),
////            salt: salt.bytes,
////            iterations: itterations,
////            keyLength: 16, /* 16 == AES-128, 32 == AES-256 */
////            variant: .sha256
////        ).calculate()
//
//        // These should be the same
//        print("Key 1 -> \(key.asString(base: .base16))")
//        //print("Key 2 -> \(key2.asString(base: .base16))")
//
//        //Create our CBC AES Cipher
//        let aes = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .noPadding)
//
//        // Try GCM
//        //let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .detached), padding: .noPadding)
//
//        let decryptedKey = try aes.decrypt(ciphertext.bytes)
//
//        print(decryptedKey.asString(base: .base64))
//
//        let deASN = try Asn1Parser.parse(data: Data(decryptedKey))
//        print(deASN)
//        print("-----")
//        let unASN = try Asn1Parser.parse(data: pemToData(unencryptedPem))
//        print(unASN)
//
//        /// sequence(nodes: [
//        ///     libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//        ///         libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),   // [42,134,72,134,247,13,1,1,1] => RSA Private Key
//        ///         libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),
//        ///                 libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//        ///                     libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),
//        ///                     libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)
//        ///                 ])
//        ///             ]),
//        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),
//        ///                 libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)
//        ///             ])
//        ///         ]),
//        ///         libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
//        ///     ])
//        /// ])
//
//        var unencRawPrivateKeyData:Data? = nil
//        if case .sequence(let top) = unASN {
//            if case .octetString(let d) = top.last {
//                print("Found our unenc octetString")
//                unencRawPrivateKeyData = d
//            }
//        }
//
//        var decRawPrivateKeyData:Data? = nil
//        if case .sequence(let top) = deASN {
//            if case .octetString(let d) = top.last {
//                print("Found our dec octetString")
//                decRawPrivateKeyData = d
//            }
//        }
//
//        guard let uRawPrivKeyData = unencRawPrivateKeyData else {
//            return XCTFail("Failed to parse our unencrypted private pem key...")
//        }
//
//        guard let dRawPrivKeyData = decRawPrivateKeyData else {
//            return XCTFail("Failed to parse our decrypted private pem key...")
//        }
//
//        print(uRawPrivKeyData.asString(base: .base64))
//        print(dRawPrivKeyData.asString(base: .base64))
//
//        print(dRawPrivKeyData.count)
//        print(uRawPrivKeyData.count)
//
//        let og = try RSAPrivateKey(rawRepresentation: uRawPrivKeyData)
//        let de = try RSAPrivateKey(rawRepresentation: dRawPrivKeyData)
//
//        print(og)
//
//        print(de)
//
//        XCTAssertEqual(uRawPrivKeyData, dRawPrivKeyData)
//        XCTAssertEqual(og, de)
//
//
//        //XCTAssertEqual(uRawPrivKeyData.bytes, decryptedKey, "Not Equal")
//    }

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

        let fromDecrypted = try LibP2PCrypto.Keys.KeyPair(pem: unencryptedPem)
        let fromEncrypted = try LibP2PCrypto.Keys.KeyPair(pem: encryptedPem, password: "mypassword")

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


////     /**
////        * Decrypts the given cipher text with the provided key. The `key` should
////        * be a cryptographically safe key and not a plaintext password. To use
////        * a plaintext password, use `decrypt`. The options used to create
////        * this decryption cipher must be the same as those used to create
////        * the encryption cipher.
////        *
////        * @private
////        * @param {Uint8Array} ciphertextAndNonce The data to decrypt
////        * @param {Uint8Array} key
////        * @returns {Promise<Uint8Array>}
////        */
////       async function decryptWithKey (ciphertextAndNonce, key) { // eslint-disable-line require-await
////         // Create Uint8Arrays of nonce, ciphertext and tag.
////         const nonce = ciphertextAndNonce.slice(0, nonceLength)
////         const ciphertext = ciphertextAndNonce.slice(nonceLength, ciphertextAndNonce.length - algorithmTagLength)
////         const tag = ciphertextAndNonce.slice(ciphertext.length + nonceLength)
////
////         // Create the cipher instance.
////         const cipher = crypto.createDecipheriv(algorithm, key, nonce)
////
////         // Decrypt and return result.
////         cipher.setAuthTag(tag)
////         return uint8ArrayConcat([cipher.update(ciphertext), cipher.final()])
////       }
////
////       /**
////        * Uses the provided password to derive a pbkdf2 key. The key
////        * will then be used to decrypt the data. The options used to create
////        * this decryption cipher must be the same as those used to create
////        * the encryption cipher.
////        *
////        * @param {Uint8Array} data The data to decrypt
////        * @param {string|Uint8Array} password A plain password
////        */
////       async function decrypt (data, password) { // eslint-disable-line require-await
////         // Create Uint8Arrays of salt and ciphertextAndNonce.
////         const salt = data.slice(0, saltLength)
////         const ciphertextAndNonce = data.slice(saltLength)
////
////         if (typeof password === 'string' || password instanceof String) {
////           password = uint8ArrayFromString(password)
////         }
////
////         // Derive the key using PBKDF2.
////         const key = crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest)
////
////         // Decrypt and return result.
////         return decryptWithKey(ciphertextAndNonce, key)
////       }
////     */
////
////
////    /// Private Key
////    /// Raw Bytes: [1, 187, 116, 255, 157, 152, 71, 218, 87, 128, 62, 200, 148, 52, 164, 109, 237, 133, 89, 216, 240, 207, 80, 244, 60, 41, 32, 117, 184, 2, 231, 7, 9, 237, 110, 180, 86, 120, 103, 133, 84, 215, 104, 137, 101, 171, 127, 154, 54, 153, 229, 201, 46, 20, 1, 221, 211, 59, 129, 102, 129, 5, 76, 249, 30, 182]
////    /// Bytes: 66
////    /// ---
////    /// Public Key
////    /// Raw Bytes: [0, 110, 196, 197, 185, 248, 73, 76, 67, 3, 127, 38, 67, 168, 163, 6, 20, 223, 146, 233, 198, 22, 77, 105, 120, 172, 14, 6, 95, 144, 206, 161, 48, 16, 46, 29, 26, 53, 177, 60, 132, 212, 146, 37, 203, 104, 104, 81, 129, 246, 149, 222, 98, 0, 249, 7, 134, 50, 83, 122, 75, 74, 242, 216, 234, 152, 0, 196, 255, 251, 57, 249, 20, 79, 95, 72, 156, 153, 174, 189, 153, 145, 253, 72, 69, 57, 114, 180, 179, 100, 173, 183, 100, 235, 84, 42, 66, 116, 93, 139, 64, 190, 225, 15, 90, 159, 178, 212, 204, 25, 174, 159, 36, 177, 45, 227, 230, 147, 191, 167, 141, 103, 47, 96, 183, 159, 143, 89, 155, 144, 199, 38]
////    /// Bytes: 132
////    /// ---
////    func testECRawRep() throws {
////        let key = P521.Signing.PrivateKey()
////
////        let rawPrivKey = key.rawRepresentation
////        let rawPubKey = key.publicKey.rawRepresentation
////
////        //print(key.x963Representation.asString(base: .base64))
////        print("Private Key")
////        print("Raw Bytes: \(rawPrivKey.bytes)")
////        print("Bytes: \(rawPrivKey.bytes.count)")
////        print("---")
////        //print(rawRep.asString(base: .base64))
////        print("Public Key")
////        print("Raw Bytes: \(rawPubKey.bytes)")
////        print("Bytes: \(rawPubKey.bytes.count)")
////        print("---")
////
////        let importedKey = try P521.Signing.PrivateKey(rawRepresentation: rawPrivKey)
////
////        print(importedKey)
////    }
    
    func testRSA_Pem_Parsing_Public() throws {
        //let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_1024_PUBLIC)
        let rsaPublic = try RSAPublicKey(pem: TestPEMKeys.RSA_1024_PUBLIC, asType: RSAPublicKey.self)

        print(rsaPublic)
    }
    
    func testRSA_Pem_Parsing_Private() throws {
        let rsaPrivate = try RSAPrivateKey(pem: TestPEMKeys.RSA_1024_PRIVATE, asType: RSAPrivateKey.self)

        print(rsaPrivate)
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
        //let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.Ed25519_KeyPair.PUBLIC)

        //print(parsed)
        
        let ed25519Public = try Curve25519.Signing.PublicKey(pem: TestPEMKeys.Ed25519_KeyPair.PUBLIC, asType: Curve25519.Signing.PublicKey.self)
        
        print(ed25519Public)
        
        let ed25519Private = try Curve25519.Signing.PrivateKey(pem: TestPEMKeys.Ed25519_KeyPair.PRIVATE, asType: Curve25519.Signing.PrivateKey.self)

        print(ed25519Private)
        
        XCTAssertEqual(ed25519Private.publicKey, ed25519Public)
    }

    func testEd25519_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.Ed25519_KeyPair.PRIVATE)

        print(parsed)
    }
    
    /// openssl ecparam -genkey -name secp256k1 -out ec_key.pem -param_enc explicit
    /// Create Secp256k1 Key: `openssl ecparam -name secp256k1 -genkey -noout -out ec-secp256k1-priv-key.pem`
    /// Create Public PEM from Private PEM: `openssl ec -in ec-secp256k1-priv-key.pem -pubout > ec-secp256k1-pub-key.pem`
//    func testSecp256k1_Pem_Parsing_Public() throws {
//        //let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.SECP256k1_KeyPair.PUBLIC)
//
//        //print(parsed)
//
//        //2a8648ce3d0201
//        //2b8104000a
//        //let secp256k1Public = try Secp256k1PublicKey(pem: TestPEMKeys.SECP256k1_KeyPair.PUBLIC, asType: Secp256k1PublicKey.self)
//
//        //print(secp256k1Public)
//
//        //let secp256k1Private = try Secp256k1PrivateKey(pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE, asType: Secp256k1PrivateKey.self)
//
//        //print(secp256k1Private)
//
////        XCTAssertEqual(secp256k1Private.publicKey, secp256k1Public)
//
//        ///   0:d=0  hl=3 l= 162 cons: SEQUENCE
//        ///   3:d=1  hl=2 l=   1 prim:  INTEGER           :01
//        ///   6:d=1  hl=2 l=  44 cons:  SEQUENCE
//        ///   8:d=2  hl=2 l=   7 prim:   OBJECT            :prime-field
//        ///  17:d=2  hl=2 l=  33 prim:   INTEGER           :FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
//        ///  52:d=1  hl=2 l=   6 cons:  SEQUENCE
//        ///  54:d=2  hl=2 l=   1 prim:   OCTET STRING      [HEX DUMP]:00
//        ///  57:d=2  hl=2 l=   1 prim:   OCTET STRING      [HEX DUMP]:07
//        ///  60:d=1  hl=2 l=  65 prim:  OCTET STRING      [HEX DUMP]:0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
//        /// 127:d=1  hl=2 l=  33 prim:  INTEGER           :FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//        /// 162:d=1  hl=2 l=   1 prim:  INTEGER           :01
//        let ecPEM = """
//        -----BEGIN EC PRIVATE KEY-----
//        MIIBEwIBAQQgiOURdsStmumMgM2c29TlUxEdNxrQns8VPeM0sV08MtKggaUwgaIC
//        AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
//        MAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm
//        o8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu
//        3OavSKA7v9JejNA2QUECAQGhRANCAASDsnwEULWLn8HV8iobNGNAdze/SbwbehJ3
//        l+gvkHpYQ2tMD9d4NTMDKFTxPUN+w0ktADgGaPhd2flQ2dNL7nFT
//        -----END EC PRIVATE KEY-----
//        """
//        let ecPEM2 = """
//        -----BEGIN EC PRIVATE KEY-----
//        MHQCAQEEIFTQEjBp0zAIiafoD6+xwBS/kAvc4qq0BVZ1QTk//EguoAcGBSuBBAAK
//        oUQDQgAEmLNqAvsnenwfMz8+U5MUGb4zwhfxVBjRqn7Bqa/CCVPtsqSMfhzaE30u
//        OQlpl7VjL/jrZYpUv8aPRfTBSn396w==
//        -----END EC PRIVATE KEY-----
//        """
//
//        let ecParams = """
//        -----BEGIN EC PARAMETERS-----
//        BgUrgQQACg==
//        -----END EC PARAMETERS-----
//        """
//
//        let ecPEMPrivate = """
//        -----BEGIN EC PRIVATE KEY-----
//        MHQCAQEEINMfarC/mmrd3GKaOfl+7iXffsdg4MqMa4HY5wkBDilooAcGBSuBBAAK
//        oUQDQgAEJ9kHLQX2sVEh14Duq23w5af30636vUx93jVsMIDhONwwuQc2N7mv4/oY
//        8oB3EPTRyh+o+6J+9qXI1VaJjvSr5Q==
//        -----END EC PRIVATE KEY-----
//        """
//        let ecPEMPublic = """
//        -----BEGIN PUBLIC KEY-----
//        MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEJ9kHLQX2sVEh14Duq23w5af30636vUx9
//        3jVsMIDhONwwuQc2N7mv4/oY8oB3EPTRyh+o+6J+9qXI1VaJjvSr5Q==
//        -----END PUBLIC KEY-----
//        """
//
//        let pemBase64String = ecPEM2.split(separator: "\n").dropFirst().dropLast().joined()
//        let pemData = Data(base64Encoded: pemBase64String)!
//
//        print(pemData.toHexString())
//
//        //30820113
//        //  020101
//        //  042088e51176c4ad9ae98c80cd9cdbd4e553111d371ad09ecf153de334b15d3c32d2a081a53081a2
//        //  020101
//        //  302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
//        //  3006
//        //    040100
//        //    040107
//        //  04410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
//        //  022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0//364141
//        //  020101
//        //  a144
//        //    0342
//        //      00
//        //      0483b27c0450b58b9fc1d5f22a1b3463407737bf49bc1b7a127797e82f907a58436b4c0fd7783533032854f13d437ec3492d00380668f85dd9f950d9d34bee7153
//
//
//        //3074
//        //  020101
//        //  042054d0123069d3300889a7e80fafb1c014bf900bdce2aab405567541393ffc
//        //482ea00706052b8104000aa1440342000498b36a02fb277a7c1f333f3e53931419be33c217f15418d1aa7ec1a9afc20953edb2a48c7e1cda137d2e39096997b5632ff8eb658a54bfc68f45f4c14a7dfdeb
//
//        let parsed = try ASN1.Decoder.decode(data: pemData)
//
//        print(parsed)
//
////        if case .octetString(let rawData) = parsed {
////            let edPrivate = try Curve25519.Signing.PrivateKey(rawRepresentation: rawData)
////            print(edPrivate)
////        }
//    }
    
    func testSecp256k1_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE)

        print(parsed)
    }
    
    func testImportSecp256k1PEM() throws {
        let secp256k1Public = try Secp256k1PublicKey(pem: TestPEMKeys.SECP256k1_KeyPair.PUBLIC, asType: Secp256k1PublicKey.self)
        
        print(secp256k1Public)
        
        let secp256k1Private = try Secp256k1PrivateKey(pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE, asType: Secp256k1PrivateKey.self)

        print(secp256k1Private)
        
        XCTAssertEqual(secp256k1Private.publicKey, secp256k1Public)
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
        ("testImportFromMarshalledPrivateKey_1024", testImportFromMarshalledPrivateKey_1024),
        ("testImportFromMarshalledPrivateKey_2048", testImportFromMarshalledPrivateKey_2048),
        ("testImportFromMarshalledPrivateKey_3072", testImportFromMarshalledPrivateKey_3072),
        ("testImportFromMarshalledPrivateKey_4096", testImportFromMarshalledPrivateKey_4096),
        ("testRSAMessageSignVerify_StaticKey", testRSAMessageSignVerify_StaticKey),
        ("testRSAMessageSignVerify_DynamicKey", testRSAMessageSignVerify_DynamicKey),
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
        //("testPemParsing", testPemParsing),
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
        //("testRSAEncryptedPrivateKeyPem2_Manual", testRSAEncryptedPrivateKeyPem2_Manual),
        ("testImportEncryptedPemKey", testImportEncryptedPemKey),
        ("testRSAEncryptedPrivateKeyPemExportManual", testRSAEncryptedPrivateKeyPemExportManual),
        ("testRSAEncryptedPrivateKeyPemExport", testRSAEncryptedPrivateKeyPemExport),
        ("testRSAEncryptedPrivateKeyPem", testRSAEncryptedPrivateKeyPem),
        ("testRSAEncryptedPrivateKeyPem2", testRSAEncryptedPrivateKeyPem2),
        ("testRSA_Pem_Parsing_Public", testRSA_Pem_Parsing_Public),
        ("testRSA_Pem_Parsing_Private", testRSA_Pem_Parsing_Private),
        ("testEd25519_Pem_Parsing_Public", testEd25519_Pem_Parsing_Public),
        //("testEd25519_Pem_Parsing_Private", testEd25519_Pem_Parsing_Private),
        //("testSecp256k1_Pem_Parsing_Public", testSecp256k1_Pem_Parsing_Public),
        ("testSecp256k1_Pem_Parsing_Private", testSecp256k1_Pem_Parsing_Private),
        ("testEmbeddedEd25519PublicKey", testEmbeddedEd25519PublicKey)
    ]
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

/// RSA Object Identifier --> 2a 86 48 86 f7 0d 01 01 01 (bit length independent, pub/priv key independent)
/// ECDSA P384 --> 2a 86 48 ce 3d 02 01
//    func testPemParsing() throws {
//
////        let pem = """
////        -----BEGIN PUBLIC KEY-----
////        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcZ/r0nvJyHUUstIB5BqCUJ1CC
////        Cd1nzle4bEpPQJ/S0Wn7mV2FDAeh+UcbVhZu9n+5zypYNjeZKapPqBLoT8eCK51y
////        Kpzeb8LuEm3P8PK4xN18XBrIF1GprN8IIgSdK9f5SwnemutcURrY+PlWnvj7N5s/
////        03RlJA3/NHVXpPW/VQIDAQAB
////        -----END PUBLIC KEY-----
////        """
//
//        let pem = """
//        -----BEGIN PRIVATE KEY-----
//        MIIG/wIBADANBgkqhkiG9w0BAQEFAASCBukwggblAgEAAoIBgQDp0Whyqa8KmdvK
//        0MsQGJEBzDAEHAZc0C6cr0rkb6Xwo+yB5kjZBRDORk0UXtYGE1pYt4JhUTmMzcWO
//        v2xTIsdbVMQlNtput2U8kIqS1cSTkX5HxOJtCiIzntMzuR/bGPSOexkyFQ8nCUqb
//        ROS7cln/ixprra2KMAKldCApN3ue2jo/JI1gyoS8sekhOASAa0ufMPpC+f70sc75
//        Y53VLnGBNM43iM/2lsK+GI2a13d6rRy86CEM/ygnh/EDlyNDxo+SQmy6GmSv/lmR
//        xgWQE2dIfK504KIxFTOphPAQAr9AsmcNnCQLhbz7YTsBz8WcytHGQ0Z5pnBQJ9AV
//        CX9E6DFHetvs0CNLVw1iEO06QStzHulmNEI/3P8I1TIxViuESJxSu3pSNwG1bSJZ
//        +Qee24vvlz/slBzK5gZWHvdm46v7vl5z7SA+whncEtjrswd8vkJk9fI/YTUbgOC0
//        HWMdc2t/LTZDZ+LUSZ/b2n5trvdJSsOKTjEfuf0wICC08pUUk8MCAwEAAQKCAYEA
//        ywve+DQCneIezHGk5cVvp2/6ApeTruXalJZlIxsRr3eq2uNwP4X2oirKpPX2RjBo
//        NMKnpnsyzuOiu+Pf3hJFrTpfWzHXXm5Eq+OZcwnQO5YNY6XGO4qhSNKT9ka9Mzbo
//        qRKdPrCrB+s5rryVJXKYVSInP3sDSQ2IPsYpZ6GW6Mv56PuFCpjTzElzejV7M0n5
//        0bRmn+MZVMVUR54KYiaCywFgUzmr3yfs1cfcsKqMRywt2J58lRy/chTLZ6LILQMv
//        4V01neVJiRkTmUfIWvc1ENIFM9QJlky9AvA5ASvwTTRz8yOnxoOXE/y4OVyOePjT
//        cz9eumu9N5dPuUIMmsYlXmRNaeGZPD9bIgKY5zOlfhlfZSuOLNH6EHBNr6JAgfwL
//        pdP43sbg2SSNKpBZ0iSMvpyTpbigbe3OyhnFH/TyhcC2Wdf62S9/FRsvjlRPbakW
//        YhKAA2kmJoydcUDO5ccEga8b7NxCdhRiczbiU2cj70pMIuOhDlGAznyxsYbtyxaB
//        AoHBAPy6Cbt6y1AmuId/HYfvms6i8B+/frD1CKyn+sUDkPf81xSHV7RcNrJi1S1c
//        V55I0y96HulsR+GmcAW1DF3qivWkdsd/b4mVkizd/zJm3/Dm8p8QOnNTtdWvYoEB
//        VzfAhBGaR/xflSLxZh2WE8ZHQ3IcRCXV9ZFgJ7PMeTprBJXzl0lTptvrHyo9QK1v
//        obLrL/KuXWS0ql1uSnJr1vtDI5uW8WU4GDENeU5b/CJHpKpjVxlGg+7pmLknxlBl
//        oBnZnQKBwQDs2Ky29qZ69qnPWowKceMJ53Z6uoUeSffRZ7xuBjowpkylasEROjuL
//        nyAihIYB7fd7R74CnRVYLI+O2qXfNKJ8HN+TgcWv8LudkRcnZDSvoyPEJAPyZGfr
//        olRCXD3caqtarlZO7vXSAl09C6HcL2KZ8FuPIEsuO0Aw25nESMg9eVMaIC6s2eSU
//        NUt6xfZw1JC0c+f0LrGuFSjxT2Dr5WKND9ageI6afuauMuosjrrOMl2g0dMcSnVz
//        KrtYa7Wi1N8CgcBFnuJreUplDCWtfgEen40f+5b2yAQYr4fyOFxGxdK73jVJ/HbW
//        wsh2n+9mDZg9jIZQ/+1gFGpA6V7W06dSf/hD70ihcKPDXSbloUpaEikC7jxMQWY4
//        uwjOkwAp1bq3Kxu21a+bAKHO/H1LDTrpVlxoJQ1I9wYtRDXrvBpxU2XyASbeFmNT
//        FhSByFn27Ve4OD3/NrWXtoVwM5/ioX6ZvUcj55McdTWE3ddbFNACiYX9QlyOI/TY
//        bhWafDCPmU9fj6kCgcEAjyQEfi9jPj2FM0RODqH1zS6OdG31tfCOTYicYQJyeKSI
//        /hAezwKaqi9phHMDancfcupQ89Nr6vZDbNrIFLYC3W+1z7hGeabMPNZLYAs3rE60
//        dv4tRHlaNRbORazp1iTBmvRyRRI2js3O++3jzOb2eILDUyT5St+UU/LkY7R5EG4a
//        w1df3idx9gCftXufDWHqcqT6MqFl0QgIzo5izS68+PPxitpRlR3M3Mr4rCU20Rev
//        blphdF+rzAavYyj1hYuRAoHBANmxwbq+QqsJ19SmeGMvfhXj+T7fNZQFh2F0xwb2
//        rMlf4Ejsnx97KpCLUkoydqAs2q0Ws9Nkx2VEVx5KfUD7fWhgbpdnEPnQkfeXv9sD
//        vZTuAoqInN1+vj1TME6EKR/6D4OtQygSNpecv23EuqEvyXWqRVsRt9Qd2B0H4k7h
//        gnjREs10u7zyqBIZH7KYVgyh27WxLr859ap8cKAH6Fb+UOPtZo3sUeeume60aebn
//        4pMwXeXP+LO8NIfRXV8mgrm86g==
//        -----END PRIVATE KEY-----
//        """
//
////        /// EC P256 Public Key
////        let pem = """
////        -----BEGIN PUBLIC KEY-----
////        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb4nB0k8CBVnKCHVHkxuXAkSlZuO5
////        Nsev1rzcRv5QHiJuWUKomFGadQlMSGwoDOHEDdW3ujcA6t0ADteHw6KrZg==
////        -----END PUBLIC KEY-----
////        """
//
////        /// EC P384 Public Key
////        let pem = """
////        -----BEGIN PUBLIC KEY-----
////        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBwY0l7mq7hSBEZRld5ISWfSoFsYN3wwM
////        hdD3cMU95DmYXzbqVHB4dCfsy7bexm4h9c0zs4CyTPzy3DV3vfmv1akQJIQv7l08
////        lx/YXNeGXTN4Gr9r4rwA5GvRl1p6plPL
////        -----END PUBLIC KEY-----
////        """
//
////        /// EC P521 Public Key
////        let pem = """
////        -----BEGIN PUBLIC KEY-----
////        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAp3v1UQWvSyQnkAUEBu+x/7ZrPtNJ
////        SCUk9kMvuZMyGP1idwvspALuJjzrSFFlXObjlOjxucSbWhTYF/o3nc0XzpAA3dxA
////        BYiMqH9vrVePoJMpv+DMdkUiUJ/WqHSOu9bJEi1h4fdqh5HHx4QZJY/iX/59VAi1
////        uSbAhALvbdGFbVpkcOs=
////        -----END PUBLIC KEY-----
////        """
//
//        /// EC P256 Private Key
////        let pem = """
////        -----BEGIN PRIVATE KEY-----
////        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZjQLlzempZx7YF1F
////        +MK1HWZTNgLcC1MAufb/2/YZYk6hRANCAAQwgn0PfkIHiZ/K+3zA//CoDqU2PqDc
////        aA3U5R68jmlZQITvMyBlMJl9Mjh0biIe88dAfRKeUm9FVMD2ErJ/006V
////        -----END PRIVATE KEY-----
////        """
//
//        /// PEMP384PKCS8
////        let pem = """
////        -----BEGIN PRIVATE KEY-----
////        MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDB7ERKhMR+mvz1NQ+oL
////        i6ZJMACOcwbUetWcNnB4Mnx3j4XuhpkkHEW8E1+rXyjZ3UmhZANiAASYH+emlyXM
////        kBSFJl0BiopDVuIIR47M4pLl00YNnuu/Rp5VHeVAHrP67i2Q92u5fk34eOSwQvkO
////        VvktWsgtzAomIam4SHqE9bhvrHy6kW6QzxlERHTL+YkXEX8c6t8VOxk=
////        -----END PRIVATE KEY-----
////        """
//
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//        //print(raw.data)
//
//        //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
//
//        let asn = try Asn1Parser.parse(data: raw.data)
//        //let asn = try Asn1Parser.parse(data: key)
//
//        print("*****")
//        print(asn)
//        print("*****")
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
//            print("Trying to Init RSA from bitString")
//            let sk = try RSAPrivateKey(rawRepresentation: bits)
//            //let sk = try LibP2PCrypto.Keys.secKeyFrom(data: bits, isPrivateKey: true, keyType: .EC(curve: .P256))
//            print(sk)
//        } else if let oct = oct {
//            print("Trying to Init RSA from OctetString")
//            let sk = try RSAPrivateKey(rawRepresentation: oct)
//            //print(ec.bytes.map { "\($0)"}.joined(separator: ",") )
////            var ec2 = ec.bytes
////            ec2.insert(0, at: 0)
////            let sk = try LibP2PCrypto.Keys.secKeyFrom(data: Data(ec2), isPrivateKey: true, keyType: .EC(curve: .P256))
//            print(sk)
//        }
//    }
