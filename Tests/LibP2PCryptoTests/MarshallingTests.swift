//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2026 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import Multibase
import SwiftProtobuf
import Testing

@testable import LibP2PCrypto

@Suite("Marshalling Tests")
struct MarshallingTests {

    // https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
    @Test func testLibp2pPeerIDSpecTestVectors_RSA() throws {
        // These are hex string encoding of public and private protobuf keys
        let rsaPrivateKey =
            "080012ae123082092a0201000282020100e1beab071d08200bde24eef00d049449b07770ff9910257b2d7d5dda242ce8f0e2f12e1af4b32d9efd2c090f66b0f29986dbb645dae9880089704a94e5066d594162ae6ee8892e6ec70701db0a6c445c04778eb3de1293aa1a23c3825b85c6620a2bc3f82f9b0c309bc0ab3aeb1873282bebd3da03c33e76c21e9beb172fd44c9e43be32e2c99827033cf8d0f0c606f4579326c930eb4e854395ad941256542c793902185153c474bed109d6ff5141ebf9cd256cf58893a37f83729f97e7cb435ec679d2e33901d27bb35aa0d7e20561da08885ef0abbf8e2fb48d6a5487047a9ecb1ad41fa7ed84f6e3e8ecd5d98b3982d2a901b4454991766da295ab78822add5612a2df83bcee814cf50973e80d7ef38111b1bd87da2ae92438a2c8cbcc70b31ee319939a3b9c761dbc13b5c086d6b64bf7ae7dacc14622375d92a8ff9af7eb962162bbddebf90acb32adb5e4e4029f1c96019949ecfbfeffd7ac1e3fbcc6b6168c34be3d5a2e5999fcbb39bba7adbca78eab09b9bc39f7fa4b93411f4cc175e70c0a083e96bfaefb04a9580b4753c1738a6a760ae1afd851a1a4bdad231cf56e9284d832483df215a46c1c21bdf0c6cfe951c18f1ee4078c79c13d63edb6e14feaeffabc90ad317e4875fe648101b0864097e998f0ca3025ef9638cd2b0caecd3770ab54a1d9c6ca959b0f5dcbc90caeefc4135baca6fd475224269bbe1b02030100010282020100a472ffa858efd8588ce59ee264b957452f3673acdf5631d7bfd5ba0ef59779c231b0bc838a8b14cae367b6d9ef572c03c7883b0a3c652f5c24c316b1ccfd979f13d0cd7da20c7d34d9ec32dfdc81ee7292167e706d705efde5b8f3edfcba41409e642f8897357df5d320d21c43b33600a7ae4e505db957c1afbc189d73f0b5d972d9aaaeeb232ca20eebd5de6fe7f29d01470354413cc9a0af1154b7af7c1029adcd67c74b4798afeb69e09f2cb387305e73a1b5f450202d54f0ef096fe1bde340219a1194d1ac9026e90b366cce0c59b239d10e4888f52ca1780824d39ae01a6b9f4dd6059191a7f12b2a3d8db3c2868cd4e5a5862b8b625a4197d52c6ac77710116ebd3ced81c4d91ad5fdfbed68312ebce7eea45c1833ca3acf7da2052820eacf5c6b07d086dabeb893391c71417fd8a4b1829ae2cf60d1749d0e25da19530d889461c21da3492a8dc6ccac7de83ac1c2185262c7473c8cc42f547cc9864b02a8073b6aa54a037d8c0de3914784e6205e83d97918b944f11b877b12084c0dd1d36592f8a4f8b8da5bb404c3d2c079b22b6ceabfbcb637c0dbe0201f0909d533f8bf308ada47aee641a012a494d31b54c974e58b87f140258258bb82f31692659db7aa07e17a5b2a0832c24e122d3a8babcc9ee74cbb07d3058bb85b15f6f6b2674aba9fd34367be9782d444335fbed31e3c4086c652597c27104938b47fa10282010100e9fdf843c1550070ca711cb8ff28411466198f0e212511c3186623890c0071bf6561219682fe7dbdfd81176eba7c4faba21614a20721e0fcd63768e6d925688ecc90992059ac89256e0524de90bf3d8a052ce6a9f6adafa712f3107a016e20c80255c9e37d8206d1bc327e06e66eb24288da866b55904fd8b59e6b2ab31bc5eab47e597093c63fab7872102d57b4c589c66077f534a61f5f65127459a33c91f6db61fc431b1ae90be92b4149a3255291baf94304e3efb77b1107b5a3bda911359c40a53c347ff9100baf8f36dc5cd991066b5bdc28b39ed644f404afe9213f4d31c9d4e40f3a5f5e3c39bebeb244e84137544e1a1839c1c8aaebf0c78a7fad590282010100f6fa1f1e6b803742d5490b7441152f500970f46feb0b73a6e4baba2aaf3c0e245ed852fc31d86a8e46eb48e90fac409989dfee45238f97e8f1f8e83a136488c1b04b8a7fb695f37b8616307ff8a8d63e8cfa0b4fb9b9167ffaebabf111aa5a4344afbabd002ae8961c38c02da76a9149abdde93eb389eb32595c29ba30d8283a7885218a5a9d33f7f01dbdf85f3aad016c071395491338ec318d39220e1c7bd69d3d6b520a13a30d745c102b827ad9984b0dd6aed73916ffa82a06c1c111e7047dcd2668f988a0570a71474992eecf416e068f029ec323d5d635fd24694fc9bf96973c255d26c772a95bf8b7f876547a5beabf86f06cd21b67994f944e7a5493028201010095b02fd30069e547426a8bea58e8a2816f33688dac6c6f6974415af8402244a22133baedf34ce499d7036f3f19b38eb00897c18949b0c5a25953c71aeeccfc8f6594173157cc854bd98f16dffe8f28ca13b77eb43a2730585c49fc3f608cd811bb54b03b84bddaa8ef910988567f783012266199667a546a18fd88271fbf63a45ae4fd4884706da8befb9117c0a4d73de5172f8640b1091ed8a4aea3ed4641463f5ff6a5e3401ad7d0c92811f87956d1fd5f9a1d15c7f3839a08698d9f35f9d966e5000f7cb2655d7b6c4adcd8a9d950ea5f61bb7c9a33c17508f9baa313eecfee4ae493249ebe05a5d7770bbd3551b2eeb752e3649e0636de08e3d672e66cb90282010100ad93e4c31072b063fc5ab5fe22afacece775c795d0efdf7c704cfc027bde0d626a7646fc905bb5a80117e3ca49059af14e0160089f9190065be9bfecf12c3b2145b211c8e89e42dd91c38e9aa23ca73697063564f6f6aa6590088a738722df056004d18d7bccac62b3bafef6172fc2a4b071ea37f31eff7a076bcab7dd144e51a9da8754219352aef2c73478971539fa41de4759285ea626fa3c72e7085be47d554d915bbb5149cb6ef835351f231043049cd941506a034bf2f8767f3e1e42ead92f91cb3d75549b57ef7d56ac39c2d80d67f6a2b4ca192974bfc5060e2dd171217971002193dba12e7e4133ab201f07500a90495a38610279b13a48d54f0c99028201003e3a1ac0c2b67d54ed5c4bbe04a7db99103659d33a4f9d35809e1f60c282e5988dddc964527f3b05e6cc890eab3dcb571d66debf3a5527704c87264b3954d7265f4e8d2c637dd89b491b9cf23f264801f804b90454d65af0c4c830d1aef76f597ef61b26ca857ecce9cb78d4f6c2218c00d2975d46c2b013fbf59b750c3b92d8d3ed9e6d1fd0ef1ec091a5c286a3fe2dead292f40f380065731e2079ebb9f2a7ef2c415ecbb488da98f3a12609ca1b6ec8c734032c8bd513292ff842c375d4acd1b02dfb206b24cd815f8e2f9d4af8e7dea0370b19c1b23cc531d78b40e06e1119ee2e08f6f31c6e2e8444c568d13c5d451a291ae0c9f1d4f27d23b3a00d60ad"
        let expectedRSAPublicKey =
            "080012a60430820222300d06092a864886f70d01010105000382020f003082020a0282020100e1beab071d08200bde24eef00d049449b07770ff9910257b2d7d5dda242ce8f0e2f12e1af4b32d9efd2c090f66b0f29986dbb645dae9880089704a94e5066d594162ae6ee8892e6ec70701db0a6c445c04778eb3de1293aa1a23c3825b85c6620a2bc3f82f9b0c309bc0ab3aeb1873282bebd3da03c33e76c21e9beb172fd44c9e43be32e2c99827033cf8d0f0c606f4579326c930eb4e854395ad941256542c793902185153c474bed109d6ff5141ebf9cd256cf58893a37f83729f97e7cb435ec679d2e33901d27bb35aa0d7e20561da08885ef0abbf8e2fb48d6a5487047a9ecb1ad41fa7ed84f6e3e8ecd5d98b3982d2a901b4454991766da295ab78822add5612a2df83bcee814cf50973e80d7ef38111b1bd87da2ae92438a2c8cbcc70b31ee319939a3b9c761dbc13b5c086d6b64bf7ae7dacc14622375d92a8ff9af7eb962162bbddebf90acb32adb5e4e4029f1c96019949ecfbfeffd7ac1e3fbcc6b6168c34be3d5a2e5999fcbb39bba7adbca78eab09b9bc39f7fa4b93411f4cc175e70c0a083e96bfaefb04a9580b4753c1738a6a760ae1afd851a1a4bdad231cf56e9284d832483df215a46c1c21bdf0c6cfe951c18f1ee4078c79c13d63edb6e14feaeffabc90ad317e4875fe648101b0864097e998f0ca3025ef9638cd2b0caecd3770ab54a1d9c6ca959b0f5dcbc90caeefc4135baca6fd475224269bbe1b0203010001"

        let pbPrivateKey = try ProtoPrivateKey(serializedBytes: Data(hex: rsaPrivateKey))
        #expect(pbPrivateKey.type == .rsa)

        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: rsaPrivateKey))
        #expect(kp.keyType == .rsa)
        #expect(try kp.marshalPublicKey().asString(base: .base16) == expectedRSAPublicKey)
    }

    // https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
    @Test func testLibp2pPeerIDSpecTestVectors_ED25519() throws {
        // These are hex string encoding of public and private protobuf keys
        let ed25519PrivateKey =
            "080112407e0830617c4a7de83925dfb2694556b12936c477a0e1feb2e148ec9da60fee7d1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"
        let expectedED25519PublicKey = "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"

        let pbPrivateKey = try ProtoPrivateKey(serializedBytes: Data(hex: ed25519PrivateKey))
        #expect(pbPrivateKey.type == .ed25519)

        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: ed25519PrivateKey))
        #expect(kp.keyType == .ed25519)
        #expect(try kp.marshalPublicKey().asString(base: .base16) == expectedED25519PublicKey)
    }

    // https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
    @Test func testLibp2pPeerIDSpecTestVectors_Secp256k1() throws {
        // These are hex string encoding of public and private protobuf keys
        let secp256k1PrivateKey = "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"
        let expectedSecp256k1PublicKey = "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"

        let pbPrivateKey = try ProtoPrivateKey(serializedBytes: Data(hex: secp256k1PrivateKey))
        #expect(pbPrivateKey.type == .secp256K1)

        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: secp256k1PrivateKey))
        #expect(kp.keyType == .secp256k1)
        let marshaledPubKey = try kp.marshalPublicKey()
        print("Marshalled PubKey: \(marshaledPubKey.asString(base: .base16))")
        print("Marshalled PubKey Size: \(marshaledPubKey.count)")
        #expect(try kp.marshalPublicKey().asString(base: .base16) == expectedSecp256k1PublicKey)
    }

    // Manual
    @Test func testImportFromMarshalledPublicKey_Manual() throws {
        let marshaledData: [UInt8] = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_2048, as: .base64Pad)
        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: Data(marshaledData))

        /// We've imported a Public Key!  🥳
        print(pubKey)

        /// Now lets try and re-marshal the imported key and make sure it matches the original data...
        let marshaledKey = try pubKey.marshalPublicKey()

        let base64MarshaledPublicKey = marshaledKey.asString(base: .base64Pad)

        print(base64MarshaledPublicKey)
        #expect(base64MarshaledPublicKey == MarshaledData.PUBLIC_RSA_KEY_2048)
    }

    @Test func testCreateKeyPairFromMarshalledPublicKey_2048() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_2048,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey == nil)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_2048)
    }

    @Test func testCreateKeyPairFromMarshalledPublicKey_3072() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_3072,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey == nil)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_3072)
    }

    @Test func testCreateKeyPairFromMarshalledPublicKey_4096() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_4096,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey == nil)
        /// Ensures that the public key was instantiated properly and then we can marshal it back into the original marshaled data
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_4096)
    }

    @Test func testImportFromMarshalledPrivateKey_Manual() throws {
        let marshaledData: [UInt8] = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_2048, as: .base64Pad)
        let privKey = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(marshaledData))

        print(privKey)
    }

    @Test func testImportFromMarshalledPrivateKey_2048() throws {
        //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_2048,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey != nil)
        //#expect(keyPair.publicKey != nil)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)

        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        #expect(try keyPair.privateKey?.marshal().asString(base: .base64Pad) == MarshaledData.PRIVATE_RSA_KEY_2048)

        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_2048)
    }

    @Test func testImportFromMarshalledPrivateKey_3072() throws {
        //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_3072,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey != nil)
        //#expect(keyPair.publicKey != nil)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)

        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        #expect(try keyPair.privateKey?.marshal().asString(base: .base64Pad) == MarshaledData.PRIVATE_RSA_KEY_3072)

        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_3072)
    }

    @Test func testImportFromMarshalledPrivateKey_4096() throws {
        //RawPrivateKey(marshaledKey: MarshaledData.PRIVATE_KEY, base: .base64Pad)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(
            marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_4096,
            base: .base64Pad
        )

        print(keyPair)

        #expect(keyPair.privateKey != nil)
        //#expect(keyPair.publicKey != nil)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)

        /// Ensure that when we marshal the private key, we end up with that same data we imported.
        #expect(try keyPair.privateKey?.marshal().asString(base: .base64Pad) == MarshaledData.PRIVATE_RSA_KEY_4096)

        /// Ensures that the public key derived from the private key is correct and the marshaled version matches that of the fixture.
        #expect(try keyPair.publicKey.marshal().asString(base: .base64Pad) == MarshaledData.PUBLIC_RSA_KEY_4096)
    }
}
