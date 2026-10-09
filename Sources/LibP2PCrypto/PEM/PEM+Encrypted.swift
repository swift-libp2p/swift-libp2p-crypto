//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import CryptoSwift
import Foundation
import SwiftASN1

// MARK: Encrypted PEM

extension LibP2PCrypto.PEM {

    /// Default PBKDF2 iteration count used when encrypting a new PEM.
    ///
    /// Raised from the legacy `2048` to follow modern guidance for PBKDF2. Decoding stays
    /// parameter-driven (the iteration count is read from the PEM), so previously-encrypted
    /// PEMs with any iteration count still import.
    internal static let defaultPBKDF2Iterations = 310_000
    /// Default PBKDF2 salt length in bytes used when encrypting a new PEM (raised from 8).
    internal static let defaultPBKDF2SaltLength = 16
    /// Default IV length in bytes for the default AES-128-CBC cipher.
    internal static let defaultCipherIVLength = 16

    internal struct EncryptedPEM {
        let objectIdentifer: ASN1ObjectIdentifier
        let ciphertext: [UInt8]
        let pbkdfAlgorithm: PBKDFAlgorithm
        let cipherAlgorithm: CipherAlgorithm
    }

    /// Attempts to decode an encrypted Private Key PEM, returning all of the information necessary to decrypt the encrypted PEM
    /// - Parameter encryptedPEM: The raw base64 decoded PEM data
    /// - Returns: An `EncryptedPEM` Struct containing the ciphertext, the pbkdf alogrithm for key derivation, the cipher algorithm for decrypting and the objectIdentifier describing the contents of this PEM data
    ///
    /// To decrypt an encrypted PEM Private Key...
    /// 1) Strip the headers of the PEM and base64 decode the data
    /// 2) Parse the data via ASN1 looking for both the pbkdf and cipher algorithms, their respective parameters (salt, iv and itterations) and the ciphertext (aka octet string))
    /// 3) Derive the encryption key using the appropriate pbkdf alogorithm, found in step 2
    /// 4) Use the encryption key to instantiate the appropriate cipher algorithm, also found in step 2
    /// 5) Decrypt the encrypted ciphertext (the contents of the octetString node)
    /// 6) The decrypted octet string can now be handled like any other Private Key PEM
    ///
    /// ```
    /// SEQUENCE {
    ///   SEQUENCE {
    ///       OBJECT IDENTIFIER                 // PEM's ObjectIdentifier (PBES2)
    ///       SEQUENCE {
    ///           SEQUENCE {
    ///               OBJECT IDENTIFIER         // PBKDF Algorithm
    ///               SEQUENCE {
    ///                   OCTET STRING          // SALT
    ///                   INTEGER               // ITERATIONS
    ///               }
    ///           }
    ///           SEQUENCE {
    ///               OBJECT IDENTIFIER         // Cipher Algorithm (ex: aes-128-cbc)
    ///               OCTET STRING              // Initial Vector (IV)
    ///           }
    ///       }
    ///   }
    ///   OCTET STRING                          // Ciphertext
    /// }
    /// ```
    internal static func decodeEncryptedPEM(_ encryptedPEM: Data) throws -> EncryptedPEM {
        let encryptedPrivateKeyInfo = try EncryptedPrivateKeyInfo(derEncoded: encryptedPEM.byteArray)

        return EncryptedPEM(
            objectIdentifer: encryptedPrivateKeyInfo.encryptionAlgorithm,
            ciphertext: Array(encryptedPrivateKeyInfo.encryptedData.bytes),
            pbkdfAlgorithm: try decodePBKFD(encryptedPrivateKeyInfo.keyDerivationFunction),
            cipherAlgorithm: try decodeCipher(encryptedPrivateKeyInfo.encryptionScheme)
        )
    }

    internal static func encryptPEM(
        _ pem: Data,
        withPassword password: String,
        usingPBKDF pbkdf: PBKDFAlgorithm? = nil,
        andCipher cipher: CipherAlgorithm? = nil
    ) throws -> Data {

        let cipher = try cipher ?? .aes_128_cbc(iv: LibP2PCrypto.randomBytes(length: defaultCipherIVLength))
        let pbkdf =
            try pbkdf
            ?? .pbkdf2(
                salt: LibP2PCrypto.randomBytes(length: defaultPBKDF2SaltLength),
                iterations: defaultPBKDF2Iterations
            )

        // Generate Encryption Key from Password
        let key = try pbkdf.deriveKey(password: password, ofLength: cipher.desiredKeyLength)

        // Encrypt Plaintext
        let ciphertext = try cipher.encrypt(bytes: pem.byteArray, withKey: key)

        // Encode Encrypted PEM (including pbkdf and cipher algos used)
        let encoded = try EncryptedPrivateKeyInfo(
            keyDerivationFunction: pbkdf.encodePBKDF(),
            encryptionScheme: cipher.encodeCipher(),
            encryptedData: ciphertext
        ).serializedDERBytes()

        let base64 = "\n" + encoded.toBase64().split(intoChunksOfLength: 64).joined(separator: "\n") + "\n"

        return Data(
            LibP2PCrypto.PEM.PEMType.encryptedPrivateKey.headerBytes + base64.bytes
                + LibP2PCrypto.PEM.PEMType.encryptedPrivateKey.footerBytes
        )
    }

    internal static func encryptPEMString(
        _ pem: Data,
        withPassword password: String,
        usingPBKDF pbkdf: PBKDFAlgorithm? = nil,
        andCipher cipher: CipherAlgorithm? = nil
    ) throws -> String {
        let data = try LibP2PCrypto.PEM.encryptPEM(pem, withPassword: password, usingPBKDF: pbkdf, andCipher: cipher)
        guard let string = String(data: data, encoding: .utf8) else {
            throw Error.encodingError
        }
        return string
    }
}
