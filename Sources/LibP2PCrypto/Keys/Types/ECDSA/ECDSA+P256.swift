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

import Crypto

// MARK: - P-256 (secp256r1 / prime256v1)
//
// The libp2p CommonPublicKey / CommonPrivateKey / DERCodable implementations are shared by every curve,
// see `ECDSAPublicKeyBacking` and `ECDSAPrivateKeyBacking` in ECDSA.swift

extension P256.Signing.ECDSASignature: ECDSASignatureBacking {}

extension P256.Signing.PublicKey: ECDSAPublicKeyBacking {
    public static var curve: LibP2PCrypto.Keys.EllipticCurve { .p256 }
}

extension P256.Signing.PublicKey: @retroactive Equatable {}

/// - Note: Private keys intentionally aren't `Equatable`, compare their derived public keys instead
extension P256.Signing.PrivateKey: ECDSAPrivateKeyBacking {}
