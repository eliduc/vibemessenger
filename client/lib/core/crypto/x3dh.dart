// VibeMessenger - self-hosted end-to-end encrypted messenger.
// Copyright (C) 2026 eliduc
//
// This program is free software: you may redistribute it and/or modify it under
// the terms of the GNU Affero General Public License, version 3, as published by
// the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL v3 <https://www.gnu.org/licenses/agpl-3.0.html>;
// a verbatim copy ships in the LICENSE file at the root of this repository.
//
// AGPL section 13: if you modify this program and let users interact with it
// over a network, you must offer those users the complete corresponding source
// of your modified version, at no charge, from a network server.

/// X3DH (Extended Triple Diffie-Hellman) Protocol Implementation
/// Initial key agreement for establishing encrypted sessions
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'key_exchange.dart';
import 'aes_gcm.dart';

/// Identity key pair (long-term)
class IdentityKeyPair {
  final X25519KeyPair dhKeyPair;
  final Ed25519Signer signingKeyPair;
  
  IdentityKeyPair._({
    required this.dhKeyPair,
    required this.signingKeyPair,
  });
  
  /// Generate new identity
  static Future<IdentityKeyPair> generate() async {
    return IdentityKeyPair._(
      dhKeyPair: await X25519KeyPair.generate(),
      signingKeyPair: await Ed25519Signer.generate(),
    );
  }
  
  Future<Uint8List> getPublicKey() => dhKeyPair.getPublicKeyBytes();
  Future<String> getPublicKeyBase64() => dhKeyPair.getPublicKeyBase64();
}

/// Signed pre-key (medium-term, rotated periodically)
class SignedPreKey {
  final int id;
  final X25519KeyPair keyPair;
  final Uint8List signature;
  final DateTime createdAt;
  
  SignedPreKey._({
    required this.id,
    required this.keyPair,
    required this.signature,
    required this.createdAt,
  });
  
  /// Generate new signed pre-key
  static Future<SignedPreKey> generate(
    int id,
    IdentityKeyPair identity,
  ) async {
    final keyPair = await X25519KeyPair.generate();
    final publicKey = await keyPair.getPublicKeyBytes();
    final signature = await identity.signingKeyPair.sign(publicKey);
    
    return SignedPreKey._(
      id: id,
      keyPair: keyPair,
      signature: signature,
      createdAt: DateTime.now(),
    );
  }
  
  Future<Uint8List> getPublicKey() => keyPair.getPublicKeyBytes();
  Future<String> getPublicKeyBase64() => keyPair.getPublicKeyBase64();
  String get signatureBase64 => base64.encode(signature);
}

/// One-time pre-key (single use)
class OneTimePreKey {
  final int id;
  final X25519KeyPair keyPair;
  
  OneTimePreKey._({required this.id, required this.keyPair});
  
  static Future<OneTimePreKey> generate(int id) async {
    return OneTimePreKey._(
      id: id,
      keyPair: await X25519KeyPair.generate(),
    );
  }
  
  Future<Uint8List> getPublicKey() => keyPair.getPublicKeyBytes();
  Future<String> getPublicKeyBase64() => keyPair.getPublicKeyBase64();
  
  Map<String, dynamic> toPublicMap() async {
    return {
      'id': id,
      'key': await getPublicKeyBase64(),
    };
  }
}

/// Pre-key bundle (public keys for key exchange)
class PreKeyBundle {
  final String identityKey;
  final int signedPreKeyId;
  final String signedPreKey;
  final String signedPreKeySignature;
  final Map<String, dynamic>? oneTimePreKey; // {id, key}
  
  PreKeyBundle({
    required this.identityKey,
    required this.signedPreKeyId,
    required this.signedPreKey,
    required this.signedPreKeySignature,
    this.oneTimePreKey,
  });
  
  factory PreKeyBundle.fromJson(Map<String, dynamic> json) {
    return PreKeyBundle(
      identityKey: json['identity_key'] as String,
      signedPreKeyId: json['signed_prekey_id'] as int,
      signedPreKey: json['signed_prekey'] as String,
      signedPreKeySignature: json['signed_prekey_signature'] as String,
      oneTimePreKey: json['one_time_prekey'] as Map<String, dynamic>?,
    );
  }
}

/// Result of X3DH key agreement
class X3DHResult {
  final Uint8List sharedSecret;
  final Uint8List ephemeralPublicKey;
  final int? usedOneTimePreKeyId;
  
  X3DHResult({
    required this.sharedSecret,
    required this.ephemeralPublicKey,
    this.usedOneTimePreKeyId,
  });
}

/// X3DH Protocol Implementation
class X3DH {
  /// Perform X3DH as initiator (Alice)
  /// 
  /// Calculates shared secret from:
  /// DH1 = DH(IK_A, SPK_B)
  /// DH2 = DH(EK_A, IK_B)
  /// DH3 = DH(EK_A, SPK_B)
  /// DH4 = DH(EK_A, OPK_B) [if available]
  static Future<X3DHResult> initiateSession(
    IdentityKeyPair ourIdentity,
    PreKeyBundle theirBundle,
  ) async {
    // Generate ephemeral key pair
    final ephemeralKeyPair = await X25519KeyPair.generate();
    
    // Decode their keys
    final theirIdentityKey = base64.decode(theirBundle.identityKey);
    final theirSignedPreKey = base64.decode(theirBundle.signedPreKey);
    
    // DH1: IK_A <-> SPK_B
    final dh1 = await ourIdentity.dhKeyPair.sharedSecret(
      Uint8List.fromList(theirSignedPreKey),
    );
    
    // DH2: EK_A <-> IK_B
    final dh2 = await ephemeralKeyPair.sharedSecret(
      Uint8List.fromList(theirIdentityKey),
    );
    
    // DH3: EK_A <-> SPK_B
    final dh3 = await ephemeralKeyPair.sharedSecret(
      Uint8List.fromList(theirSignedPreKey),
    );
    
    // Combine DH results
    final dhResults = <Uint8List>[dh1, dh2, dh3];
    int? usedOtpId;
    
    // DH4: EK_A <-> OPK_B (if available)
    if (theirBundle.oneTimePreKey != null) {
      final otpKey = base64.decode(theirBundle.oneTimePreKey!['key'] as String);
      final dh4 = await ephemeralKeyPair.sharedSecret(Uint8List.fromList(otpKey));
      dhResults.add(dh4);
      usedOtpId = theirBundle.oneTimePreKey!['id'] as int;
    }
    
    // Concatenate all DH results
    final concatenated = Uint8List.fromList(
      dhResults.expand((x) => x).toList(),
    );
    
    // Derive shared secret using HKDF
    final sharedSecret = await KeyDerivation.deriveKey(
      concatenated,
      info: Uint8List.fromList(utf8.encode('X3DH')),
    );
    
    return X3DHResult(
      sharedSecret: sharedSecret,
      ephemeralPublicKey: await ephemeralKeyPair.getPublicKeyBytes(),
      usedOneTimePreKeyId: usedOtpId,
    );
  }
  
  /// Process X3DH as responder (Bob)
  /// 
  /// Called when receiving initial message with ephemeral key
  static Future<Uint8List> processSession({
    required IdentityKeyPair ourIdentity,
    required SignedPreKey ourSignedPreKey,
    OneTimePreKey? ourOneTimePreKey,
    required Uint8List theirIdentityKey,
    required Uint8List theirEphemeralKey,
  }) async {
    // DH1: SPK_B <-> IK_A
    final dh1 = await ourSignedPreKey.keyPair.sharedSecret(theirIdentityKey);
    
    // DH2: IK_B <-> EK_A
    final dh2 = await ourIdentity.dhKeyPair.sharedSecret(theirEphemeralKey);
    
    // DH3: SPK_B <-> EK_A
    final dh3 = await ourSignedPreKey.keyPair.sharedSecret(theirEphemeralKey);
    
    // Combine DH results
    final dhResults = <Uint8List>[dh1, dh2, dh3];
    
    // DH4: OPK_B <-> EK_A (if one-time key was used)
    if (ourOneTimePreKey != null) {
      final dh4 = await ourOneTimePreKey.keyPair.sharedSecret(theirEphemeralKey);
      dhResults.add(dh4);
    }
    
    // Concatenate all DH results
    final concatenated = Uint8List.fromList(
      dhResults.expand((x) => x).toList(),
    );
    
    // Derive shared secret using HKDF
    final sharedSecret = await KeyDerivation.deriveKey(
      concatenated,
      info: Uint8List.fromList(utf8.encode('X3DH')),
    );
    
    return sharedSecret;
  }
}

/// Key bundle for local storage
class LocalKeyBundle {
  final IdentityKeyPair identity;
  final SignedPreKey signedPreKey;
  final List<OneTimePreKey> oneTimePreKeys;
  
  LocalKeyBundle({
    required this.identity,
    required this.signedPreKey,
    required this.oneTimePreKeys,
  });
  
  /// Generate complete key bundle
  static Future<LocalKeyBundle> generate({
    int preKeyCount = 100,
  }) async {
    final identity = await IdentityKeyPair.generate();
    final signedPreKey = await SignedPreKey.generate(1, identity);
    
    final oneTimePreKeys = <OneTimePreKey>[];
    for (var i = 0; i < preKeyCount; i++) {
      oneTimePreKeys.add(await OneTimePreKey.generate(i + 1));
    }
    
    return LocalKeyBundle(
      identity: identity,
      signedPreKey: signedPreKey,
      oneTimePreKeys: oneTimePreKeys,
    );
  }
  
  /// Get public bundle for server upload
  Future<Map<String, dynamic>> toPublicBundle() async {
    final otpMaps = <Map<String, dynamic>>[];
    for (final otp in oneTimePreKeys) {
      otpMaps.add({
        'id': otp.id,
        'key': await otp.getPublicKeyBase64(),
      });
    }
    
    return {
      'identity_key': await identity.getPublicKeyBase64(),
      'signed_prekey_id': signedPreKey.id,
      'signed_prekey': await signedPreKey.getPublicKeyBase64(),
      'signed_prekey_signature': signedPreKey.signatureBase64,
      'one_time_prekeys': otpMaps,
    };
  }
}
