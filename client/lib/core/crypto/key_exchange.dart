/// X25519 Key Exchange Implementation
/// Used for generating key pairs and performing Diffie-Hellman key exchange
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Represents a key pair for X25519 operations
class X25519KeyPair {
  final SimpleKeyPair keyPair;
  
  X25519KeyPair._(this.keyPair);
  
  /// Generate a new random key pair
  static Future<X25519KeyPair> generate() async {
    final algorithm = X25519();
    final keyPair = await algorithm.newKeyPair();
    return X25519KeyPair._(keyPair);
  }
  
  /// Restore key pair from stored private key
  static Future<X25519KeyPair> fromPrivateKey(Uint8List privateKeyBytes) async {
    final algorithm = X25519();
    final privateKey = SimpleKeyPairData(
      privateKeyBytes,
      publicKey: SimplePublicKey(
        Uint8List(32), // Will be derived
        type: KeyPairType.x25519,
      ),
      type: KeyPairType.x25519,
    );
    
    // Derive public key from private key
    final keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
    return X25519KeyPair._(keyPair);
  }
  
  /// Get public key bytes
  Future<Uint8List> getPublicKeyBytes() async {
    final publicKey = await keyPair.extractPublicKey();
    return Uint8List.fromList(publicKey.bytes);
  }
  
  /// Get private key bytes (for secure storage)
  Future<Uint8List> getPrivateKeyBytes() async {
    final data = await keyPair.extract();
    return Uint8List.fromList(data.bytes);
  }
  
  /// Get public key as base64
  Future<String> getPublicKeyBase64() async {
    final bytes = await getPublicKeyBytes();
    return base64.encode(bytes);
  }
  
  /// Perform DH key exchange with another public key
  Future<Uint8List> sharedSecret(Uint8List otherPublicKeyBytes) async {
    final algorithm = X25519();
    final otherPublicKey = SimplePublicKey(
      otherPublicKeyBytes,
      type: KeyPairType.x25519,
    );
    
    final sharedSecret = await algorithm.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: otherPublicKey,
    );
    
    return Uint8List.fromList(await sharedSecret.extractBytes());
  }
  
  /// Perform DH with public key from base64
  Future<Uint8List> sharedSecretFromBase64(String otherPublicKeyBase64) async {
    final otherPublicKeyBytes = base64.decode(otherPublicKeyBase64);
    return sharedSecret(Uint8List.fromList(otherPublicKeyBytes));
  }
}

/// Ed25519 for signing (used to sign pre-keys)
class Ed25519Signer {
  final SimpleKeyPair keyPair;
  
  Ed25519Signer._(this.keyPair);
  
  /// Generate new signing key pair
  static Future<Ed25519Signer> generate() async {
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPair();
    return Ed25519Signer._(keyPair);
  }
  
  /// Restore from stored seed
  static Future<Ed25519Signer> fromSeed(Uint8List seed) async {
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    return Ed25519Signer._(keyPair);
  }
  
  /// Sign data
  Future<Uint8List> sign(Uint8List data) async {
    final algorithm = Ed25519();
    final signature = await algorithm.sign(data, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  }
  
  /// Get public key bytes
  Future<Uint8List> getPublicKeyBytes() async {
    final publicKey = await keyPair.extractPublicKey();
    return Uint8List.fromList(publicKey.bytes);
  }
  
  /// Verify signature
  static Future<bool> verify(
    Uint8List data,
    Uint8List signatureBytes,
    Uint8List publicKeyBytes,
  ) async {
    final algorithm = Ed25519();
    final publicKey = SimplePublicKey(
      publicKeyBytes,
      type: KeyPairType.ed25519,
    );
    
    final signature = Signature(
      signatureBytes,
      publicKey: publicKey,
    );
    
    return algorithm.verify(data, signature: signature);
  }
}
