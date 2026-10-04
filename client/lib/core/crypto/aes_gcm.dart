/// AES-256-GCM Encryption Implementation
/// Used for symmetric encryption of messages
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Encrypted message container
class EncryptedData {
  final Uint8List ciphertext;
  final Uint8List nonce;
  final Uint8List mac; // Authentication tag
  
  EncryptedData({
    required this.ciphertext,
    required this.nonce,
    required this.mac,
  });
  
  /// Serialize to JSON-compatible map
  Map<String, String> toMap() => {
    'ciphertext': base64.encode(ciphertext),
    'nonce': base64.encode(nonce),
    'mac': base64.encode(mac),
  };
  
  /// Deserialize from map
  factory EncryptedData.fromMap(Map<String, dynamic> map) {
    return EncryptedData(
      ciphertext: base64.decode(map['ciphertext'] as String),
      nonce: base64.decode(map['nonce'] as String),
      mac: base64.decode(map['mac'] as String),
    );
  }
  
  /// Serialize to base64 string
  String toBase64() => base64.encode(toBytes());
  
  /// Convert to bytes: nonce (12) + mac (16) + ciphertext
  Uint8List toBytes() {
    final result = Uint8List(nonce.length + mac.length + ciphertext.length);
    var offset = 0;
    result.setRange(offset, offset + nonce.length, nonce);
    offset += nonce.length;
    result.setRange(offset, offset + mac.length, mac);
    offset += mac.length;
    result.setRange(offset, offset + ciphertext.length, ciphertext);
    return result;
  }
  
  /// Parse from bytes
  factory EncryptedData.fromBytes(Uint8List bytes) {
    const nonceLength = 12;
    const macLength = 16;
    
    return EncryptedData(
      nonce: bytes.sublist(0, nonceLength),
      mac: bytes.sublist(nonceLength, nonceLength + macLength),
      ciphertext: bytes.sublist(nonceLength + macLength),
    );
  }
  
  /// Parse from base64
  factory EncryptedData.fromBase64(String base64String) {
    return EncryptedData.fromBytes(base64.decode(base64String));
  }
}

/// AES-256-GCM cipher
class AesGcmCipher {
  static final _algorithm = AesGcm.with256bits();
  
  /// Encrypt plaintext with key
  static Future<EncryptedData> encrypt(
    Uint8List plaintext,
    Uint8List key, {
    Uint8List? associatedData,
  }) async {
    // Generate random nonce (12 bytes for GCM)
    final nonce = _algorithm.newNonce();
    
    // Create secret key
    final secretKey = SecretKey(key);
    
    // Encrypt
    final secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: nonce,
      aad: associatedData ?? Uint8List(0),
    );
    
    return EncryptedData(
      ciphertext: Uint8List.fromList(secretBox.cipherText),
      nonce: Uint8List.fromList(secretBox.nonce),
      mac: Uint8List.fromList(secretBox.mac.bytes),
    );
  }
  
  /// Decrypt ciphertext with key
  static Future<Uint8List> decrypt(
    EncryptedData encrypted,
    Uint8List key, {
    Uint8List? associatedData,
  }) async {
    // Create secret key
    final secretKey = SecretKey(key);
    
    // Create SecretBox
    final secretBox = SecretBox(
      encrypted.ciphertext,
      nonce: encrypted.nonce,
      mac: Mac(encrypted.mac),
    );
    
    // Decrypt
    final plaintext = await _algorithm.decrypt(
      secretBox,
      secretKey: secretKey,
      aad: associatedData ?? Uint8List(0),
    );
    
    return Uint8List.fromList(plaintext);
  }
  
  /// Encrypt string message
  static Future<String> encryptString(
    String message,
    Uint8List key, {
    Uint8List? associatedData,
  }) async {
    final plaintext = utf8.encode(message);
    final encrypted = await encrypt(
      Uint8List.fromList(plaintext),
      key,
      associatedData: associatedData,
    );
    return encrypted.toBase64();
  }
  
  /// Decrypt to string message
  static Future<String> decryptString(
    String encryptedBase64,
    Uint8List key, {
    Uint8List? associatedData,
  }) async {
    final encrypted = EncryptedData.fromBase64(encryptedBase64);
    final plaintext = await decrypt(
      encrypted,
      key,
      associatedData: associatedData,
    );
    return utf8.decode(plaintext);
  }
}

/// Key Derivation Function (HKDF)
class KeyDerivation {
  static final _hkdf = Hkdf(
    hmac: Hmac.sha256(),
    outputLength: 32,
  );
  
  /// Derive key from input key material
  static Future<Uint8List> deriveKey(
    Uint8List inputKeyMaterial, {
    Uint8List? salt,
    Uint8List? info,
  }) async {
    final secretKey = SecretKey(inputKeyMaterial);
    
    final derivedKey = await _hkdf.deriveKey(
      secretKey: secretKey,
      nonce: salt ?? Uint8List(32),
      info: info ?? Uint8List(0),
    );
    
    return Uint8List.fromList(await derivedKey.extractBytes());
  }
  
  /// Derive multiple keys from shared secret
  static Future<List<Uint8List>> deriveKeys(
    Uint8List sharedSecret,
    int count, {
    Uint8List? salt,
    String? context,
  }) async {
    final keys = <Uint8List>[];
    
    for (var i = 0; i < count; i++) {
      final info = utf8.encode('${context ?? 'key'}_$i');
      final key = await deriveKey(
        sharedSecret,
        salt: salt,
        info: Uint8List.fromList(info),
      );
      keys.add(key);
    }
    
    return keys;
  }
}
