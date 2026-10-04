// VibeMessenger - self-hosted end-to-end encrypted messenger.
// Copyright (C) 2026 RLG
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

/// Double Ratchet Algorithm Implementation
/// Provides forward secrecy and break-in recovery for message encryption
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'key_exchange.dart';
import 'aes_gcm.dart';

/// Message header containing ratchet state
class MessageHeader {
  final Uint8List dhPublicKey;  // Current ratchet public key
  final int previousChainLength;  // Messages in previous sending chain
  final int messageNumber;  // Message number in current chain
  
  MessageHeader({
    required this.dhPublicKey,
    required this.previousChainLength,
    required this.messageNumber,
  });
  
  /// Serialize to bytes
  Uint8List toBytes() {
    final buffer = BytesBuilder();
    buffer.add(dhPublicKey);  // 32 bytes
    buffer.addByte(previousChainLength & 0xFF);
    buffer.addByte((previousChainLength >> 8) & 0xFF);
    buffer.addByte(messageNumber & 0xFF);
    buffer.addByte((messageNumber >> 8) & 0xFF);
    return buffer.toBytes();
  }
  
  /// Deserialize from bytes
  factory MessageHeader.fromBytes(Uint8List bytes) {
    return MessageHeader(
      dhPublicKey: bytes.sublist(0, 32),
      previousChainLength: bytes[32] | (bytes[33] << 8),
      messageNumber: bytes[34] | (bytes[35] << 8),
    );
  }
  
  /// Serialize to base64
  String toBase64() => base64.encode(toBytes());
  
  /// Deserialize from base64
  factory MessageHeader.fromBase64(String b64) {
    return MessageHeader.fromBytes(base64.decode(b64));
  }
  
  Map<String, dynamic> toJson() => {
    'dh': base64.encode(dhPublicKey),
    'pn': previousChainLength,
    'n': messageNumber,
  };
  
  factory MessageHeader.fromJson(Map<String, dynamic> json) {
    return MessageHeader(
      dhPublicKey: base64.decode(json['dh'] as String),
      previousChainLength: json['pn'] as int,
      messageNumber: json['n'] as int,
    );
  }
}

/// Encrypted message with header
class RatchetMessage {
  final MessageHeader header;
  final Uint8List ciphertext;
  final Uint8List nonce;
  final Uint8List mac;
  
  RatchetMessage({
    required this.header,
    required this.ciphertext,
    required this.nonce,
    required this.mac,
  });
  
  /// Serialize to JSON-compatible map
  Map<String, dynamic> toJson() => {
    'header': header.toJson(),
    'ciphertext': base64.encode(ciphertext),
    'nonce': base64.encode(nonce),
    'mac': base64.encode(mac),
  };
  
  /// Deserialize from JSON
  factory RatchetMessage.fromJson(Map<String, dynamic> json) {
    return RatchetMessage(
      header: MessageHeader.fromJson(json['header'] as Map<String, dynamic>),
      ciphertext: base64.decode(json['ciphertext'] as String),
      nonce: base64.decode(json['nonce'] as String),
      mac: base64.decode(json['mac'] as String),
    );
  }
  
  /// Serialize to base64 string
  String toBase64() => base64.encode(utf8.encode(jsonEncode(toJson())));
  
  /// Deserialize from base64 string
  factory RatchetMessage.fromBase64(String b64) {
    final json = jsonDecode(utf8.decode(base64.decode(b64)));
    return RatchetMessage.fromJson(json as Map<String, dynamic>);
  }
}

/// Chain key for symmetric ratchet
class ChainKey {
  final Uint8List key;
  int index;
  
  ChainKey({required this.key, this.index = 0});
  
  /// Derive next chain key and message key
  Future<(ChainKey, Uint8List)> ratchet() async {
    // Message key = HMAC(chain_key, 0x01)
    final messageKey = await _hmac(key, Uint8List.fromList([0x01]));
    
    // Next chain key = HMAC(chain_key, 0x02)
    final nextChainKey = await _hmac(key, Uint8List.fromList([0x02]));
    
    return (
      ChainKey(key: nextChainKey, index: index + 1),
      messageKey,
    );
  }
  
  static Future<Uint8List> _hmac(Uint8List key, Uint8List data) async {
    final algorithm = Hmac.sha256();
    final secretKey = SecretKey(key);
    final mac = await algorithm.calculateMac(data, secretKey: secretKey);
    return Uint8List.fromList(mac.bytes);
  }
  
  Map<String, dynamic> toJson() => {
    'key': base64.encode(key),
    'index': index,
  };
  
  factory ChainKey.fromJson(Map<String, dynamic> json) {
    return ChainKey(
      key: base64.decode(json['key'] as String),
      index: json['index'] as int,
    );
  }
}

/// Skipped message key (for out-of-order messages)
class SkippedKey {
  final Uint8List dhPublicKey;
  final int messageNumber;
  final Uint8List messageKey;
  final DateTime createdAt;
  
  SkippedKey({
    required this.dhPublicKey,
    required this.messageNumber,
    required this.messageKey,
    DateTime? createdAt,
  }) : createdAt = createdAt ?? DateTime.now();
  
  String get id => '${base64.encode(dhPublicKey)}:$messageNumber';
  
  Map<String, dynamic> toJson() => {
    'dh': base64.encode(dhPublicKey),
    'n': messageNumber,
    'mk': base64.encode(messageKey),
    'ts': createdAt.toIso8601String(),
  };
  
  factory SkippedKey.fromJson(Map<String, dynamic> json) {
    return SkippedKey(
      dhPublicKey: base64.decode(json['dh'] as String),
      messageNumber: json['n'] as int,
      messageKey: base64.decode(json['mk'] as String),
      createdAt: DateTime.parse(json['ts'] as String),
    );
  }
}

/// Double Ratchet session state
class RatchetSession {
  // DH Ratchet keys
  X25519KeyPair? dhSendingKey;
  Uint8List? dhReceivingKey;
  
  // Root key
  Uint8List rootKey;
  
  // Chain keys
  ChainKey? sendingChainKey;
  ChainKey? receivingChainKey;
  
  // Message counters
  int sendingMessageNumber = 0;
  int receivingMessageNumber = 0;
  int previousSendingChainLength = 0;
  
  // Skipped message keys (for out-of-order delivery)
  final Map<String, SkippedKey> skippedKeys = {};
  static const maxSkip = 1000;
  static const maxSkippedKeyAge = Duration(days: 7);
  
  RatchetSession({required this.rootKey});
  
  /// Initialize session as sender (Alice)
  static Future<RatchetSession> initSender({
    required Uint8List sharedSecret,
    required Uint8List recipientPublicKey,
  }) async {
    final session = RatchetSession(rootKey: sharedSecret);
    
    // Generate initial sending ratchet key
    session.dhSendingKey = await X25519KeyPair.generate();
    session.dhReceivingKey = recipientPublicKey;
    
    // Perform initial DH ratchet
    await session._dhRatchetSend();
    
    return session;
  }
  
  /// Initialize session as receiver (Bob)
  static Future<RatchetSession> initReceiver({
    required Uint8List sharedSecret,
    required X25519KeyPair ourKeyPair,
  }) async {
    final session = RatchetSession(rootKey: sharedSecret);
    session.dhSendingKey = ourKeyPair;
    return session;
  }
  
  /// Encrypt a message
  Future<RatchetMessage> encrypt(Uint8List plaintext) async {
    // Get message key from sending chain
    final (newChainKey, messageKey) = await sendingChainKey!.ratchet();
    sendingChainKey = newChainKey;
    
    // Create header
    final header = MessageHeader(
      dhPublicKey: await dhSendingKey!.getPublicKeyBytes(),
      previousChainLength: previousSendingChainLength,
      messageNumber: sendingMessageNumber,
    );
    
    sendingMessageNumber++;
    
    // Encrypt with associated data (header)
    final encrypted = await AesGcmCipher.encrypt(
      plaintext,
      messageKey,
      associatedData: header.toBytes(),
    );
    
    return RatchetMessage(
      header: header,
      ciphertext: encrypted.ciphertext,
      nonce: encrypted.nonce,
      mac: encrypted.mac,
    );
  }
  
  /// Decrypt a message
  Future<Uint8List> decrypt(RatchetMessage message) async {
    // Try skipped keys first
    final skippedId = '${base64.encode(message.header.dhPublicKey)}:${message.header.messageNumber}';
    if (skippedKeys.containsKey(skippedId)) {
      final skipped = skippedKeys.remove(skippedId)!;
      return _decryptWithKey(message, skipped.messageKey);
    }
    
    // Check if we need to perform DH ratchet
    if (dhReceivingKey == null || 
        !_bytesEqual(message.header.dhPublicKey, dhReceivingKey!)) {
      await _skipMessages(message.header.previousChainLength);
      await _dhRatchetReceive(message.header.dhPublicKey);
    }
    
    // Skip messages if needed
    await _skipMessages(message.header.messageNumber);
    
    // Get message key
    final (newChainKey, messageKey) = await receivingChainKey!.ratchet();
    receivingChainKey = newChainKey;
    receivingMessageNumber++;
    
    return _decryptWithKey(message, messageKey);
  }
  
  Future<Uint8List> _decryptWithKey(RatchetMessage message, Uint8List key) async {
    final encrypted = EncryptedData(
      ciphertext: message.ciphertext,
      nonce: message.nonce,
      mac: message.mac,
    );
    
    return AesGcmCipher.decrypt(
      encrypted,
      key,
      associatedData: message.header.toBytes(),
    );
  }
  
  /// Perform DH ratchet step (sending)
  Future<void> _dhRatchetSend() async {
    // DH with receiving key
    final dhOutput = await dhSendingKey!.sharedSecret(dhReceivingKey!);
    
    // KDF to get new root key and sending chain key
    final (newRootKey, chainKey) = await _kdfRk(rootKey, dhOutput);
    rootKey = newRootKey;
    sendingChainKey = ChainKey(key: chainKey);
    sendingMessageNumber = 0;
  }
  
  /// Perform DH ratchet step (receiving)
  Future<void> _dhRatchetReceive(Uint8List theirPublicKey) async {
    previousSendingChainLength = sendingMessageNumber;
    sendingMessageNumber = 0;
    receivingMessageNumber = 0;
    
    dhReceivingKey = theirPublicKey;
    
    // DH with their new public key
    final dhOutput = await dhSendingKey!.sharedSecret(theirPublicKey);
    
    // KDF to get new root key and receiving chain key
    final (newRootKey, chainKey) = await _kdfRk(rootKey, dhOutput);
    rootKey = newRootKey;
    receivingChainKey = ChainKey(key: chainKey);
    
    // Generate new DH key pair for next send
    dhSendingKey = await X25519KeyPair.generate();
    
    // DH ratchet for sending
    await _dhRatchetSend();
  }
  
  /// Skip and store message keys for out-of-order messages
  Future<void> _skipMessages(int until) async {
    if (receivingChainKey == null) return;
    
    if (until - receivingMessageNumber > maxSkip) {
      throw Exception('Too many skipped messages');
    }
    
    while (receivingMessageNumber < until) {
      final (newChainKey, messageKey) = await receivingChainKey!.ratchet();
      receivingChainKey = newChainKey;
      
      final skipped = SkippedKey(
        dhPublicKey: dhReceivingKey!,
        messageNumber: receivingMessageNumber,
        messageKey: messageKey,
      );
      
      skippedKeys[skipped.id] = skipped;
      receivingMessageNumber++;
    }
    
    // Clean old skipped keys
    _cleanSkippedKeys();
  }
  
  void _cleanSkippedKeys() {
    final now = DateTime.now();
    skippedKeys.removeWhere((_, v) => 
      now.difference(v.createdAt) > maxSkippedKeyAge
    );
  }
  
  /// KDF for root key ratchet
  static Future<(Uint8List, Uint8List)> _kdfRk(
    Uint8List rootKey, 
    Uint8List dhOutput,
  ) async {
    // Concatenate inputs
    final input = Uint8List.fromList([...rootKey, ...dhOutput]);
    
    // Derive 64 bytes
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
    final derived = await hkdf.deriveKey(
      secretKey: SecretKey(input),
      nonce: Uint8List(32),
      info: utf8.encode('DoubleRatchet'),
    );
    
    final bytes = await derived.extractBytes();
    
    return (
      Uint8List.fromList(bytes.sublist(0, 32)),  // New root key
      Uint8List.fromList(bytes.sublist(32, 64)), // Chain key
    );
  }
  
  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
  
  /// Serialize session state for storage
  Map<String, dynamic> toJson() {
    return {
      'rootKey': base64.encode(rootKey),
      'dhReceivingKey': dhReceivingKey != null ? base64.encode(dhReceivingKey!) : null,
      'sendingChainKey': sendingChainKey?.toJson(),
      'receivingChainKey': receivingChainKey?.toJson(),
      'sendingMessageNumber': sendingMessageNumber,
      'receivingMessageNumber': receivingMessageNumber,
      'previousSendingChainLength': previousSendingChainLength,
      'skippedKeys': skippedKeys.map((k, v) => MapEntry(k, v.toJson())),
    };
  }
  
  /// Deserialize session state
  factory RatchetSession.fromJson(
    Map<String, dynamic> json,
    X25519KeyPair? dhSendingKey,
  ) {
    final session = RatchetSession(
      rootKey: base64.decode(json['rootKey'] as String),
    );
    
    session.dhSendingKey = dhSendingKey;
    session.dhReceivingKey = json['dhReceivingKey'] != null 
        ? base64.decode(json['dhReceivingKey'] as String)
        : null;
    session.sendingChainKey = json['sendingChainKey'] != null
        ? ChainKey.fromJson(json['sendingChainKey'] as Map<String, dynamic>)
        : null;
    session.receivingChainKey = json['receivingChainKey'] != null
        ? ChainKey.fromJson(json['receivingChainKey'] as Map<String, dynamic>)
        : null;
    session.sendingMessageNumber = json['sendingMessageNumber'] as int;
    session.receivingMessageNumber = json['receivingMessageNumber'] as int;
    session.previousSendingChainLength = json['previousSendingChainLength'] as int;
    
    final skipped = json['skippedKeys'] as Map<String, dynamic>?;
    if (skipped != null) {
      for (final entry in skipped.entries) {
        session.skippedKeys[entry.key] = SkippedKey.fromJson(
          entry.value as Map<String, dynamic>,
        );
      }
    }
    
    return session;
  }
}
