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

/// Session Manager - Manages encrypted sessions with contacts
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';

import 'x3dh.dart';
import 'double_ratchet.dart';
import 'key_exchange.dart';
import '../network/api_client.dart';

/// Encrypted session with a contact
class EncryptedSession {
  final String recipientId;
  final RatchetSession ratchetSession;
  final DateTime createdAt;
  DateTime lastUsed;
  
  EncryptedSession({
    required this.recipientId,
    required this.ratchetSession,
    DateTime? createdAt,
    DateTime? lastUsed,
  }) : createdAt = createdAt ?? DateTime.now(),
       lastUsed = lastUsed ?? DateTime.now();
}

/// Session Manager
class SessionManager {
  static final SessionManager _instance = SessionManager._internal();
  factory SessionManager() => _instance;
  SessionManager._internal();
  
  final _logger = Logger();
  final _storage = const FlutterSecureStorage();
  
  // In-memory session cache
  final Map<String, EncryptedSession> _sessions = {};
  
  // Our identity keys (loaded from secure storage)
  LocalKeyBundle? _keyBundle;
  
  // Pending sessions waiting for first message from recipient
  final Map<String, X3DHResult> _pendingSessions = {};
  
  /// Initialize session manager
  Future<void> init() async {
    await _loadKeyBundle();
    await _loadSessions();
  }
  
  /// Check if we have keys
  bool get hasKeys => _keyBundle != null;
  
  /// Get our identity public key
  Future<String?> getIdentityPublicKey() async {
    return _keyBundle?.identity.getPublicKeyBase64();
  }
  
  /// Generate new key bundle
  Future<Map<String, dynamic>> generateKeys({int preKeyCount = 100}) async {
    _logger.i('Generating new key bundle with $preKeyCount prekeys');
    
    _keyBundle = await LocalKeyBundle.generate(preKeyCount: preKeyCount);
    await _saveKeyBundle();
    
    return _keyBundle!.toPublicBundle();
  }
  
  /// Establish session with contact (we initiate)
  Future<EncryptedSession> establishSession(String recipientId) async {
    if (_keyBundle == null) {
      throw Exception('No key bundle. Call generateKeys first.');
    }
    
    // Check if session already exists
    if (_sessions.containsKey(recipientId)) {
      _logger.i('Reusing existing session with $recipientId');
      return _sessions[recipientId]!;
    }
    
    _logger.i('Establishing new session with $recipientId');
    
    // Fetch recipient's key bundle from server
    final bundleJson = await apiClient.getKeyBundle(recipientId);
    final recipientBundle = PreKeyBundle.fromJson(bundleJson);
    
    // Perform X3DH key agreement
    final x3dhResult = await X3DH.initiateSession(
      _keyBundle!.identity,
      recipientBundle,
    );
    
    // Initialize Double Ratchet session
    final ratchetSession = await RatchetSession.initSender(
      sharedSecret: x3dhResult.sharedSecret,
      recipientPublicKey: base64.decode(recipientBundle.signedPreKey),
    );
    
    // Store pending session info (for initial message header)
    _pendingSessions[recipientId] = x3dhResult;
    
    // Create and cache session
    final session = EncryptedSession(
      recipientId: recipientId,
      ratchetSession: ratchetSession,
    );
    
    _sessions[recipientId] = session;
    await _saveSession(session);
    
    return session;
  }
  
  /// Process incoming session establishment (they initiated)
  Future<EncryptedSession> processIncomingSession({
    required String senderId,
    required Uint8List theirIdentityKey,
    required Uint8List theirEphemeralKey,
    int? usedOneTimePreKeyId,
  }) async {
    if (_keyBundle == null) {
      throw Exception('No key bundle');
    }
    
    _logger.i('Processing incoming session from $senderId');
    
    // Find used one-time prekey if any
    OneTimePreKey? usedOtp;
    if (usedOneTimePreKeyId != null) {
      usedOtp = _keyBundle!.oneTimePreKeys.firstWhere(
        (k) => k.id == usedOneTimePreKeyId,
        orElse: () => throw Exception('One-time prekey not found'),
      );
      
      // Remove used one-time prekey
      _keyBundle!.oneTimePreKeys.removeWhere((k) => k.id == usedOneTimePreKeyId);
      await _saveKeyBundle();
    }
    
    // Perform X3DH as receiver
    final sharedSecret = await X3DH.processSession(
      ourIdentity: _keyBundle!.identity,
      ourSignedPreKey: _keyBundle!.signedPreKey,
      ourOneTimePreKey: usedOtp,
      theirIdentityKey: theirIdentityKey,
      theirEphemeralKey: theirEphemeralKey,
    );
    
    // Initialize Double Ratchet session
    final ratchetSession = await RatchetSession.initReceiver(
      sharedSecret: sharedSecret,
      ourKeyPair: _keyBundle!.signedPreKey.keyPair,
    );
    
    // Create and cache session
    final session = EncryptedSession(
      recipientId: senderId,
      ratchetSession: ratchetSession,
    );
    
    _sessions[senderId] = session;
    await _saveSession(session);
    
    return session;
  }
  
  /// Encrypt message for recipient
  Future<String> encryptMessage(String recipientId, String plaintext) async {
    // Get or establish session
    var session = _sessions[recipientId];
    if (session == null) {
      session = await establishSession(recipientId);
    }
    
    // Encrypt with Double Ratchet
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final encrypted = await session.ratchetSession.encrypt(plaintextBytes);
    
    // Update last used
    session.lastUsed = DateTime.now();
    await _saveSession(session);
    
    // Build message payload
    final payload = <String, dynamic>{
      'message': encrypted.toJson(),
    };
    
    // Include X3DH info in first message
    final pending = _pendingSessions.remove(recipientId);
    if (pending != null) {
      payload['x3dh'] = {
        'identity_key': await _keyBundle!.identity.getPublicKeyBase64(),
        'ephemeral_key': base64.encode(pending.ephemeralPublicKey),
        'used_otp_id': pending.usedOneTimePreKeyId,
      };
    }
    
    return base64.encode(utf8.encode(jsonEncode(payload)));
  }
  
  /// Decrypt message from sender
  Future<String> decryptMessage(String senderId, String encryptedPayload) async {
    final payloadJson = jsonDecode(
      utf8.decode(base64.decode(encryptedPayload))
    ) as Map<String, dynamic>;
    
    // Check for X3DH info (first message)
    var session = _sessions[senderId];
    if (session == null && payloadJson.containsKey('x3dh')) {
      final x3dh = payloadJson['x3dh'] as Map<String, dynamic>;
      session = await processIncomingSession(
        senderId: senderId,
        theirIdentityKey: base64.decode(x3dh['identity_key'] as String),
        theirEphemeralKey: base64.decode(x3dh['ephemeral_key'] as String),
        usedOneTimePreKeyId: x3dh['used_otp_id'] as int?,
      );
    }
    
    if (session == null) {
      throw Exception('No session with $senderId');
    }
    
    // Decrypt with Double Ratchet
    final ratchetMessage = RatchetMessage.fromJson(
      payloadJson['message'] as Map<String, dynamic>,
    );
    
    final plaintext = await session.ratchetSession.decrypt(ratchetMessage);
    
    // Update last used
    session.lastUsed = DateTime.now();
    await _saveSession(session);
    
    return utf8.decode(plaintext);
  }
  
  /// Check if session exists with contact
  bool hasSession(String contactId) => _sessions.containsKey(contactId);
  
  /// Delete session with contact
  Future<void> deleteSession(String contactId) async {
    _sessions.remove(contactId);
    await _storage.delete(key: 'session_$contactId');
  }
  
  /// Get prekey count (for replenishment check)
  int get preKeyCount => _keyBundle?.oneTimePreKeys.length ?? 0;
  
  /// Generate and return additional prekeys
  Future<List<Map<String, dynamic>>> generateAdditionalPreKeys(int count) async {
    if (_keyBundle == null) return [];
    
    final startId = _keyBundle!.oneTimePreKeys.isEmpty 
        ? 1 
        : _keyBundle!.oneTimePreKeys.map((k) => k.id).reduce((a, b) => a > b ? a : b) + 1;
    
    final newKeys = <OneTimePreKey>[];
    final publicKeys = <Map<String, dynamic>>[];
    
    for (var i = 0; i < count; i++) {
      final key = await OneTimePreKey.generate(startId + i);
      newKeys.add(key);
      publicKeys.add({
        'id': key.id,
        'key': await key.getPublicKeyBase64(),
      });
    }
    
    _keyBundle!.oneTimePreKeys.addAll(newKeys);
    await _saveKeyBundle();
    
    return publicKeys;
  }
  
  // ============== Private Storage Methods ==============
  
  Future<void> _loadKeyBundle() async {
    try {
      final data = await _storage.read(key: 'key_bundle');
      if (data != null) {
        // TODO: Properly deserialize key bundle
        // For now, we'll regenerate if not found
        _logger.i('Key bundle loaded from storage');
      }
    } catch (e) {
      _logger.e('Failed to load key bundle: $e');
    }
  }
  
  Future<void> _saveKeyBundle() async {
    if (_keyBundle == null) return;
    
    try {
      // TODO: Properly serialize key bundle including private keys
      // This is a simplified version
      final publicBundle = await _keyBundle!.toPublicBundle();
      await _storage.write(
        key: 'key_bundle',
        value: jsonEncode(publicBundle),
      );
      _logger.i('Key bundle saved to storage');
    } catch (e) {
      _logger.e('Failed to save key bundle: $e');
    }
  }
  
  Future<void> _loadSessions() async {
    try {
      final keys = await _storage.readAll();
      for (final entry in keys.entries) {
        if (entry.key.startsWith('session_')) {
          // TODO: Properly deserialize session
          _logger.d('Found session: ${entry.key}');
        }
      }
    } catch (e) {
      _logger.e('Failed to load sessions: $e');
    }
  }
  
  Future<void> _saveSession(EncryptedSession session) async {
    try {
      final data = {
        'recipientId': session.recipientId,
        'ratchet': session.ratchetSession.toJson(),
        'createdAt': session.createdAt.toIso8601String(),
        'lastUsed': session.lastUsed.toIso8601String(),
      };
      
      await _storage.write(
        key: 'session_${session.recipientId}',
        value: jsonEncode(data),
      );
    } catch (e) {
      _logger.e('Failed to save session: $e');
    }
  }
}

/// Global session manager instance
final sessionManager = SessionManager();
