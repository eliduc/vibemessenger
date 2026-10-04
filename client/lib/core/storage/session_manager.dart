/// Session Manager - Manages encrypted sessions with contacts
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';

import '../crypto/x3dh.dart';
import '../crypto/double_ratchet.dart';
import '../crypto/aes_gcm.dart';
import '../network/api_client.dart';

/// Encrypted session with a contact
class Session {
  final String recipientId;
  final DoubleRatchetState ratchetState;
  final DateTime createdAt;
  DateTime lastUsed;
  
  Session({
    required this.recipientId,
    required this.ratchetState,
    DateTime? createdAt,
    DateTime? lastUsed,
  }) : createdAt = createdAt ?? DateTime.now(),
       lastUsed = lastUsed ?? DateTime.now();
}

/// Manages encryption sessions
class SessionManager {
  final _logger = Logger();
  final _storage = const FlutterSecureStorage();
  
  // Local key bundle
  LocalKeyBundle? _keyBundle;
  
  // Active sessions: recipientId -> Session
  final Map<String, Session> _sessions = {};
  
  /// Initialize with stored keys or generate new ones
  Future<void> init() async {
    // Try to load existing key bundle
    final storedBundle = await _storage.read(key: 'key_bundle');
    if (storedBundle != null) {
      // TODO: Deserialize stored bundle
      _logger.i('Loaded existing key bundle');
    } else {
      // Generate new bundle
      await generateKeyBundle();
    }
  }
  
  /// Generate new key bundle
  Future<void> generateKeyBundle({int preKeyCount = 100}) async {
    _logger.i('Generating new key bundle...');
    _keyBundle = await LocalKeyBundle.generate(preKeyCount: preKeyCount);
    
    // Upload to server
    final publicBundle = await _keyBundle!.toPublicBundle();
    await apiClient.uploadKeyBundle(publicBundle);
    
    // Store private keys securely
    // TODO: Implement proper serialization
    _logger.i('Key bundle generated and uploaded');
  }
  
  /// Get or create session with recipient
  Future<Session> getOrCreateSession(String recipientId) async {
    // Check for existing session
    if (_sessions.containsKey(recipientId)) {
      final session = _sessions[recipientId]!;
      session.lastUsed = DateTime.now();
      return session;
    }
    
    // Create new session via X3DH
    _logger.i('Creating new session with $recipientId');
    
    // Fetch recipient's key bundle
    final bundleJson = await apiClient.getKeyBundle(recipientId);
    final theirBundle = PreKeyBundle.fromJson(bundleJson);
    
    // Perform X3DH
    final x3dhResult = await X3DH.initiateSession(
      _keyBundle!.identity,
      theirBundle,
    );
    
    // Initialize Double Ratchet
    final theirIdentityKey = base64.decode(theirBundle.identityKey);
    final ratchetState = await DoubleRatchetState.initSender(
      sharedSecret: x3dhResult.sharedSecret,
      theirPublicKey: theirIdentityKey,
    );
    
    final session = Session(
      recipientId: recipientId,
      ratchetState: ratchetState,
    );
    
    _sessions[recipientId] = session;
    await _saveSession(session);
    
    return session;
  }
  
  /// Encrypt message for recipient
  Future<String> encryptMessage(String recipientId, String plaintext) async {
    final session = await getOrCreateSession(recipientId);
    
    // Encrypt with Double Ratchet
    final plaintextBytes = Uint8List.fromList(utf8.encode(plaintext));
    final encrypted = await session.ratchetState.encrypt(plaintextBytes);
    
    // Save updated session state
    await _saveSession(session);
    
    return encrypted.toBase64();
  }
  
  /// Decrypt received message
  Future<String> decryptMessage(
    String senderId,
    String encryptedBase64,
  ) async {
    // Get or create session
    final session = _sessions[senderId];
    if (session == null) {
      throw Exception('No session with sender $senderId');
    }
    
    // Parse encrypted message
    final encrypted = DoubleRatchetMessage.fromBase64(encryptedBase64);
    
    // Decrypt with Double Ratchet
    final plaintextBytes = await session.ratchetState.decrypt(encrypted);
    
    // Save updated session state
    await _saveSession(session);
    
    return utf8.decode(plaintextBytes);
  }
  
  /// Process incoming initial message (X3DH response)
  Future<Session> processIncomingSession({
    required String senderId,
    required Uint8List theirIdentityKey,
    required Uint8List theirEphemeralKey,
    int? usedOneTimePreKeyId,
  }) async {
    _logger.i('Processing incoming session from $senderId');
    
    // Find the one-time prekey that was used
    OneTimePreKey? usedOtp;
    if (usedOneTimePreKeyId != null) {
      usedOtp = _keyBundle!.oneTimePreKeys.firstWhere(
        (otp) => otp.id == usedOneTimePreKeyId,
        orElse: () => throw Exception('One-time prekey not found'),
      );
      // Remove used one-time prekey
      _keyBundle!.oneTimePreKeys.removeWhere((otp) => otp.id == usedOneTimePreKeyId);
    }
    
    // Process X3DH
    final sharedSecret = await X3DH.processSession(
      ourIdentity: _keyBundle!.identity,
      ourSignedPreKey: _keyBundle!.signedPreKey,
      ourOneTimePreKey: usedOtp,
      theirIdentityKey: theirIdentityKey,
      theirEphemeralKey: theirEphemeralKey,
    );
    
    // Initialize Double Ratchet as receiver
    final ratchetState = await DoubleRatchetState.initReceiver(
      sharedSecret: sharedSecret,
      ourKeyPair: _keyBundle!.signedPreKey.keyPair,
    );
    
    final session = Session(
      recipientId: senderId,
      ratchetState: ratchetState,
    );
    
    _sessions[senderId] = session;
    await _saveSession(session);
    
    // Check if we need to replenish one-time prekeys
    await _checkAndReplenishPrekeys();
    
    return session;
  }
  
  /// Save session to secure storage
  Future<void> _saveSession(Session session) async {
    final key = 'session_${session.recipientId}';
    final data = jsonEncode({
      'recipientId': session.recipientId,
      'ratchetState': session.ratchetState.toJson(),
      'createdAt': session.createdAt.toIso8601String(),
      'lastUsed': session.lastUsed.toIso8601String(),
    });
    await _storage.write(key: key, value: data);
  }
  
  /// Load session from secure storage
  Future<Session?> _loadSession(String recipientId) async {
    final key = 'session_$recipientId';
    final data = await _storage.read(key: key);
    if (data == null) return null;
    
    // TODO: Implement proper deserialization
    return null;
  }
  
  /// Check and replenish one-time prekeys if needed
  Future<void> _checkAndReplenishPrekeys() async {
    final status = await apiClient.getKeyBundleStatus();
    final remaining = status['prekeys_remaining'] as int;
    
    if (remaining < 10) {
      _logger.i('Replenishing one-time prekeys...');
      
      // Generate new prekeys
      final newPrekeys = <Map<String, dynamic>>[];
      final startId = _keyBundle!.oneTimePreKeys.isEmpty 
          ? 1 
          : _keyBundle!.oneTimePreKeys.last.id + 1;
      
      for (var i = 0; i < 50; i++) {
        final otp = await OneTimePreKey.generate(startId + i);
        _keyBundle!.oneTimePreKeys.add(otp);
        newPrekeys.add({
          'id': otp.id,
          'key': await otp.getPublicKeyBase64(),
        });
      }
      
      await apiClient.addPreKeys(newPrekeys);
      _logger.i('Added ${newPrekeys.length} new prekeys');
    }
  }
  
  /// Delete session
  Future<void> deleteSession(String recipientId) async {
    _sessions.remove(recipientId);
    await _storage.delete(key: 'session_$recipientId');
  }
  
  /// Get all active session IDs
  List<String> getActiveSessions() => _sessions.keys.toList();
  
  /// Check if session exists
  bool hasSession(String recipientId) => _sessions.containsKey(recipientId);
}

/// Global session manager instance
final sessionManager = SessionManager();
