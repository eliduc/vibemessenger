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

/// Authentication Provider
library;

import 'package:flutter/foundation.dart';
import 'package:logger/logger.dart';

import '../../core/network/api_client.dart';
import '../../core/network/websocket_client.dart';
import '../../core/crypto/x3dh.dart';

/// Authentication state
enum AuthState {
  unknown,
  unauthenticated,
  authenticated,
}

/// Authentication Provider
class AuthProvider extends ChangeNotifier {
  final _logger = Logger();
  
  AuthState _state = AuthState.unknown;
  UserInfo? _user;
  LocalKeyBundle? _keyBundle;
  bool _isLoading = true;
  String? _error;
  
  AuthState get state => _state;
  UserInfo? get user => _user;
  bool get isAuthenticated => _state == AuthState.authenticated;
  bool get isLoading => _isLoading;
  String? get error => _error;
  
  AuthProvider() {
    _init();
  }
  
  Future<void> _init() async {
    try {
      await apiClient.init();
      
      if (apiClient.isAuthenticated) {
        // Try to get user info
        _user = await apiClient.getMe();
        _state = AuthState.authenticated;
        
        // Connect WebSocket
        await wsClient.connect();
      } else {
        _state = AuthState.unauthenticated;
      }
    } catch (e) {
      _logger.e('Init failed: $e');
      _state = AuthState.unauthenticated;
    }
    
    _isLoading = false;
    notifyListeners();
  }
  
  /// Register new account
  Future<bool> register({
    required String username,
    required String password,
    String? displayName,
  }) async {
    _isLoading = true;
    _error = null;
    notifyListeners();
    
    try {
      // Register user
      final (user, _) = await apiClient.register(
        username: username,
        password: password,
        displayName: displayName,
      );
      
      _user = user;
      
      // Generate and upload key bundle
      await _generateAndUploadKeys();
      
      _state = AuthState.authenticated;
      
      // Connect WebSocket
      await wsClient.connect();
      
      _isLoading = false;
      notifyListeners();
      return true;
      
    } catch (e) {
      _logger.e('Registration failed: $e');
      _error = _parseError(e);
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }
  
  /// Login
  Future<bool> login({
    required String username,
    required String password,
  }) async {
    _isLoading = true;
    _error = null;
    notifyListeners();
    
    try {
      final (user, _) = await apiClient.login(
        username: username,
        password: password,
      );
      
      _user = user;
      _state = AuthState.authenticated;
      
      // Check if we need to upload keys
      final status = await apiClient.getKeyBundleStatus();
      if (status['has_bundle'] != true) {
        await _generateAndUploadKeys();
      }
      
      // Connect WebSocket
      await wsClient.connect();
      
      _isLoading = false;
      notifyListeners();
      return true;
      
    } catch (e) {
      _logger.e('Login failed: $e');
      _error = _parseError(e);
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }
  
  /// Logout
  Future<void> logout() async {
    try {
      wsClient.disconnect();
      await apiClient.logout();
    } catch (e) {
      _logger.e('Logout error: $e');
    }
    
    _state = AuthState.unauthenticated;
    _user = null;
    _keyBundle = null;
    notifyListeners();
  }
  
  /// Generate and upload cryptographic keys
  Future<void> _generateAndUploadKeys() async {
    _logger.i('Generating key bundle...');
    
    _keyBundle = await LocalKeyBundle.generate();
    final publicBundle = await _keyBundle!.toPublicBundle();
    
    await apiClient.uploadKeyBundle(publicBundle);
    
    _logger.i('Key bundle uploaded');
    
    // TODO: Store private keys securely
  }
  
  String _parseError(dynamic error) {
    if (error.toString().contains('409')) {
      return 'Username already exists';
    }
    if (error.toString().contains('401')) {
      return 'Invalid username or password';
    }
    return 'An error occurred. Please try again.';
  }
}
