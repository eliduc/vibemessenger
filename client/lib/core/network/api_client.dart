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

/// API Client for server communication
library;

import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';

import '../config/app_config.dart';

/// Authentication tokens
class AuthTokens {
  final String accessToken;
  final String refreshToken;
  final int expiresIn;
  
  AuthTokens({
    required this.accessToken,
    required this.refreshToken,
    required this.expiresIn,
  });
  
  factory AuthTokens.fromJson(Map<String, dynamic> json) {
    return AuthTokens(
      accessToken: json['access_token'] as String,
      refreshToken: json['refresh_token'] as String,
      expiresIn: json['expires_in'] as int,
    );
  }
}

/// User info
class UserInfo {
  final String id;
  final String username;
  final String? displayName;
  final bool isVerified;
  final DateTime? lastSeen;
  
  UserInfo({
    required this.id,
    required this.username,
    this.displayName,
    required this.isVerified,
    this.lastSeen,
  });
  
  factory UserInfo.fromJson(Map<String, dynamic> json) {
    return UserInfo(
      id: json['id'] as String,
      username: json['username'] as String,
      displayName: json['display_name'] as String?,
      isVerified: json['is_verified'] as bool,
      lastSeen: json['last_seen'] != null 
          ? DateTime.parse(json['last_seen'] as String)
          : null,
    );
  }
}

/// API Client
class ApiClient {
  late final Dio _dio;
  final _storage = const FlutterSecureStorage();
  final _logger = Logger();
  
  String? _accessToken;
  String? _refreshToken;
  
  ApiClient() {
    _dio = Dio(BaseOptions(
      baseUrl: AppConfig.apiUrl,
      connectTimeout: AppConfig.connectionTimeout,
      receiveTimeout: AppConfig.receiveTimeout,
      headers: {
        'Content-Type': 'application/json',
      },
    ));
    
    // Add interceptor for auth and token refresh
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: _onRequest,
      onError: _onError,
    ));
  }
  
  /// Initialize with stored tokens
  Future<void> init() async {
    _accessToken = await _storage.read(key: 'access_token');
    _refreshToken = await _storage.read(key: 'refresh_token');
  }
  
  /// Check if authenticated
  bool get isAuthenticated => _accessToken != null;
  
  /// Get current access token
  String? get accessToken => _accessToken;
  
  // ============== Auth Endpoints ==============
  
  /// Register new user
  Future<(UserInfo, AuthTokens)> register({
    required String username,
    required String password,
    String? displayName,
    String? deviceId,
  }) async {
    final response = await _dio.post('/auth/register', data: {
      'username': username,
      'password': password,
      if (displayName != null) 'display_name': displayName,
      if (deviceId != null) 'device_id': deviceId,
    });
    
    final user = UserInfo.fromJson(response.data['user']);
    final tokens = AuthTokens.fromJson(response.data['tokens']);
    
    await _saveTokens(tokens);
    
    return (user, tokens);
  }
  
  /// Login
  Future<(UserInfo, AuthTokens)> login({
    required String username,
    required String password,
    String? deviceId,
  }) async {
    final response = await _dio.post('/auth/login', data: {
      'username': username,
      'password': password,
      if (deviceId != null) 'device_id': deviceId,
    });
    
    final user = UserInfo.fromJson(response.data['user']);
    final tokens = AuthTokens.fromJson(response.data['tokens']);
    
    await _saveTokens(tokens);
    
    return (user, tokens);
  }
  
  /// Logout
  Future<void> logout({bool allDevices = false}) async {
    try {
      await _dio.post('/auth/logout', queryParameters: {
        'all_devices': allDevices,
      }, data: {
        if (_refreshToken != null) 'refresh_token': _refreshToken,
      });
    } catch (e) {
      _logger.w('Logout failed: $e');
    }
    
    await _clearTokens();
  }
  
  /// Get current user
  Future<UserInfo> getMe() async {
    final response = await _dio.get('/auth/me');
    return UserInfo.fromJson(response.data);
  }
  
  // ============== Keys Endpoints ==============
  
  /// Upload key bundle
  Future<void> uploadKeyBundle(Map<String, dynamic> bundle) async {
    await _dio.post('/keys/bundle', data: bundle);
  }
  
  /// Get user's key bundle
  Future<Map<String, dynamic>> getKeyBundle(String userId) async {
    final response = await _dio.get('/keys/bundle/$userId');
    return response.data;
  }
  
  /// Add more one-time prekeys
  Future<void> addPreKeys(List<Map<String, dynamic>> prekeys) async {
    await _dio.post('/keys/bundle/prekeys', data: prekeys);
  }
  
  /// Get key bundle status
  Future<Map<String, dynamic>> getKeyBundleStatus() async {
    final response = await _dio.get('/keys/bundle/status/me');
    return response.data;
  }
  
  // ============== Messages Endpoints ==============
  
  /// Send message
  Future<Map<String, dynamic>> sendMessage({
    required String recipientId,
    required String encryptedPayload,
    String messageType = 'text',
    String? clientMessageId,
    String? fileId,
  }) async {
    final response = await _dio.post('/messages/send', data: {
      'recipient_id': recipientId,
      'encrypted_payload': encryptedPayload,
      'message_type': messageType,
      if (clientMessageId != null) 'client_message_id': clientMessageId,
      if (fileId != null) 'file_id': fileId,
    });
    return response.data;
  }
  
  /// Get pending messages
  Future<List<Map<String, dynamic>>> getPendingMessages({int limit = 100}) async {
    final response = await _dio.get('/messages/pending', queryParameters: {
      'limit': limit,
    });
    return List<Map<String, dynamic>>.from(response.data);
  }
  
  /// Acknowledge messages
  Future<void> ackMessages(List<String> messageIds, String status) async {
    await _dio.post('/messages/ack', data: {
      'message_ids': messageIds,
      'status': status,
    });
  }
  
  /// Get message history with contact
  Future<List<Map<String, dynamic>>> getMessageHistory(
    String contactId, {
    String? beforeId,
    String? afterId,
    int limit = 50,
  }) async {
    final response = await _dio.get('/messages/history/$contactId', queryParameters: {
      if (beforeId != null) 'before_id': beforeId,
      if (afterId != null) 'after_id': afterId,
      'limit': limit,
    });
    return List<Map<String, dynamic>>.from(response.data);
  }
  
  // ============== Private Methods ==============
  
  Future<void> _saveTokens(AuthTokens tokens) async {
    _accessToken = tokens.accessToken;
    _refreshToken = tokens.refreshToken;
    
    await _storage.write(key: 'access_token', value: tokens.accessToken);
    await _storage.write(key: 'refresh_token', value: tokens.refreshToken);
  }
  
  Future<void> _clearTokens() async {
    _accessToken = null;
    _refreshToken = null;
    
    await _storage.delete(key: 'access_token');
    await _storage.delete(key: 'refresh_token');
  }
  
  void _onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (_accessToken != null) {
      options.headers['Authorization'] = 'Bearer $_accessToken';
    }
    handler.next(options);
  }
  
  Future<void> _onError(DioException error, ErrorInterceptorHandler handler) async {
    if (error.response?.statusCode == 401 && _refreshToken != null) {
      // Try to refresh token
      try {
        final response = await _dio.post('/auth/refresh', data: {
          'refresh_token': _refreshToken,
        });
        
        final tokens = AuthTokens.fromJson(response.data);
        await _saveTokens(tokens);
        
        // Retry original request
        final opts = error.requestOptions;
        opts.headers['Authorization'] = 'Bearer ${tokens.accessToken}';
        
        final retryResponse = await _dio.fetch(opts);
        return handler.resolve(retryResponse);
      } catch (e) {
        // Refresh failed, logout
        await _clearTokens();
      }
    }
    
    handler.next(error);
  }
}

/// Global API client instance
final apiClient = ApiClient();
