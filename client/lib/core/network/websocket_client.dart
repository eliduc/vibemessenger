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

/// WebSocket Client for real-time messaging
library;

import 'dart:async';
import 'dart:convert';

import 'package:logger/logger.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../config/app_config.dart';
import 'api_client.dart';

/// WebSocket message types
enum WSMessageType {
  // Client -> Server
  auth,
  ping,
  sendMessage,
  ackMessage,
  typing,
  
  // Server -> Client
  pong,
  newMessage,
  messageSent,
  messageStatus,
  userOnline,
  userOffline,
  userTyping,
  error,
  
  // Calls
  callOffer,
  callAnswer,
  callIce,
  callHangup,
}

/// WebSocket message
class WSMessage {
  final WSMessageType type;
  final Map<String, dynamic> payload;
  final String? requestId;
  
  WSMessage({
    required this.type,
    this.payload = const {},
    this.requestId,
  });
  
  factory WSMessage.fromJson(Map<String, dynamic> json) {
    return WSMessage(
      type: WSMessageType.values.firstWhere(
        (t) => t.name == _snakeToCamel(json['type'] as String),
        orElse: () => WSMessageType.error,
      ),
      payload: json['payload'] as Map<String, dynamic>? ?? {},
      requestId: json['request_id'] as String?,
    );
  }
  
  Map<String, dynamic> toJson() => {
    'type': _camelToSnake(type.name),
    'payload': payload,
    if (requestId != null) 'request_id': requestId,
  };
  
  static String _snakeToCamel(String s) {
    return s.replaceAllMapped(
      RegExp(r'_([a-z])'),
      (m) => m.group(1)!.toUpperCase(),
    );
  }
  
  static String _camelToSnake(String s) {
    return s.replaceAllMapped(
      RegExp(r'[A-Z]'),
      (m) => '_${m.group(0)!.toLowerCase()}',
    );
  }
}

/// WebSocket connection state
enum WSConnectionState {
  disconnected,
  connecting,
  connected,
  reconnecting,
}

/// WebSocket Client
class WebSocketClient {
  final _logger = Logger();
  
  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  Timer? _pingTimer;
  Timer? _reconnectTimer;
  
  WSConnectionState _state = WSConnectionState.disconnected;
  int _reconnectAttempts = 0;
  static const _maxReconnectAttempts = 10;
  
  // Callbacks
  final _messageController = StreamController<WSMessage>.broadcast();
  final _stateController = StreamController<WSConnectionState>.broadcast();
  
  /// Message stream
  Stream<WSMessage> get messages => _messageController.stream;
  
  /// Connection state stream
  Stream<WSConnectionState> get stateChanges => _stateController.stream;
  
  /// Current state
  WSConnectionState get state => _state;
  
  /// Connect to WebSocket server
  Future<void> connect() async {
    if (_state == WSConnectionState.connected || 
        _state == WSConnectionState.connecting) {
      return;
    }
    
    final token = apiClient.accessToken;
    if (token == null) {
      _logger.e('Cannot connect: not authenticated');
      return;
    }
    
    _setState(WSConnectionState.connecting);
    
    try {
      final uri = Uri.parse('${AppConfig.wsUrl}?token=$token');
      _channel = WebSocketChannel.connect(uri);
      
      await _channel!.ready;
      
      _setState(WSConnectionState.connected);
      _reconnectAttempts = 0;
      
      // Start listening
      _subscription = _channel!.stream.listen(
        _onMessage,
        onError: _onError,
        onDone: _onDone,
      );
      
      // Start ping timer
      _startPingTimer();
      
      _logger.i('WebSocket connected');
      
    } catch (e) {
      _logger.e('WebSocket connection failed: $e');
      _setState(WSConnectionState.disconnected);
      _scheduleReconnect();
    }
  }
  
  /// Disconnect
  void disconnect() {
    _reconnectTimer?.cancel();
    _pingTimer?.cancel();
    _subscription?.cancel();
    _channel?.sink.close();
    _channel = null;
    _setState(WSConnectionState.disconnected);
    _logger.i('WebSocket disconnected');
  }
  
  /// Send message
  void send(WSMessage message) {
    if (_state != WSConnectionState.connected) {
      _logger.w('Cannot send: not connected');
      return;
    }
    
    try {
      _channel!.sink.add(jsonEncode(message.toJson()));
    } catch (e) {
      _logger.e('Send failed: $e');
    }
  }
  
  /// Send and wait for response
  Future<WSMessage?> sendAndWait(
    WSMessage message, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final requestId = DateTime.now().millisecondsSinceEpoch.toString();
    message = WSMessage(
      type: message.type,
      payload: message.payload,
      requestId: requestId,
    );
    
    final completer = Completer<WSMessage?>();
    
    // Listen for response
    final sub = messages.where((m) => m.requestId == requestId).listen((m) {
      if (!completer.isCompleted) {
        completer.complete(m);
      }
    });
    
    // Send message
    send(message);
    
    // Wait with timeout
    try {
      final result = await completer.future.timeout(timeout);
      return result;
    } on TimeoutException {
      return null;
    } finally {
      await sub.cancel();
    }
  }
  
  /// Send typing indicator
  void sendTyping(String contactId) {
    send(WSMessage(
      type: WSMessageType.typing,
      payload: {'contact_id': contactId},
    ));
  }
  
  // ============== Private Methods ==============
  
  void _setState(WSConnectionState state) {
    _state = state;
    _stateController.add(state);
  }
  
  void _onMessage(dynamic data) {
    try {
      final json = jsonDecode(data as String) as Map<String, dynamic>;
      final message = WSMessage.fromJson(json);
      
      // Handle pong internally
      if (message.type == WSMessageType.pong) {
        return;
      }
      
      _messageController.add(message);
      
    } catch (e) {
      _logger.e('Failed to parse message: $e');
    }
  }
  
  void _onError(dynamic error) {
    _logger.e('WebSocket error: $error');
    _handleDisconnect();
  }
  
  void _onDone() {
    _logger.i('WebSocket closed');
    _handleDisconnect();
  }
  
  void _handleDisconnect() {
    _pingTimer?.cancel();
    _subscription?.cancel();
    _channel = null;
    
    if (_state != WSConnectionState.disconnected) {
      _setState(WSConnectionState.reconnecting);
      _scheduleReconnect();
    }
  }
  
  void _scheduleReconnect() {
    if (_reconnectAttempts >= _maxReconnectAttempts) {
      _logger.e('Max reconnect attempts reached');
      _setState(WSConnectionState.disconnected);
      return;
    }
    
    _reconnectAttempts++;
    
    // Exponential backoff
    final delay = Duration(
      milliseconds: AppConfig.wsReconnectDelay.inMilliseconds * 
        (1 << (_reconnectAttempts - 1)).clamp(1, 32),
    );
    
    _logger.i('Reconnecting in ${delay.inSeconds}s (attempt $_reconnectAttempts)');
    
    _reconnectTimer = Timer(delay, connect);
  }
  
  void _startPingTimer() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(
      const Duration(seconds: 25),
      (_) => _sendPing(),
    );
  }
  
  void _sendPing() {
    send(WSMessage(type: WSMessageType.ping));
  }
  
  /// Dispose resources
  void dispose() {
    disconnect();
    _messageController.close();
    _stateController.close();
  }
}

/// Global WebSocket client instance
final wsClient = WebSocketClient();
