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

/// Chat Provider - Manages chats and messages
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:logger/logger.dart';
import 'package:uuid/uuid.dart';

import '../../core/network/api_client.dart';
import '../../core/network/websocket_client.dart';
import '../../core/crypto/session_manager.dart';
import '../../shared/models/message.dart';

/// Chat Provider
class ChatProvider extends ChangeNotifier {
  final _logger = Logger();
  final _uuid = const Uuid();
  
  // Current user ID
  String? _currentUserId;
  
  // Chat list
  final List<Chat> _chats = [];
  List<Chat> get chats => List.unmodifiable(_chats);
  
  // Messages by chat ID
  final Map<String, List<Message>> _messages = {};
  
  // Currently active chat
  String? _activeChatId;
  String? get activeChatId => _activeChatId;
  
  // Loading states
  bool _isLoading = false;
  bool get isLoading => _isLoading;
  
  // WebSocket subscription
  StreamSubscription? _wsSubscription;
  
  // Online users
  final Set<String> _onlineUsers = {};
  
  /// Initialize provider
  Future<void> init(String userId) async {
    _currentUserId = userId;
    
    // Initialize session manager
    await sessionManager.init();
    
    // Subscribe to WebSocket messages
    _wsSubscription = wsClient.messages.listen(_handleWebSocketMessage);
    
    // Load pending messages
    await _loadPendingMessages();
  }
  
  /// Get messages for a chat
  List<Message> getMessages(String chatId) {
    return _messages[chatId] ?? [];
  }
  
  /// Set active chat
  void setActiveChat(String? chatId) {
    _activeChatId = chatId;
    
    // Mark messages as read
    if (chatId != null) {
      _markChatAsRead(chatId);
    }
    
    notifyListeners();
  }
  
  /// Start new chat with user
  Future<Chat> startChat(Contact contact) async {
    // Check if chat already exists
    final existingIndex = _chats.indexWhere((c) => c.recipientId == contact.id);
    if (existingIndex >= 0) {
      return _chats[existingIndex];
    }
    
    // Create new chat
    final chat = Chat(
      id: contact.id,
      recipientId: contact.id,
      recipientUsername: contact.username,
      recipientDisplayName: contact.displayName,
      isOnline: _onlineUsers.contains(contact.id),
    );
    
    _chats.insert(0, chat);
    _messages[chat.id] = [];
    
    notifyListeners();
    
    return chat;
  }
  
  /// Send text message
  Future<bool> sendMessage(String chatId, String text) async {
    if (_currentUserId == null) return false;
    
    final messageId = _uuid.v4();
    final timestamp = DateTime.now();
    
    // Create local message
    final message = Message(
      id: messageId,
      chatId: chatId,
      senderId: _currentUserId!,
      recipientId: chatId,
      type: MessageType.text,
      content: text,
      status: MessageStatus.sending,
      timestamp: timestamp,
      isOutgoing: true,
    );
    
    // Add to messages
    _messages.putIfAbsent(chatId, () => []);
    _messages[chatId]!.add(message);
    
    // Update chat
    _updateChatLastMessage(chatId, message);
    
    notifyListeners();
    
    try {
      // Encrypt message
      final encryptedPayload = await sessionManager.encryptMessage(
        chatId,
        text,
      );
      
      // Send via API
      final response = await apiClient.sendMessage(
        recipientId: chatId,
        encryptedPayload: encryptedPayload,
        clientMessageId: messageId,
      );
      
      // Update message status
      _updateMessageStatus(chatId, messageId, MessageStatus.sent);
      
      _logger.i('Message sent: $messageId');
      return true;
      
    } catch (e) {
      _logger.e('Failed to send message: $e');
      _updateMessageStatus(chatId, messageId, MessageStatus.failed);
      return false;
    }
  }
  
  /// Resend failed message
  Future<bool> resendMessage(String chatId, String messageId) async {
    final messages = _messages[chatId];
    if (messages == null) return false;
    
    final index = messages.indexWhere((m) => m.id == messageId);
    if (index < 0) return false;
    
    final message = messages[index];
    if (message.status != MessageStatus.failed) return false;
    
    // Update status to sending
    _updateMessageStatus(chatId, messageId, MessageStatus.sending);
    
    try {
      // Encrypt and send
      final encryptedPayload = await sessionManager.encryptMessage(
        chatId,
        message.content,
      );
      
      await apiClient.sendMessage(
        recipientId: chatId,
        encryptedPayload: encryptedPayload,
        clientMessageId: messageId,
      );
      
      _updateMessageStatus(chatId, messageId, MessageStatus.sent);
      return true;
      
    } catch (e) {
      _logger.e('Failed to resend message: $e');
      _updateMessageStatus(chatId, messageId, MessageStatus.failed);
      return false;
    }
  }
  
  /// Load message history for chat
  Future<void> loadMessageHistory(String chatId, {String? beforeId}) async {
    _isLoading = true;
    notifyListeners();
    
    try {
      final serverMessages = await apiClient.getMessageHistory(
        chatId,
        beforeId: beforeId,
      );
      
      for (final msgJson in serverMessages) {
        await _processServerMessage(msgJson);
      }
      
    } catch (e) {
      _logger.e('Failed to load history: $e');
    }
    
    _isLoading = false;
    notifyListeners();
  }
  
  /// Send typing indicator
  void sendTypingIndicator(String chatId) {
    wsClient.sendTyping(chatId);
  }
  
  // ============== Private Methods ==============
  
  void _handleWebSocketMessage(WSMessage message) {
    switch (message.type) {
      case WSMessageType.newMessage:
        _handleNewMessage(message.payload);
        break;
      case WSMessageType.messageStatus:
        _handleMessageStatus(message.payload);
        break;
      case WSMessageType.userOnline:
        _handleUserOnline(message.payload['user_id'] as String);
        break;
      case WSMessageType.userOffline:
        _handleUserOffline(message.payload['user_id'] as String);
        break;
      case WSMessageType.userTyping:
        _handleUserTyping(message.payload['user_id'] as String);
        break;
      default:
        break;
    }
  }
  
  Future<void> _handleNewMessage(Map<String, dynamic> payload) async {
    try {
      await _processServerMessage(payload);
      
      // Acknowledge message
      final messageId = payload['id'] as String;
      await apiClient.ackMessages([messageId], 'delivered');
      
    } catch (e) {
      _logger.e('Failed to handle new message: $e');
    }
  }
  
  Future<void> _processServerMessage(Map<String, dynamic> msgJson) async {
    final senderId = msgJson['sender_id'] as String;
    final isOutgoing = senderId == _currentUserId;
    final chatId = isOutgoing 
        ? msgJson['recipient_id'] as String 
        : senderId;
    
    // Decrypt message
    String content;
    try {
      final encryptedPayload = msgJson['encrypted_payload'] as String;
      content = await sessionManager.decryptMessage(senderId, encryptedPayload);
    } catch (e) {
      _logger.e('Failed to decrypt message: $e');
      content = '[Unable to decrypt message]';
    }
    
    // Create message object
    final message = Message(
      id: msgJson['id'] as String,
      chatId: chatId,
      senderId: senderId,
      recipientId: msgJson['recipient_id'] as String,
      type: MessageType.text,
      content: content,
      status: _parseMessageStatus(msgJson['status'] as String?),
      timestamp: DateTime.parse(msgJson['created_at'] as String),
      isOutgoing: isOutgoing,
    );
    
    // Add to messages if not duplicate
    _messages.putIfAbsent(chatId, () => []);
    final exists = _messages[chatId]!.any((m) => m.id == message.id);
    if (!exists) {
      _messages[chatId]!.add(message);
      _messages[chatId]!.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    }
    
    // Update or create chat
    _ensureChat(chatId, senderId);
    _updateChatLastMessage(chatId, message);
    
    // Increment unread if not active chat
    if (!isOutgoing && chatId != _activeChatId) {
      final chatIndex = _chats.indexWhere((c) => c.id == chatId);
      if (chatIndex >= 0) {
        _chats[chatIndex] = _chats[chatIndex].copyWith(
          unreadCount: _chats[chatIndex].unreadCount + 1,
        );
      }
    }
    
    notifyListeners();
  }
  
  void _handleMessageStatus(Map<String, dynamic> payload) {
    final messageId = payload['message_id'] as String;
    final status = _parseMessageStatus(payload['status'] as String?);
    
    // Find message in all chats
    for (final chatId in _messages.keys) {
      final messages = _messages[chatId]!;
      final index = messages.indexWhere((m) => m.id == messageId);
      if (index >= 0) {
        _updateMessageStatus(chatId, messageId, status);
        break;
      }
    }
  }
  
  void _handleUserOnline(String userId) {
    _onlineUsers.add(userId);
    _updateUserOnlineStatus(userId, true);
  }
  
  void _handleUserOffline(String userId) {
    _onlineUsers.remove(userId);
    _updateUserOnlineStatus(userId, false);
  }
  
  void _handleUserTyping(String userId) {
    // TODO: Show typing indicator in UI
    _logger.d('User $userId is typing');
  }
  
  void _updateMessageStatus(String chatId, String messageId, MessageStatus status) {
    final messages = _messages[chatId];
    if (messages == null) return;
    
    final index = messages.indexWhere((m) => m.id == messageId);
    if (index >= 0) {
      messages[index] = messages[index].copyWith(status: status);
      notifyListeners();
    }
  }
  
  void _updateChatLastMessage(String chatId, Message message) {
    final chatIndex = _chats.indexWhere((c) => c.id == chatId);
    if (chatIndex >= 0) {
      _chats[chatIndex] = _chats[chatIndex].copyWith(
        lastMessage: message,
        lastActivity: message.timestamp,
      );
      
      // Move to top
      final chat = _chats.removeAt(chatIndex);
      _chats.insert(0, chat);
    }
  }
  
  void _ensureChat(String chatId, String senderId) {
    final exists = _chats.any((c) => c.id == chatId);
    if (!exists) {
      // Create placeholder chat - will be updated with full info
      final chat = Chat(
        id: chatId,
        recipientId: chatId,
        recipientUsername: senderId,  // Will be replaced with actual username
        isOnline: _onlineUsers.contains(chatId),
      );
      _chats.insert(0, chat);
    }
  }
  
  void _updateUserOnlineStatus(String userId, bool isOnline) {
    final index = _chats.indexWhere((c) => c.recipientId == userId);
    if (index >= 0) {
      _chats[index] = _chats[index].copyWith(isOnline: isOnline);
      notifyListeners();
    }
  }
  
  Future<void> _markChatAsRead(String chatId) async {
    final messages = _messages[chatId];
    if (messages == null) return;
    
    // Get unread message IDs
    final unreadIds = messages
        .where((m) => !m.isOutgoing && m.status != MessageStatus.read)
        .map((m) => m.id)
        .toList();
    
    if (unreadIds.isNotEmpty) {
      try {
        await apiClient.ackMessages(unreadIds, 'read');
        
        // Update local messages
        for (final id in unreadIds) {
          _updateMessageStatus(chatId, id, MessageStatus.read);
        }
        
        // Clear unread count
        final chatIndex = _chats.indexWhere((c) => c.id == chatId);
        if (chatIndex >= 0) {
          _chats[chatIndex] = _chats[chatIndex].copyWith(unreadCount: 0);
        }
        
        notifyListeners();
      } catch (e) {
        _logger.e('Failed to mark as read: $e');
      }
    }
  }
  
  Future<void> _loadPendingMessages() async {
    try {
      final pending = await apiClient.getPendingMessages();
      
      for (final msgJson in pending) {
        await _processServerMessage(msgJson);
      }
      
      // Acknowledge all
      if (pending.isNotEmpty) {
        final ids = pending.map((m) => m['id'] as String).toList();
        await apiClient.ackMessages(ids, 'delivered');
      }
    } catch (e) {
      _logger.e('Failed to load pending messages: $e');
    }
  }
  
  MessageStatus _parseMessageStatus(String? status) {
    switch (status) {
      case 'pending': return MessageStatus.sent;
      case 'delivered': return MessageStatus.delivered;
      case 'read': return MessageStatus.read;
      default: return MessageStatus.sent;
    }
  }
  
  @override
  void dispose() {
    _wsSubscription?.cancel();
    super.dispose();
  }
}
