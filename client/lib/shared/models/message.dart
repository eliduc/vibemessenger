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

/// Message Models
library;

import 'package:equatable/equatable.dart';

/// Message status
enum MessageStatus {
  sending,
  sent,
  delivered,
  read,
  failed,
}

/// Message type
enum MessageType {
  text,
  image,
  file,
  voice,
}

/// Chat message
class Message extends Equatable {
  final String id;
  final String chatId;
  final String senderId;
  final String recipientId;
  final MessageType type;
  final String content;
  final MessageStatus status;
  final DateTime timestamp;
  final String? fileId;
  final String? fileName;
  final int? fileSize;
  final bool isOutgoing;
  
  const Message({
    required this.id,
    required this.chatId,
    required this.senderId,
    required this.recipientId,
    required this.type,
    required this.content,
    required this.status,
    required this.timestamp,
    this.fileId,
    this.fileName,
    this.fileSize,
    required this.isOutgoing,
  });
  
  @override
  List<Object?> get props => [
    id, chatId, senderId, recipientId, type, 
    content, status, timestamp, fileId, isOutgoing,
  ];
  
  Message copyWith({
    String? id,
    String? chatId,
    String? senderId,
    String? recipientId,
    MessageType? type,
    String? content,
    MessageStatus? status,
    DateTime? timestamp,
    String? fileId,
    String? fileName,
    int? fileSize,
    bool? isOutgoing,
  }) {
    return Message(
      id: id ?? this.id,
      chatId: chatId ?? this.chatId,
      senderId: senderId ?? this.senderId,
      recipientId: recipientId ?? this.recipientId,
      type: type ?? this.type,
      content: content ?? this.content,
      status: status ?? this.status,
      timestamp: timestamp ?? this.timestamp,
      fileId: fileId ?? this.fileId,
      fileName: fileName ?? this.fileName,
      fileSize: fileSize ?? this.fileSize,
      isOutgoing: isOutgoing ?? this.isOutgoing,
    );
  }
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'chat_id': chatId,
    'sender_id': senderId,
    'recipient_id': recipientId,
    'type': type.name,
    'content': content,
    'status': status.name,
    'timestamp': timestamp.toIso8601String(),
    'file_id': fileId,
    'file_name': fileName,
    'file_size': fileSize,
    'is_outgoing': isOutgoing,
  };
  
  factory Message.fromJson(Map<String, dynamic> json, {required bool isOutgoing}) {
    return Message(
      id: json['id'] as String,
      chatId: json['chat_id'] as String? ?? 
              (isOutgoing ? json['recipient_id'] : json['sender_id']) as String,
      senderId: json['sender_id'] as String,
      recipientId: json['recipient_id'] as String,
      type: MessageType.values.firstWhere(
        (t) => t.name == (json['message_type'] ?? json['type'] ?? 'text'),
        orElse: () => MessageType.text,
      ),
      content: json['content'] as String? ?? '',
      status: MessageStatus.values.firstWhere(
        (s) => s.name == (json['status'] ?? 'sent'),
        orElse: () => MessageStatus.sent,
      ),
      timestamp: json['timestamp'] != null
          ? DateTime.parse(json['timestamp'] as String)
          : (json['created_at'] != null 
              ? DateTime.parse(json['created_at'] as String)
              : DateTime.now()),
      fileId: json['file_id'] as String?,
      fileName: json['file_name'] as String?,
      fileSize: json['file_size'] as int?,
      isOutgoing: isOutgoing,
    );
  }
}

/// Chat (conversation) summary
class Chat extends Equatable {
  final String id;  // Same as contact's user ID
  final String recipientId;
  final String recipientUsername;
  final String? recipientDisplayName;
  final Message? lastMessage;
  final int unreadCount;
  final DateTime? lastActivity;
  final bool isOnline;
  
  const Chat({
    required this.id,
    required this.recipientId,
    required this.recipientUsername,
    this.recipientDisplayName,
    this.lastMessage,
    this.unreadCount = 0,
    this.lastActivity,
    this.isOnline = false,
  });
  
  String get displayName => recipientDisplayName ?? recipientUsername;
  
  @override
  List<Object?> get props => [
    id, recipientId, recipientUsername, recipientDisplayName,
    lastMessage, unreadCount, lastActivity, isOnline,
  ];
  
  Chat copyWith({
    String? id,
    String? recipientId,
    String? recipientUsername,
    String? recipientDisplayName,
    Message? lastMessage,
    int? unreadCount,
    DateTime? lastActivity,
    bool? isOnline,
  }) {
    return Chat(
      id: id ?? this.id,
      recipientId: recipientId ?? this.recipientId,
      recipientUsername: recipientUsername ?? this.recipientUsername,
      recipientDisplayName: recipientDisplayName ?? this.recipientDisplayName,
      lastMessage: lastMessage ?? this.lastMessage,
      unreadCount: unreadCount ?? this.unreadCount,
      lastActivity: lastActivity ?? this.lastActivity,
      isOnline: isOnline ?? this.isOnline,
    );
  }
}

/// Contact (user that can be messaged)
class Contact extends Equatable {
  final String id;
  final String username;
  final String? displayName;
  final bool isVerified;
  final DateTime? lastSeen;
  final bool isOnline;
  
  const Contact({
    required this.id,
    required this.username,
    this.displayName,
    this.isVerified = false,
    this.lastSeen,
    this.isOnline = false,
  });
  
  String get name => displayName ?? username;
  
  @override
  List<Object?> get props => [id, username, displayName, isVerified, lastSeen, isOnline];
  
  factory Contact.fromJson(Map<String, dynamic> json) {
    return Contact(
      id: json['id'] as String,
      username: json['username'] as String,
      displayName: json['display_name'] as String?,
      isVerified: json['is_verified'] as bool? ?? false,
      lastSeen: json['last_seen'] != null 
          ? DateTime.parse(json['last_seen'] as String)
          : null,
    );
  }
}
