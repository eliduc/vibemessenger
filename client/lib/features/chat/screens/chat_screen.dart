/// Chat Screen - Individual chat view
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';

import '../chat_provider.dart';
import '../../../shared/models/message.dart';

class ChatScreen extends StatefulWidget {
  final Chat chat;
  
  const ChatScreen({super.key, required this.chat});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _messageController = TextEditingController();
  final _scrollController = ScrollController();
  final _focusNode = FocusNode();
  
  Timer? _typingTimer;
  bool _isTyping = false;

  @override
  void initState() {
    super.initState();
    
    // Set active chat
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<ChatProvider>().setActiveChat(widget.chat.id);
    });
    
    // Listen for new messages to scroll
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    context.read<ChatProvider>().setActiveChat(null);
    _messageController.dispose();
    _scrollController.dispose();
    _focusNode.dispose();
    _typingTimer?.cancel();
    super.dispose();
  }
  
  void _onScroll() {
    // Load more messages when near top
    if (_scrollController.position.pixels < 100) {
      // TODO: Load older messages
    }
  }
  
  void _onTextChanged(String text) {
    // Send typing indicator
    if (!_isTyping && text.isNotEmpty) {
      _isTyping = true;
      context.read<ChatProvider>().sendTypingIndicator(widget.chat.id);
    }
    
    // Reset typing timer
    _typingTimer?.cancel();
    _typingTimer = Timer(const Duration(seconds: 3), () {
      _isTyping = false;
    });
  }
  
  Future<void> _sendMessage() async {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;
    
    _messageController.clear();
    _isTyping = false;
    
    final chatProvider = context.read<ChatProvider>();
    await chatProvider.sendMessage(widget.chat.id, text);
    
    // Scroll to bottom
    _scrollToBottom();
  }
  
  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final chatProvider = context.watch<ChatProvider>();
    final messages = chatProvider.getMessages(widget.chat.id);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            // Avatar
            CircleAvatar(
              radius: 18,
              backgroundColor: theme.colorScheme.primaryContainer,
              child: Text(
                widget.chat.displayName[0].toUpperCase(),
                style: TextStyle(
                  color: theme.colorScheme.onPrimaryContainer,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            const SizedBox(width: 12),
            
            // Name and status
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.chat.displayName,
                    style: theme.textTheme.titleMedium,
                    overflow: TextOverflow.ellipsis,
                  ),
                  Text(
                    widget.chat.isOnline ? 'Online' : 'Offline',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: widget.chat.isOnline 
                          ? Colors.green 
                          : theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.call_outlined),
            onPressed: () {
              // TODO: Voice call
            },
          ),
          IconButton(
            icon: const Icon(Icons.more_vert),
            onPressed: () {
              _showChatOptions(context);
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Encryption badge
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 8),
            color: theme.colorScheme.primaryContainer.withOpacity(0.3),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  Icons.lock_outline,
                  size: 14,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 4),
                Text(
                  'Messages are end-to-end encrypted',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
              ],
            ),
          ),
          
          // Messages list
          Expanded(
            child: messages.isEmpty
                ? _buildEmptyState(theme)
                : ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.all(16),
                    itemCount: messages.length,
                    itemBuilder: (context, index) {
                      final message = messages[index];
                      final showDate = index == 0 || 
                          !_isSameDay(
                            messages[index - 1].timestamp,
                            message.timestamp,
                          );
                      
                      return Column(
                        children: [
                          if (showDate) _buildDateSeparator(message.timestamp, theme),
                          _MessageBubble(
                            message: message,
                            onResend: () => chatProvider.resendMessage(
                              widget.chat.id,
                              message.id,
                            ),
                          ),
                        ],
                      );
                    },
                  ),
          ),
          
          // Input area
          _buildInputArea(theme),
        ],
      ),
    );
  }
  
  Widget _buildEmptyState(ThemeData theme) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.chat_bubble_outline,
            size: 64,
            color: theme.colorScheme.primary.withOpacity(0.5),
          ),
          const SizedBox(height: 16),
          Text(
            'No messages yet',
            style: theme.textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Text(
            'Send a message to start the conversation',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildDateSeparator(DateTime date, ThemeData theme) {
    String text;
    final now = DateTime.now();
    
    if (_isSameDay(date, now)) {
      text = 'Today';
    } else if (_isSameDay(date, now.subtract(const Duration(days: 1)))) {
      text = 'Yesterday';
    } else {
      text = DateFormat('MMMM d, yyyy').format(date);
    }
    
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Text(
        text,
        style: theme.textTheme.bodySmall?.copyWith(
          color: theme.colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
  
  Widget _buildInputArea(ThemeData theme) {
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        boxShadow: [
          BoxShadow(
            offset: const Offset(0, -1),
            blurRadius: 4,
            color: Colors.black.withOpacity(0.1),
          ),
        ],
      ),
      child: SafeArea(
        child: Row(
          children: [
            // Attachment button
            IconButton(
              icon: const Icon(Icons.attach_file),
              onPressed: () {
                // TODO: Attach file
              },
            ),
            
            // Text field
            Expanded(
              child: TextField(
                controller: _messageController,
                focusNode: _focusNode,
                decoration: InputDecoration(
                  hintText: 'Message',
                  filled: true,
                  fillColor: theme.colorScheme.surfaceContainerHighest,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide.none,
                  ),
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 8,
                  ),
                ),
                maxLines: 4,
                minLines: 1,
                textCapitalization: TextCapitalization.sentences,
                onChanged: _onTextChanged,
                onSubmitted: (_) => _sendMessage(),
              ),
            ),
            
            const SizedBox(width: 8),
            
            // Send button
            IconButton.filled(
              icon: const Icon(Icons.send),
              onPressed: _sendMessage,
            ),
          ],
        ),
      ),
    );
  }
  
  void _showChatOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.person_outline),
              title: const Text('View Profile'),
              onTap: () {
                Navigator.pop(context);
                // TODO: View profile
              },
            ),
            ListTile(
              leading: const Icon(Icons.search),
              title: const Text('Search Messages'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Search
              },
            ),
            ListTile(
              leading: const Icon(Icons.notifications_outlined),
              title: const Text('Mute Notifications'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Mute
              },
            ),
            ListTile(
              leading: const Icon(Icons.delete_outline),
              title: const Text('Clear Chat'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Clear chat
              },
            ),
          ],
        ),
      ),
    );
  }
  
  bool _isSameDay(DateTime a, DateTime b) {
    return a.year == b.year && a.month == b.month && a.day == b.day;
  }
}

/// Message bubble widget
class _MessageBubble extends StatelessWidget {
  final Message message;
  final VoidCallback? onResend;
  
  const _MessageBubble({
    required this.message,
    this.onResend,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isOutgoing = message.isOutgoing;
    
    return Align(
      alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(bottom: 4),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        child: GestureDetector(
          onLongPress: () => _showMessageOptions(context),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: isOutgoing 
                  ? theme.colorScheme.primary 
                  : theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(16),
                topRight: const Radius.circular(16),
                bottomLeft: Radius.circular(isOutgoing ? 16 : 4),
                bottomRight: Radius.circular(isOutgoing ? 4 : 16),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                // Message content
                Text(
                  message.content,
                  style: TextStyle(
                    color: isOutgoing 
                        ? theme.colorScheme.onPrimary 
                        : theme.colorScheme.onSurface,
                  ),
                ),
                
                const SizedBox(height: 4),
                
                // Time and status
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      DateFormat('HH:mm').format(message.timestamp),
                      style: TextStyle(
                        fontSize: 11,
                        color: isOutgoing 
                            ? theme.colorScheme.onPrimary.withOpacity(0.7)
                            : theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    if (isOutgoing) ...[
                      const SizedBox(width: 4),
                      _buildStatusIcon(theme),
                    ],
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
  
  Widget _buildStatusIcon(ThemeData theme) {
    final color = theme.colorScheme.onPrimary.withOpacity(0.7);
    
    switch (message.status) {
      case MessageStatus.sending:
        return SizedBox(
          width: 12,
          height: 12,
          child: CircularProgressIndicator(
            strokeWidth: 1.5,
            color: color,
          ),
        );
      case MessageStatus.sent:
        return Icon(Icons.check, size: 14, color: color);
      case MessageStatus.delivered:
        return Icon(Icons.done_all, size: 14, color: color);
      case MessageStatus.read:
        return Icon(Icons.done_all, size: 14, color: Colors.lightBlueAccent);
      case MessageStatus.failed:
        return GestureDetector(
          onTap: onResend,
          child: const Icon(Icons.error_outline, size: 14, color: Colors.red),
        );
    }
  }
  
  void _showMessageOptions(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.copy),
              title: const Text('Copy'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Copy to clipboard
              },
            ),
            if (message.status == MessageStatus.failed)
              ListTile(
                leading: const Icon(Icons.refresh),
                title: const Text('Resend'),
                onTap: () {
                  Navigator.pop(context);
                  onResend?.call();
                },
              ),
            ListTile(
              leading: const Icon(Icons.delete_outline),
              title: const Text('Delete'),
              onTap: () {
                Navigator.pop(context);
                // TODO: Delete message
              },
            ),
          ],
        ),
      ),
    );
  }
}
