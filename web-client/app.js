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

// Secure Messenger Web Client with Voice Calls and E2EE

// Password visibility toggle (v3.11.12)
function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
    } else {
        input.type = 'password';
        btn.textContent = '👁';
    }
}
// Version: 3.10.0 - WebAuthn biometric auth, passkey login, app lock, step-up verification
const API_URL = '/api/v1';

// Early theme initialization (before DOM ready to prevent flash)
(function() {
    const savedTheme = localStorage.getItem('theme') || 'system';
    if (savedTheme !== 'system') {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
})();

const state = {
    user: null,
    token: null,
    refreshToken: null,
    ws: null,
    chats: {},
    currentChat: null,
    currentChatId: null,
    pingInterval: null,
    permissions: null,
    onlineUsers: {},  // user_id -> boolean
    // Call state
    call: null,
    peerConnection: null,
    localStream: null,
    remoteStream: null,
    iceCandidateBuffer: [],
    // Disappearing messages
    disappearingTime: 0,  // 0 = off, otherwise seconds
    // Typing indicator
    typingUsers: {},  // chatId -> { timeout, userId }
    lastTypingSent: 0,
    // Sound settings
    soundEnabled: localStorage.getItem('soundEnabled') !== 'false',
    // Pending status updates (for messages not yet confirmed by server)
    pendingStatusUpdates: {},  // server_message_id -> { status, timestamp }
    // Reply state
    replyToMessage: null,  // { id, sender_id, sender_name, text }
    // Offline state
    isOnline: navigator.onLine,
    messageQueue: [],  // Messages to send when back online
    offlineBannerTimeout: null,  // Delay before showing banner
    // IndexedDB instance
    offlineDB: null,
    // E2EE state
    e2eeReady: false,
    keyBundles: {},  // recipient_id -> key bundle cache
    fileKeys: {},  // КАО#090: file_id -> at-rest AES key (from decrypted fileInfo)
    pollKeys: {},  // КАО#230 (SER#18): poll_id -> per-poll content key (from the E2E announce message)
    keyResetPending: {},  // v3.8.8: userId -> displayName for pending key reset notifications
    // v3.8.36: Multi-select mode for batch operations
    multiSelectMode: false,
    selectedMessages: [],  // Array of { id, isSent, message }
    // v3.8.37: Set of favorite message IDs for star indicator
    favoriteMessageIds: new Set(),
    // v3.11.8: Screenshot protection
    screenshotProtection: localStorage.getItem('screenshotProtection') === 'true',
};

const screens = {
    auth: document.getElementById('auth-screen'),
    chats: document.getElementById('chats-screen'),
    chat: document.getElementById('chat-screen'),
    settings: document.getElementById('settings-screen'),
};

// ==================== INDEXEDDB OFFLINE STORAGE ====================

/**
 * VibeOfflineDB - IndexedDB wrapper for offline message storage
 * Provides reliable persistent storage that survives browser restarts
 */
class VibeOfflineDB {
    constructor() {
        this.dbName = 'VibeMessengerOffline';
        this.dbVersion = 3;  // v3: Added knownIdentityKeys store for identity key change detection
        this.db = null;
    }
    
    /**
     * Initialize IndexedDB connection
     * @returns {Promise<boolean>} Success status
     */
    async init() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                console.warn('IndexedDB not supported, falling back to localStorage');
                resolve(false);
                return;
            }
            
            const request = indexedDB.open(this.dbName, this.dbVersion);
            
            request.onerror = (event) => {
                console.error('IndexedDB error:', event.target.error);
                resolve(false);
            };
            
            request.onsuccess = (event) => {
                this.db = event.target.result;
                console.log('IndexedDB initialized');
                resolve(true);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Pending messages store
                if (!db.objectStoreNames.contains('pendingMessages')) {
                    const store = db.createObjectStore('pendingMessages', { 
                        keyPath: 'client_message_id' 
                    });
                    store.createIndex('userId', 'user_id', { unique: false });
                    store.createIndex('chatId', 'chat_id', { unique: false });
                    store.createIndex('queuedAt', 'queued_at', { unique: false });
                }
                
                // Cached messages store (for offline access)
                if (!db.objectStoreNames.contains('cachedMessages')) {
                    const cacheStore = db.createObjectStore('cachedMessages', { 
                        keyPath: 'id' 
                    });
                    cacheStore.createIndex('chatId', 'chat_id', { unique: false });
                    cacheStore.createIndex('timestamp', 'created_at', { unique: false });
                }
                
                // Sync status store
                if (!db.objectStoreNames.contains('syncStatus')) {
                    db.createObjectStore('syncStatus', { keyPath: 'key' });
                }
                
                // Decrypted messages store (E2EE cache)
                if (!db.objectStoreNames.contains('decryptedMessages')) {
                    const decryptedStore = db.createObjectStore('decryptedMessages', { 
                        keyPath: 'id' 
                    });
                    decryptedStore.createIndex('chatId', 'chat_id', { unique: false });
                    decryptedStore.createIndex('decryptedAt', 'decrypted_at', { unique: false });
                }
                
                // Known identity keys store (v3.7.0 - for identity key change detection)
                if (!db.objectStoreNames.contains('knownIdentityKeys')) {
                    const keysStore = db.createObjectStore('knownIdentityKeys', { 
                        keyPath: 'user_id' 
                    });
                    keysStore.createIndex('trusted', 'trusted', { unique: false });
                }
                
                console.log('IndexedDB schema created');
            };
        });
    }
    
    /**
     * Add a pending message to the queue
     * @param {Object} message - Message data
     * @returns {Promise<boolean>} Success status
     */
    async addPendingMessage(message) {
        if (!this.db) return false;
        
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readwrite');
                const store = transaction.objectStore('pendingMessages');
                
                const messageData = {
                    ...message,
                    user_id: state.user?.id,
                    chat_id: message.group_id ? 'group_' + message.group_id : message.recipient_id,
                    queued_at: new Date().toISOString(),
                    status: 'pending'
                };
                
                const request = store.put(messageData);
                
                request.onsuccess = () => {
                    console.log('Message added to IndexedDB queue:', message.client_message_id);
                    resolve(true);
                };
                
                request.onerror = (event) => {
                    console.error('Error adding pending message:', event.target.error);
                    resolve(false);
                };
            } catch (e) {
                console.error('IndexedDB addPendingMessage error:', e);
                resolve(false);
            }
        });
    }
    
    /**
     * Get all pending messages for current user
     * @returns {Promise<Array>} Array of pending messages
     */
    async getPendingMessages() {
        if (!this.db || !state.user?.id) return [];
        
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readonly');
                const store = transaction.objectStore('pendingMessages');
                const index = store.index('userId');
                const request = index.getAll(state.user.id);
                
                request.onsuccess = (event) => {
                    const messages = event.target.result || [];
                    // Sort by queued_at
                    messages.sort((a, b) => new Date(a.queued_at) - new Date(b.queued_at));
                    resolve(messages);
                };
                
                request.onerror = (event) => {
                    console.error('Error getting pending messages:', event.target.error);
                    resolve([]);
                };
            } catch (e) {
                console.error('IndexedDB getPendingMessages error:', e);
                resolve([]);
            }
        });
    }
    
    /**
     * Remove a pending message (after successful send)
     * @param {string} clientMessageId - Client message ID
     * @returns {Promise<boolean>} Success status
     */
    async removePendingMessage(clientMessageId) {
        if (!this.db) return false;
        
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readwrite');
                const store = transaction.objectStore('pendingMessages');
                const request = store.delete(clientMessageId);
                
                request.onsuccess = () => {
                    console.log('Removed pending message:', clientMessageId);
                    resolve(true);
                };
                
                request.onerror = (event) => {
                    console.error('Error removing pending message:', event.target.error);
                    resolve(false);
                };
            } catch (e) {
                console.error('IndexedDB removePendingMessage error:', e);
                resolve(false);
            }
        });
    }
    
    /**
     * Update pending message status
     * @param {string} clientMessageId - Client message ID
     * @param {string} status - New status ('pending', 'sending', 'failed')
     * @returns {Promise<boolean>} Success status
     */
    async updatePendingStatus(clientMessageId, status) {
        if (!this.db) return false;
        
        return new Promise((resolve, reject) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readwrite');
                const store = transaction.objectStore('pendingMessages');
                const getRequest = store.get(clientMessageId);
                
                getRequest.onsuccess = (event) => {
                    const message = event.target.result;
                    if (message) {
                        message.status = status;
                        message.updated_at = new Date().toISOString();
                        store.put(message);
                    }
                    resolve(true);
                };
                
                getRequest.onerror = () => resolve(false);
            } catch (e) {
                console.error('IndexedDB updatePendingStatus error:', e);
                resolve(false);
            }
        });
    }
    
    /**
     * Get count of pending messages
     * @returns {Promise<number>} Count of pending messages
     */
    async getPendingCount() {
        if (!this.db || !state.user?.id) return 0;
        
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readonly');
                const store = transaction.objectStore('pendingMessages');
                const index = store.index('userId');
                const request = index.count(state.user.id);
                
                request.onsuccess = (event) => resolve(event.target.result);
                request.onerror = () => resolve(0);
            } catch (e) {
                resolve(0);
            }
        });
    }
    
    /**
     * Clear all pending messages for current user
     * @returns {Promise<boolean>} Success status
     */
    async clearPendingMessages() {
        if (!this.db || !state.user?.id) return false;
        
        const messages = await this.getPendingMessages();
        for (const msg of messages) {
            await this.removePendingMessage(msg.client_message_id);
        }
        return true;
    }
    
    /**
     * Check if a message is pending
     * @param {string} clientMessageId - Client message ID
     * @returns {Promise<boolean>} True if message is pending
     */
    async isPending(clientMessageId) {
        if (!this.db) return false;
        
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['pendingMessages'], 'readonly');
                const store = transaction.objectStore('pendingMessages');
                const request = store.get(clientMessageId);
                
                request.onsuccess = (event) => resolve(!!event.target.result);
                request.onerror = () => resolve(false);
            } catch (e) {
                resolve(false);
            }
        });
    }
    
    // ==================== DECRYPTED MESSAGES CACHE (E2EE) ====================
    
    /**
     * Save decrypted message to cache
     * @param {string} messageId - Server message ID
     * @param {string} chatId - Chat ID (user_id or group_id)
     * @param {string} text - Decrypted text
     * @param {Object|null} fileInfo - File info if any
     * @returns {Promise<boolean>} Success status
     */
    async saveDecryptedMessage(messageId, chatId, text, fileInfo = null) {
        if (!this.db) return false;
        
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
                const store = transaction.objectStore('decryptedMessages');
                
                const record = {
                    id: messageId,
                    chat_id: chatId,
                    text: text,
                    file_info: fileInfo,
                    decrypted_at: Date.now()
                };
                
                const request = store.put(record);
                request.onsuccess = () => resolve(true);
                request.onerror = () => resolve(false);
            } catch (e) {
                console.error('Error saving decrypted message:', e);
                resolve(false);
            }
        });
    }
    
    /**
     * Get decrypted message from cache
     * @param {string} messageId - Server message ID
     * @returns {Promise<Object|null>} {text, file_info} or null
     */
    async getDecryptedMessage(messageId) {
        if (!this.db) return null;
        
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['decryptedMessages'], 'readonly');
                const store = transaction.objectStore('decryptedMessages');
                const request = store.get(messageId);
                
                request.onsuccess = (event) => {
                    const result = event.target.result;
                    if (result) {
                        resolve({ text: result.text, file_info: result.file_info });
                    } else {
                        resolve(null);
                    }
                };
                request.onerror = () => resolve(null);
            } catch (e) {
                resolve(null);
            }
        });
    }
    
    /**
     * Get multiple decrypted messages from cache
     * @param {Array<string>} messageIds - Array of message IDs
     * @returns {Promise<Map<string, Object>>} Map of id -> {text, file_info}
     */
    async getDecryptedMessages(messageIds) {
        if (!this.db || !messageIds.length) return new Map();
        
        return new Promise((resolve) => {
            try {
                const result = new Map();
                const transaction = this.db.transaction(['decryptedMessages'], 'readonly');
                const store = transaction.objectStore('decryptedMessages');
                let completed = 0;
                
                for (const id of messageIds) {
                    const request = store.get(id);
                    request.onsuccess = (event) => {
                        const record = event.target.result;
                        if (record) {
                            result.set(id, { text: record.text, file_info: record.file_info });
                        }
                        completed++;
                        if (completed === messageIds.length) {
                            resolve(result);
                        }
                    };
                    request.onerror = () => {
                        completed++;
                        if (completed === messageIds.length) {
                            resolve(result);
                        }
                    };
                }
            } catch (e) {
                resolve(new Map());
            }
        });
    }
    
    /**
     * Delete decrypted messages for a chat (on chat delete)
     * @param {string} chatId - Chat ID
     * @returns {Promise<boolean>} Success status
     */
    async deleteDecryptedMessagesForChat(chatId) {
        if (!this.db) return false;
        
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
                const store = transaction.objectStore('decryptedMessages');
                const index = store.index('chatId');
                const request = index.openCursor(IDBKeyRange.only(chatId));
                
                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        cursor.delete();
                        cursor.continue();
                    } else {
                        resolve(true);
                    }
                };
                request.onerror = () => resolve(false);
            } catch (e) {
                resolve(false);
            }
        });
    }
    
    /**
     * КАО#274 (#40): delete specific decrypted-message plaintext from the cache by id.
     * Used when disappearing messages expire so their plaintext doesn't linger on disk.
     */
    async deleteDecryptedMessages(messageIds) {
        if (!this.db || !messageIds || !messageIds.length) return false;
        return new Promise((resolve) => {
            try {
                const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
                const store = transaction.objectStore('decryptedMessages');
                for (const id of messageIds) { try { store.delete(id); } catch (e) {} }
                transaction.oncomplete = () => resolve(true);
                transaction.onerror = () => resolve(false);
            } catch (e) { resolve(false); }
        });
    }

    /**
     * Clear old decrypted messages (older than 30 days)
     * @returns {Promise<number>} Number of deleted messages
     */
    async cleanupOldDecryptedMessages() {
        if (!this.db) return 0;
        
        const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
        
        return new Promise((resolve) => {
            try {
                let deleted = 0;
                const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
                const store = transaction.objectStore('decryptedMessages');
                const index = store.index('decryptedAt');
                const request = index.openCursor(IDBKeyRange.upperBound(thirtyDaysAgo));
                
                request.onsuccess = (event) => {
                    const cursor = event.target.result;
                    if (cursor) {
                        cursor.delete();
                        deleted++;
                        cursor.continue();
                    } else {
                        if (deleted > 0) {
                            console.log('[E2EE] Cleaned up', deleted, 'old decrypted messages');
                        }
                        resolve(deleted);
                    }
                };
                request.onerror = () => resolve(deleted);
            } catch (e) {
                resolve(0);
            }
        });
    }
}

// Create global IndexedDB instance
const offlineDB = new VibeOfflineDB();

// ==================== XSS PROTECTION ====================

/**
 * Escape HTML special characters to prevent XSS attacks
 * @param {string} text - User input text
 * @returns {string} - Safe HTML string
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const str = String(text);
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return str.replace(/[&<>"']/g, char => map[char]);
}

/**
 * Escape a string for safe use in JavaScript string context (inside onclick, etc.)
 * This handles quotes, backslashes, and other special characters that could break
 * out of the string context and execute arbitrary code.
 */
function escapeJsString(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/\\/g, '\\\\')     // Backslash first!
        .replace(/'/g, "\\'")        // Single quotes
        .replace(/"/g, '\\"')        // Double quotes
        .replace(/\n/g, '\\n')       // Newlines
        .replace(/\r/g, '\\r')       // Carriage returns
        .replace(/\t/g, '\\t')       // Tabs
        .replace(/</g, '\\x3c')      // Less than (prevent </script> injection)
        .replace(/>/g, '\\x3e')      // Greater than
        .replace(/\u2028/g, '\\u2028') // Line separator
        .replace(/\u2029/g, '\\u2029'); // Paragraph separator
}

/**
 * Safe attribute value for use in onclick handlers.
 * Applies both JS escaping and HTML escaping for double protection.
 */
function safeOnclickArg(text) {
    return escapeHtml(escapeJsString(text));
}

/**
 * Parse Markdown text and convert to HTML.
 * Supports: **bold**, *italic*, ~~strikethrough~~, `code`, ```code blocks```, [links](url), lists
 * Escaping: \* \_ \~ \` \[ \] to output literal characters
 */
function parseMarkdown(text) {
    if (text === null || text === undefined) return '';
    let str = String(text);
    
    // First, handle escape sequences - replace \X with placeholders
    const escapeMap = {};
    let escapeIndex = 0;
    str = str.replace(/\\([*_~`\[\]\\])/g, (match, char) => {
        const placeholder = `\x00ESC${escapeIndex++}\x00`;
        escapeMap[placeholder] = char;
        return placeholder;
    });
    
    // Escape HTML
    str = escapeHtml(str);
    
    // Code blocks (```) - must be before inline code
    str = str.replace(/```([^`]+)```/g, '<pre class="md-code-block">$1</pre>');
    
    // Inline code (`)
    str = str.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');
    
    // Bold (**text** or __text__)
    str = str.replace(/\*\*([^*]+)\*\*/g, '<strong class="md-bold">$1</strong>');
    str = str.replace(/__([^_]+)__/g, '<strong class="md-bold">$1</strong>');
    
    // Italic (*text* or _text_) - must be after bold
    str = str.replace(/\*([^*]+)\*/g, '<em class="md-italic">$1</em>');
    str = str.replace(/(?<![a-zA-Z0-9])_([^_]+)_(?![a-zA-Z0-9])/g, '<em class="md-italic">$1</em>');
    
    // Strikethrough (~~text~~)
    str = str.replace(/~~([^~]+)~~/g, '<del class="md-strike">$1</del>');
    
    // Links [text](url) — with URL scheme sanitization
    // КАО#040 (Round-3): URL capture allows one level of balanced parens so a closing ")" inside the
    // URL (e.g. javascript:alert(1) or https://…/Foo_(bar)) is consumed by the URL, not left as a
    // stray ")" after a blocked link. Was /\(([^)]+)\)/ which stopped at the first ")".
    str = str.replace(/\[([^\]]+)\]\(((?:[^()]|\([^()]*\))+)\)/g, (match, text, url) => {
        // КАО#040 (sec): allowlist URL schemes (was a bypassable blocklist)
        const trimmedUrl = url.trim().toLowerCase();
        const schemeOk = trimmedUrl.startsWith('http://') || trimmedUrl.startsWith('https://')
            || trimmedUrl.startsWith('mailto:') || trimmedUrl.startsWith('/') || trimmedUrl.startsWith('#');
        if (!schemeOk) {
            return escapeHtml(text); // disallow non-allowlisted scheme, keep text
        }
        return '<a href="' + url + '" class="md-link" target="_blank" rel="noopener noreferrer">' + text + '</a>';
    });
    
    // Auto-link URLs (not already in links)
    str = str.replace(/(?<!href="|">)(https?:\/\/[^\s<]+)/g, '<a href="$1" class="md-link" target="_blank" rel="noopener noreferrer">$1</a>');
    
    // Unordered lists (lines starting with - or *)
    str = str.replace(/^[\-\*]\s+(.+)$/gm, '<li class="md-list-item">$1</li>');
    // Wrap consecutive list items
    str = str.replace(/(<li class="md-list-item">.*<\/li>\n?)+/g, '<ul class="md-list">$&</ul>');
    
    // Ordered lists (lines starting with 1. 2. etc) — КАО#120: distinct class + wrap in <ol> (was orphan <li>)
    str = str.replace(/^\d+\.\s+(.+)$/gm, '<li class="md-olist-item">$1</li>');
    str = str.replace(/(<li class="md-olist-item">.*<\/li>\n?)+/g, '<ol class="md-list">$&</ol>');
    
    // Restore escaped characters
    for (const [placeholder, char] of Object.entries(escapeMap)) {
        str = str.replace(placeholder, escapeHtml(char));
    }
    
    return str;
}

/**
 * Parse Markdown for preview (same as parseMarkdown but wrapped in preview container)
 */
function getMarkdownPreview(text) {
    if (!text || !text.trim()) return '';
    // Check if text contains any markdown syntax
    if (!/[*_~`\[\]]/.test(text)) return '';
    return parseMarkdown(text);
}

/**
 * Update markdown preview as user types
 */
function updateMarkdownPreview() {
    const input = document.getElementById('message-text');
    const preview = document.getElementById('markdown-preview');
    const previewContent = document.getElementById('markdown-preview-content');
    
    if (!input || !preview || !previewContent) return;
    
    const text = input.value;
    const html = getMarkdownPreview(text);
    
    if (html) {
        previewContent.innerHTML = html;
        preview.classList.remove('hidden');
    } else {
        preview.classList.add('hidden');
        previewContent.innerHTML = '';
    }
}

/**
 * Clear markdown preview (call when sending message)
 */
function clearMarkdownPreview() {
    const preview = document.getElementById('markdown-preview');
    const previewContent = document.getElementById('markdown-preview-content');
    if (preview) preview.classList.add('hidden');
    if (previewContent) previewContent.innerHTML = '';
}



// ==================== CHANNEL COMMENTS (v3.11.10) ====================

/**
 * Toggle inline comments section for a channel post
 */
async function toggleChannelComments(messageId) {
    const section = document.getElementById('comments-' + messageId);
    if (section) {
        // Already open — collapse
        section.remove();
        return;
    }

    // Create comments section
    const msgEl = document.querySelector('[data-message-id="' + messageId + '"]');
    if (!msgEl) return;

    const commentsDiv = document.createElement('div');
    commentsDiv.id = 'comments-' + messageId;
    commentsDiv.className = 'channel-comments-section';
    commentsDiv.innerHTML = '<div style="text-align:center;padding:8px;color:#999;">Loading...</div>';
    msgEl.appendChild(commentsDiv);

    // Fetch comments
    try {
        const response = await api('/messages/' + messageId + '/comments');
        if (response.ok) {
            const data = await response.json();
            renderChannelComments(messageId, data.comments, commentsDiv);
        } else {
            commentsDiv.innerHTML = '<div style="color:red;padding:8px;">Failed to load comments</div>';
        }
    } catch (e) {
        console.error('Failed to load comments:', e);
        commentsDiv.innerHTML = '<div style="color:red;padding:8px;">Failed to load comments</div>';
    }
}

/**
 * Render comments inside the comments section
 */
function renderChannelComments(parentId, comments, container) {
    let html = '';

    for (const comment of comments) {
        let text = '';
        try {
            text = decodeURIComponent(escape(atob(comment.encrypted_payload)));
        } catch {
            text = comment.encrypted_payload || '';
        }
        const initial = (comment.sender_name || '?')[0].toUpperCase();
        const time = comment.created_at ? new Date(comment.created_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';

        html += '<div class="channel-comment">';
        html += '  <div class="channel-comment-avatar">' + escapeHtml(initial) + '</div>';
        html += '  <div class="channel-comment-body">';
        html += '    <div class="channel-comment-author">' + escapeHtml(comment.sender_name || 'Unknown') + '</div>';
        html += '    <div class="channel-comment-text">' + escapeHtml(text) + '</div>';
        html += '    <div class="channel-comment-time">' + time + '</div>';
        html += '  </div>';
        html += '</div>';
    }

    // Comment input
    html += '<div class="channel-comment-input-row">';
    html += '  <input type="text" id="comment-input-' + parentId + '" placeholder="Write a comment..." onkeydown="if(event.key===\'Enter\')sendChannelComment(\'' + parentId + '\')">';
    html += '  <button class="channel-comment-send-btn" onclick="sendChannelComment(\'' + parentId + '\')">Send</button>';
    html += '</div>';

    container.innerHTML = html;

    // Focus input
    const input = document.getElementById('comment-input-' + parentId);
    if (input) input.focus();
}

/**
 * Send a comment on a channel post
 */
async function sendChannelComment(parentId) {
    const input = document.getElementById('comment-input-' + parentId);
    if (!input) return;

    const text = input.value.trim();
    if (!text) return;

    const chat = state.chats[state.currentChatId];
    if (!chat) return;

    input.disabled = true;

    try {
        const encryptedPayload = btoa(unescape(encodeURIComponent(text)));
        const payload = {
            encrypted_payload: encryptedPayload,
            group_id: chat.id,
            reply_to_id: parentId,
            client_message_id: 'comment_' + Date.now()
        };

        const response = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            input.value = '';
            input.disabled = false;

            // Update comment count on the button
            const btn = document.querySelector('[data-comment-btn="' + parentId + '"]');
            if (btn) {
                const current = parseInt(btn.dataset.count || '0');
                const newCount = current + 1;
                btn.dataset.count = newCount;
                btn.textContent = '💬 ' + newCount + ' comment' + (newCount !== 1 ? 's' : '');
            }

            // Reload comments
            const section = document.getElementById('comments-' + parentId);
            if (section) {
                const resp = await api('/messages/' + parentId + '/comments');
                if (resp.ok) {
                    const data = await resp.json();
                    renderChannelComments(parentId, data.comments, section);
                }
            }
        } else {
            const err = await response.json();
            alert(err.detail || 'Failed to send comment');
            input.disabled = false;
        }
    } catch (e) {
        console.error('Send comment error:', e);
        alert('Failed to send comment');
        input.disabled = false;
    }
}

/**
 * Get HTML for channel comments button (added under each post)
 */
function getChannelCommentsButton(messageId, commentCount) {
    const count = commentCount || 0;
    const label = count > 0
        ? '💬 ' + count + ' comment' + (count !== 1 ? 's' : '')
        : '💬 Comment';
    return '<div class="channel-comments-btn" data-comment-btn="' + messageId + '" data-count="' + count + '" onclick="toggleChannelComments(\''+messageId+'\')">' + label + '</div>';
}



/**
 * Add channel comments buttons to all top-level posts after rendering
 * Called after renderMessages()
 */
function addChannelCommentButtons() {
    const chat = state.chats[state.currentChatId];
    if (!chat || !chat.isChannel) return;

    const messageEls = document.querySelectorAll('.message-bubble[data-message-id]');
    messageEls.forEach(el => {
        const msgId = el.getAttribute('data-message-id');
        // Skip if already has comments button
        if (el.querySelector('.channel-comments-btn')) return;

        // Find the message in chat data
        const msg = chat.messages.find(m => String(m.id) === String(msgId));
        if (!msg) return;

        // Only add to top-level posts (no reply_to_id)
        if (msg.reply_to_id) return;

        // Don't add to system messages
        if (msg.message_type === 'call' || msg.message_type === 'system') return;

        const count = msg.comment_count || 0;
        const btnHtml = getChannelCommentsButton(msgId, count);
        el.insertAdjacentHTML('beforeend', btnHtml);
    });
}


// ==================== CHANNEL INTEGRATION (v3.11.10) ====================

/**
 * Update UI for channel-specific behavior.
 * Called after openGroupChat() loads the chat.
 */
function updateChannelUI(chat) {
    const messageInput = document.querySelector('.message-input');
    const e2eeIndicator = document.getElementById('e2ee-indicator');

    if (chat && chat.isChannel) {
        // Show subscriber count instead of member count
        const statusEl = document.getElementById('chat-status');
        if (statusEl && chat.members) {
            const subCount = chat.members.length;
            statusEl.textContent = subCount + ' subscriber' + (subCount !== 1 ? 's' : '');
        }

        // Hide E2EE indicator for channels
        if (e2eeIndicator) {
            e2eeIndicator.style.display = 'none';
        }

        // Hide message input for non-posting roles
        if (messageInput) {
            if (!isPostingRole(chat.myRole)) {
                messageInput.style.display = 'none';
            } else {
                messageInput.style.display = '';
            }
        }
    } else {
        // Regular chat/group - restore defaults
        if (messageInput) {
            messageInput.style.display = '';
        }
        if (e2eeIndicator) {
            e2eeIndicator.style.display = '';
        }
    }
}

/**
 * Check if current chat is a channel and message should skip E2EE.
 */
function isChannelChat() {
    const chat = state.chats[state.currentChatId];
    return chat && chat.isChannel === true;
}

// ==================== OFFLINE MODE ====================

function initOfflineMode() {
    // Load message queue from localStorage
    loadMessageQueue();
    
    // Listen for online/offline events
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    // Set initial state
    updateOnlineStatus(navigator.onLine);
}

function handleOnline() {
    console.log('Network: online');
    updateOnlineStatus(true);
    
    // Reconnect WebSocket if needed
    if (state.token && (!state.ws || state.ws.readyState !== WebSocket.OPEN)) {
        connectWebSocket();
    }
    
    // Send queued messages
    sendQueuedMessages();
}

function handleOffline() {
    console.log('Network: offline');
    // Network is truly offline - show banner immediately
    if (state.offlineBannerTimeout) {
        clearTimeout(state.offlineBannerTimeout);
        state.offlineBannerTimeout = null;
    }
    updateOnlineStatus(false);
}

function updateOnlineStatus(isOnline) {
    state.isOnline = isOnline;
    const banner = document.getElementById('offline-banner');
    if (banner) {
        if (isOnline) {
            banner.classList.add('hidden');
        } else {
            banner.classList.remove('hidden');
        }
    }
}

function showOfflineBanner() {
    // Show banner only after delay (to avoid flashing during reconnect)
    if (state.offlineBannerTimeout) return; // Already scheduled
    
    state.offlineBannerTimeout = setTimeout(() => {
        state.offlineBannerTimeout = null;
        // Check again - maybe we reconnected during the delay
        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
            updateOnlineStatus(false);
        }
    }, 3000); // 3 seconds delay
}

function hideOfflineBanner() {
    // Cancel pending banner show
    if (state.offlineBannerTimeout) {
        clearTimeout(state.offlineBannerTimeout);
        state.offlineBannerTimeout = null;
    }
    updateOnlineStatus(true);
}

// Message Queue for offline mode (with IndexedDB support)
async function loadMessageQueue() {
    if (state.user && state.user.id) {
        // Try IndexedDB first
        if (offlineDB.db) {
            const messages = await offlineDB.getPendingMessages();
            state.messageQueue = messages;
            console.log('Loaded message queue from IndexedDB:', state.messageQueue.length, 'messages');
            
            // Update pending indicators in UI
            updatePendingIndicators();
            return;
        }
        
        // Fallback to localStorage
        const saved = localStorage.getItem('messageQueue_' + state.user.id);
        if (saved) {
            try {
                state.messageQueue = JSON.parse(saved);
                console.log('Loaded message queue from localStorage:', state.messageQueue.length, 'messages');
                
                // Migrate to IndexedDB if available
                if (offlineDB.db && state.messageQueue.length > 0) {
                    for (const msg of state.messageQueue) {
                        await offlineDB.addPendingMessage(msg);
                    }
                    localStorage.removeItem('messageQueue_' + state.user.id);
                    console.log('Migrated message queue to IndexedDB');
                }
            } catch (e) {
                state.messageQueue = [];
            }
        }
    }
}

async function saveMessageQueue() {
    if (state.user && state.user.id) {
        // IndexedDB is auto-saved, just update localStorage as backup
        if (!offlineDB.db) {
            localStorage.setItem('messageQueue_' + state.user.id, JSON.stringify(state.messageQueue));
        }
    }
}

async function addToMessageQueue(messageData) {
    const queuedMessage = {
        ...messageData,
        queued_at: new Date().toISOString(),
        status: 'pending'
    };
    
    // Add to IndexedDB
    if (offlineDB.db) {
        await offlineDB.addPendingMessage(queuedMessage);
    }
    
    // Also keep in memory queue
    state.messageQueue.push(queuedMessage);
    await saveMessageQueue();
    
    console.log('Message added to queue, total:', state.messageQueue.length);
    
    // Update pending indicator for this message
    updateMessagePendingUI(messageData.client_message_id, true);
}

// Update UI to show pending indicator for a message
function updateMessagePendingUI(clientMessageId, isPending) {
    const msgElement = document.querySelector(`[data-client-id="${clientMessageId}"]`);
    if (msgElement) {
        const statusIcon = msgElement.querySelector('.message-status');
        if (statusIcon) {
            if (isPending) {
                statusIcon.innerHTML = '⏳';
                statusIcon.title = 'Pending - will send when online';
                statusIcon.classList.add('pending');
            } else {
                statusIcon.classList.remove('pending');
            }
        }
    }
}

// Update all pending indicators in current chat
function updatePendingIndicators() {
    if (!state.messageQueue || state.messageQueue.length === 0) return;
    
    for (const msg of state.messageQueue) {
        if (msg.client_message_id) {
            updateMessagePendingUI(msg.client_message_id, true);
        }
    }
}

// Flag to prevent parallel execution
let isSendingQueuedMessages = false;

async function sendQueuedMessages() {
    // Load fresh from IndexedDB
    if (offlineDB.db) {
        state.messageQueue = await offlineDB.getPendingMessages();
    }
    
    if (state.messageQueue.length === 0) return;
    
    // Prevent parallel execution
    if (isSendingQueuedMessages) {
        console.log('Already sending queued messages, skipping');
        return;
    }
    
    isSendingQueuedMessages = true;
    console.log('Sending queued messages:', state.messageQueue.length);
    
    // Show sync indicator
    showSyncIndicator(true);
    
    // Take snapshot of queue and clear original
    const queue = [...state.messageQueue];
    state.messageQueue = [];
    await saveMessageQueue();
    
    // Track sent message IDs to avoid duplicates
    const sentIds = new Set();
    let successCount = 0;
    let failCount = 0;
    
    for (const msg of queue) {
        // Skip if already sent in this batch (duplicate protection)
        if (sentIds.has(msg.client_message_id)) {
            console.log('Skipping duplicate:', msg.client_message_id);
            await offlineDB.removePendingMessage(msg.client_message_id);
            continue;
        }
        
        // Update status to 'sending'
        if (offlineDB.db) {
            await offlineDB.updatePendingStatus(msg.client_message_id, 'sending');
        }
        updateMessagePendingUI(msg.client_message_id, true);
        
        try {
            const payload = {
                encrypted_payload: msg.encrypted_payload,
                client_message_id: msg.client_message_id,
            };
            
            if (msg.group_id) {
                payload.group_id = msg.group_id;
            } else if (msg.recipient_id) {
                payload.recipient_id = msg.recipient_id;
            }
            
            if (msg.expires_in_seconds) {
                payload.expires_in_seconds = msg.expires_in_seconds;
            }
            
            if (msg.reply_to_id) {
                payload.reply_to_id = msg.reply_to_id;
            }
            // КАО#160 (SER#11): preserve E2EE fields when flushing the offline queue (were dropped → broke group E2EE / multidevice / mentions)
            if (msg.encrypted_for_self) payload.encrypted_for_self = msg.encrypted_for_self;
            if (msg.sender_key_distribution) {
                // КАО#100 Round-2: re-encrypt a deferred (offline-queued) distribution now that we're back online
                if (msg.sender_key_distribution._deferred && msg.group_id) {
                    payload.sender_key_distribution = await encryptDistributionForMembers(msg.group_id, msg.sender_key_distribution._deferred);
                } else {
                    payload.sender_key_distribution = msg.sender_key_distribution;
                }
            }
            if (msg.mentions) payload.mentions = msg.mentions;

            const response = await api('/messages/send', {
                method: 'POST',
                body: JSON.stringify(payload),
            });
            
            if (response.ok) {
                const data = await response.json();
                updateMessageWithServerId(msg.client_message_id, data.id, data.status, data.expires_at);
                sentIds.add(msg.client_message_id);
                
                // Remove from IndexedDB
                await offlineDB.removePendingMessage(msg.client_message_id);
                updateMessagePendingUI(msg.client_message_id, false);
                
                successCount++;
                console.log('Queued message sent:', msg.client_message_id);
            } else if (response.status === 409) {
                // Message already exists on server (duplicate)
                console.log('Message already sent (conflict):', msg.client_message_id);
                sentIds.add(msg.client_message_id);
                await offlineDB.removePendingMessage(msg.client_message_id);
                updateMessagePendingUI(msg.client_message_id, false);
                successCount++;
            } else {
                console.error('Failed to send queued message:', msg.client_message_id, response.status);
                // Put back in queue if failed
                state.messageQueue.push(msg);
                if (offlineDB.db) {
                    await offlineDB.updatePendingStatus(msg.client_message_id, 'failed');
                }
                failCount++;
            }
        } catch (e) {
            console.error('Error sending queued message:', e);
            // Put back in queue if error
            state.messageQueue.push(msg);
            if (offlineDB.db) {
                await offlineDB.updatePendingStatus(msg.client_message_id, 'failed');
            }
            failCount++;
        }
    }
    
    await saveMessageQueue();
    isSendingQueuedMessages = false;
    
    // Hide sync indicator
    showSyncIndicator(false);
    
    // Show notification if there were results
    if (successCount > 0 || failCount > 0) {
        console.log(`Sync complete: ${successCount} sent, ${failCount} failed`);
        if (failCount > 0) {
            showToast(`${failCount} message(s) failed to send. Will retry.`, 'warning');
        }
    }
}

// Show/hide sync indicator in header
function showSyncIndicator(show) {
    let indicator = document.getElementById('sync-indicator');
    
    if (show) {
        if (!indicator) {
            indicator = document.createElement('span');
            indicator.id = 'sync-indicator';
            indicator.className = 'sync-indicator';
            indicator.innerHTML = '🔄';
            indicator.title = 'Syncing messages...';
            
            // Insert into header
            const header = document.querySelector('.header h1') || document.querySelector('.header');
            if (header) {
                header.appendChild(indicator);
            }
        }
        indicator.style.display = 'inline';
    } else {
        if (indicator) {
            indicator.style.display = 'none';
        }
    }
}

// ==================== TYPING INDICATOR ====================

var typingTimeout = null;

function sendTypingIndicator() {
    if (!state.currentChatId || !state.ws || state.ws.readyState !== WebSocket.OPEN) return;
    
    // Throttle: send at most once per 2 seconds
    const now = Date.now();
    if (now - state.lastTypingSent < 2000) return;
    state.lastTypingSent = now;
    
    const chat = state.chats[state.currentChatId];
    
    // Send via WebSocket
    const payload = {};
    if (chat && chat.isGroup) {
        payload.group_id = state.currentChatId.replace('group_', '');
    } else {
        payload.recipient_id = state.currentChatId;
    }
    
    state.ws.send(JSON.stringify({
        type: 'typing',
        payload: payload
    }));
}

function handleUserTyping(payload) {
    const userId = payload.user_id;
    const userName = payload.user_name || 'Someone';
    const groupId = payload.group_id;
    
    // Determine which chat this is for
    let chatId;
    if (groupId) {
        chatId = 'group_' + groupId;
    } else {
        chatId = userId;
    }
    
    // Only show if this chat is open
    if (state.currentChatId !== chatId) return;
    
    // Clear previous timeout for this user
    const typingKey = chatId + '_' + userId;
    if (state.typingUsers[typingKey]) {
        clearTimeout(state.typingUsers[typingKey].timeout);
    }
    
    // Show typing indicator
    showTypingIndicator(userName, groupId !== null);
    
    // Hide after 3 seconds
    state.typingUsers[typingKey] = {
        timeout: setTimeout(() => {
            hideTypingIndicator(chatId);
            delete state.typingUsers[typingKey];
        }, 3000)
    };
}

function showTypingIndicator(userName, isGroup) {
    const statusEl = document.getElementById('chat-status');
    if (statusEl) {
        const text = isGroup ? escapeHtml(userName) + ' is typing...' : 'Typing...';
        statusEl.innerHTML = '<span class="typing-indicator">' + text + '</span>';
    }
}

function hideTypingIndicator(chatId) {
    // Restore normal status
    if (state.currentChatId === chatId) {
        const chat = state.chats[chatId];
        if (chat && chat.isGroup) {
            // Group - show member count or nothing
            const statusEl = document.getElementById('chat-status');
            if (statusEl) statusEl.textContent = '';
        } else {
            // Direct chat - show online/offline status
            const isOnline = state.onlineUsers[chatId];
            updateChatHeaderStatus(isOnline);
        }
    }
}

// ==================== NOTIFICATION SOUNDS ====================

var notificationAudio = null;

function initNotificationSound() {
    // Create audio element with a simple beep sound (base64 encoded)
    notificationAudio = new Audio('data:audio/mp3;base64,SUQzBAAAAAAAI1RTU0UAAAAPAAADTGF2ZjU4Ljc2LjEwMAAAAAAAAAAAAAAA//tQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWGluZwAAAA8AAAACAAABhgC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7//////////////////////////////////////////////////////////////////8AAAAATGF2YzU4LjEzAAAAAAAAAAAAAAAAJAAAAAAAAAAAAYYNBrv/AAAAAAAAAAAAAAAAAAAAAP/7UGQAD/AAADSAAAAANIAAAGkAAAABE5JJV00AAAgpJJKummgAAFy7u7u7u7sG+7u7u7u7u7u7u7vAxEBAQEBMTAwMDAwEBATExMTExMUFBQUFBQYGBgYGBgYICAgICAgKCgoKCgoMDAwMDAwNDQ0NDQ0NTU1NTU1P/+1JkGQ/wAADSAAAAANIAAAGkAAAADe0klTSQAAC2kkknHH/gAEB4eHh4eIiIiIiIiKioqKioqLi4uLi4uMDAwMDAwMTExMTExMUlJSUlJSV//1VVVVf//VVVVX///VVX////u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4=');
    notificationAudio.volume = 0.5;
}

function playNotificationSound() {
    if (!state.soundEnabled) return;
    if (!notificationAudio) initNotificationSound();
    
    // Don't play if app is focused and chat is open
    if (document.hasFocus() && state.currentChatId) return;
    
    try {
        notificationAudio.currentTime = 0;
        notificationAudio.play().catch(() => {});
    } catch (e) {}
}

function toggleSound() {
    state.soundEnabled = !state.soundEnabled;
    localStorage.setItem('soundEnabled', state.soundEnabled);
    updateSoundButton();
}

function updateSoundButton() {
    const btn = document.getElementById('sound-toggle-btn');
    if (btn) {
        btn.textContent = state.soundEnabled ? '🔔' : '🔕';
        btn.title = state.soundEnabled ? 'Sound on' : 'Sound off';
    }
}

// ==================== SCREENSHOT PROTECTION (v3.11.8) ====================

async function toggleScreenshotProtection() {
    state.screenshotProtection = !state.screenshotProtection;
    localStorage.setItem('screenshotProtection', state.screenshotProtection);
    
    // Electron: use OS-level content protection (DRM flag)
    if (window.electronAPI) {
        await window.electronAPI.setScreenshotProtection(state.screenshotProtection);
    }
    
    applyScreenshotProtection();
    updateScreenshotToggleUI();
    showLocalMessage('privacy-message', 
        state.screenshotProtection ? 'Screenshot protection enabled' : 'Screenshot protection disabled',
        'success'
    );
}

function updateScreenshotToggleUI() {
    const toggle = document.getElementById('screenshot-toggle');
    if (toggle) {
        toggle.classList.toggle('active', state.screenshotProtection);
        toggle.setAttribute('aria-checked', state.screenshotProtection ? 'true' : 'false');  // КАО#133: a11y state sync
    }
    // Update hint text based on environment
    const hint = document.querySelector('#screenshot-protection-row .settings-row-hint');
    if (hint) {
        hint.textContent = window.electronAPI
            ? 'OS-level screen capture protection'
            : 'Block screen capture on this device';
    }
}

/**
 * Apply or remove all screenshot protection layers.
 * 
 * In Electron: real OS-level protection via setContentProtection() — 
 * blocks Win+Shift+S, PrintScreen, Recall, all screen capture tools.
 * 
 * In browser (fallback):
 * 1. CSS user-select: none on body
 * 2. PrintScreen / Meta+Shift+S key interception  
 * 3. Visibility change → cover screen with shield overlay
 * 4. Context menu suppression on media
 */
function applyScreenshotProtection() {
    const enabled = state.screenshotProtection;
    
    // In Electron, the main process handles real protection.
    // We still apply CSS/overlay layers as visual feedback.
    
    // Layer 1: CSS protection
    document.body.classList.toggle('screenshot-protected', enabled);
    
    // Layer 2 & 3: Managed via persistent event listeners (initialized once)
    // Their behavior checks state.screenshotProtection dynamically
    
    // Layer 4: Context menu on images (both Electron and browser)
    document.querySelectorAll('img, video, canvas').forEach(el => {
        if (enabled) {
            el.setAttribute('oncontextmenu', 'return false');
        } else {
            el.removeAttribute('oncontextmenu');
        }
    });
}

// Persistent event listeners (always active, check state dynamically)
(function _initScreenshotProtectionListeners() {
    // Block PrintScreen and common screenshot shortcuts (browser fallback)
    document.addEventListener('keydown', function(e) {
        if (!state.screenshotProtection) return;
        
        const isPrintScreen = e.key === 'PrintScreen';
        const isWinSnip = (e.metaKey || e.getModifierState('OS')) && e.shiftKey && e.key === 'S';
        const isMacScreenshot = e.metaKey && e.shiftKey && (e.key === '3' || e.key === '4' || e.key === '5');
        
        if (isPrintScreen || isWinSnip || isMacScreenshot) {
            e.preventDefault();
            e.stopPropagation();
            _showScreenshotShield(800);
            return false;
        }
    }, true);
    
    // Show shield overlay when app loses visibility
    document.addEventListener('visibilitychange', function() {
        if (!state.screenshotProtection) return;
        if (document.hidden) {
            _showScreenshotShield();
        } else {
            _hideScreenshotShield();
        }
    });
    
    // Cover on window blur (task switcher preview)
    window.addEventListener('blur', function() {
        if (!state.screenshotProtection) return;
        _showScreenshotShield();
    });
    
    window.addEventListener('focus', function() {
        if (!state.screenshotProtection) return;
        _hideScreenshotShield();
    });
    
    // Electron: listen for tray menu changes
    if (window.electronAPI && window.electronAPI.onScreenshotProtectionChanged) {
        window.electronAPI.onScreenshotProtectionChanged(function(enabled) {
            state.screenshotProtection = enabled;
            localStorage.setItem('screenshotProtection', enabled);
            applyScreenshotProtection();
            updateScreenshotToggleUI();
        });
    }
})();

// Sync state from Electron store on startup (Electron may have its own persisted state)
(async function _syncElectronScreenshotState() {
    if (!window.electronAPI) return;
    try {
        const electronState = await window.electronAPI.getScreenshotProtection();
        if (electronState !== state.screenshotProtection) {
            state.screenshotProtection = electronState;
            localStorage.setItem('screenshotProtection', electronState);
            applyScreenshotProtection();
            updateScreenshotToggleUI();
        }
    } catch (e) {
        console.warn('[ScreenshotProtection] Failed to sync Electron state:', e);
    }
})();

function _showScreenshotShield(autoHideMs) {
    let overlay = document.getElementById('screenshot-shield-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'screenshot-shield-overlay';
        overlay.className = 'screenshot-blur-overlay';
        overlay.innerHTML = '<div class="shield-icon">🛡️</div><div class="shield-text">Screen protected</div>';
        document.body.appendChild(overlay);
    }
    overlay.classList.add('visible');
    
    if (autoHideMs) {
        setTimeout(() => _hideScreenshotShield(), autoHideMs);
    }
}

function _hideScreenshotShield() {
    const overlay = document.getElementById('screenshot-shield-overlay');
    if (overlay) overlay.classList.remove('visible');
}

// Call ringtone (incoming) - use Audio element for Android compatibility
var callRingtone = null;
var callRingtoneInterval = null;

// Dialing sound (outgoing)
var dialingAudioCtx = null;
var dialingCurrentOsc = null;
var dialingCurrentGain = null;
var dialingInterval = null;
var dialingActive = false;

// Create ringtone audio element (works on Android)
function createRingtoneAudio() {
    if (callRingtone) return callRingtone;
    
    // Simple ringtone as base64 (short beep)
    callRingtone = new Audio('data:audio/wav;base64,UklGRl4FAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YToFAAD//wEAAQABAAEAAQACAP//AQABAAEAAQABAP///////wEAAQD//wEA//8BAAEA//8BAP////8AAAAA//8AAAEAAQD//wEA//8BAAEA/////wAAAQABAAAAAAEAAQAAAAAA//8BAAEA//8AAAEAAQD/////AAABAP//AQABAP//AAABAAAA//8BAAEA//8AAAAAAQABAAAAAQD//wAAAQABAAAA//8AAAEAAQD//wAAAAD//wEAAQD/////AAABAAAA//8BAAEA//8AAAAAAQABAP//AQD//wEA//8BAAEAAQD//wAAAAD//wEAAQD//wAAAQABAAAA/////wAAAQABAAAA//8AAAEA//8BAAEAAQD//wAAAQD//wEAAQD//wAAAAD//wEAAQAAAP//AAABAAAA//8BAAEAAQD//wAAAAD//wEAAQD//wAAAQABAAAA/////wAAAQABAAAA//8AAAEAAQD//wAAAAD//wEAAQAAAP//AAABAAAA//8BAAEAAQD//wAAAAD//wEAAQD//wAAAQABAAAA/////wAAAQABAAAA//8AAAEA');
    callRingtone.volume = 0.7;
    callRingtone.loop = false;
    return callRingtone;
}

// Pre-load audio on user interaction for Android
function preloadCallSounds() {
    try {
        createRingtoneAudio();
        // Attempt silent play to unlock audio on mobile
        if (callRingtone) {
            callRingtone.volume = 0;
            callRingtone.play().then(() => {
                callRingtone.pause();
                callRingtone.currentTime = 0;
                callRingtone.volume = 0.7;
            }).catch(() => {});
        }
    } catch (e) {}
}

// Call preloadCallSounds on first user interaction
document.addEventListener('click', function initAudio() {
    preloadCallSounds();
    document.removeEventListener('click', initAudio);
}, { once: true });
document.addEventListener('touchstart', function initAudio() {
    preloadCallSounds();
    document.removeEventListener('touchstart', initAudio);
}, { once: true, passive: true });

function playCallSound() {
    if (!state.soundEnabled) return;
    
    stopCallSound();
    
    try {
        const audio = createRingtoneAudio();
        
        const playRing = () => {
            if (!state.call || state.call.status !== 'ringing') {
                stopCallSound();
                return;
            }
            audio.currentTime = 0;
            audio.play().catch(e => console.log('Ringtone play error:', e));
        };
        
        playRing();
        callRingtoneInterval = setInterval(playRing, 1500);
        
        // Also try to vibrate on mobile
        if (navigator.vibrate) {
            navigator.vibrate([500, 300, 500, 300, 500, 1000]);
        }
    } catch (e) {
        console.log('Could not play call sound:', e);
    }
}

function playDialingSound() {
    if (!state.soundEnabled) return;
    
    stopDialingSound();
    dialingActive = true;
    
    try {
        dialingAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
        
        const playTone = () => {
            if (!dialingActive) {
                return;
            }
            
            // Stop previous oscillator if still playing
            if (dialingCurrentOsc) {
                try {
                    dialingCurrentGain.gain.value = 0;
                    dialingCurrentOsc.stop();
                } catch (e) {}
            }
            
            // Create fresh oscillator for each tone
            dialingCurrentOsc = dialingAudioCtx.createOscillator();
            dialingCurrentGain = dialingAudioCtx.createGain();
            
            dialingCurrentOsc.connect(dialingCurrentGain);
            dialingCurrentGain.connect(dialingAudioCtx.destination);
            
            dialingCurrentOsc.frequency.value = 440;
            dialingCurrentOsc.type = 'sine';
            dialingCurrentGain.gain.value = 0.25;
            
            dialingCurrentOsc.start();
            
            // Stop after 1 second
            setTimeout(() => {
                if (dialingCurrentOsc && dialingCurrentGain) {
                    try {
                        dialingCurrentGain.gain.value = 0;
                        dialingCurrentOsc.stop();
                    } catch (e) {}
                }
            }, 1000);
        };
        
        playTone();
        dialingInterval = setInterval(playTone, 4000);
    } catch (e) {
        console.log('Could not create dialing sound:', e);
    }
}

function stopDialingSound() {
    dialingActive = false;
    
    if (dialingInterval) {
        clearInterval(dialingInterval);
        dialingInterval = null;
    }
    
    // Stop current oscillator
    if (dialingCurrentOsc) {
        try {
            dialingCurrentGain.gain.value = 0;
            dialingCurrentOsc.stop();
        } catch (e) {}
        dialingCurrentOsc = null;
        dialingCurrentGain = null;
    }
    
    // Close audio context
    if (dialingAudioCtx) {
        try {
            dialingAudioCtx.close();
        } catch (e) {}
        dialingAudioCtx = null;
    }
}

function stopCallSound() {
    // Stop ringtone
    if (callRingtoneInterval) {
        clearInterval(callRingtoneInterval);
        callRingtoneInterval = null;
    }
    if (callRingtone) {
        try {
            callRingtone.pause();
            callRingtone.currentTime = 0;
        } catch (e) {}
    }
    
    // Stop vibration
    if (navigator.vibrate) {
        navigator.vibrate(0);
    }
    
    // Also stop dialing sound
    stopDialingSound();
}

// ==================== PINNED MESSAGES ====================

async function loadPinnedMessages() {
    if (!state.currentChatId) return;
    
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    try {
        const chatId = chat.isGroup ? state.currentChatId.replace('group_', '') : state.currentChatId;
        const response = await api('/messages/pinned/' + chatId);
        if (response.ok) {
            const pinnedData = await response.json();
            chat.pinnedMessages = pinnedData.map(p => {
                // v3.11.10: Handle E2EE encrypted pinned messages
                let text = '';
                try {
                    const rawDecoded = atob(p.encrypted_payload);
                    if (rawDecoded.startsWith('{"v":')) {
                        // КАО#200: reuse the already-decrypted text from the loaded chat instead of a bare placeholder
                        const cachedMsg = chat.messages && chat.messages.find(m => m.id === p.id);
                        text = (cachedMsg && cachedMsg.text && !cachedMsg.text.includes('Encrypted message')) ? cachedMsg.text : '🔒 Encrypted message';
                    } else {
                        text = decodeURIComponent(escape(rawDecoded));
                        try {
                            const parsed = JSON.parse(text);
                            text = parsed.text || parsed.content || '📎 File';
                        } catch {
                            // text is already plain string
                        }
                    }
                } catch {
                    text = '🔒 Encrypted message';
                }
                return {
                    id: p.id,
                    sender_id: p.sender_id,
                    text: text,
                    created_at: p.created_at,
                    pinned_at: p.pinned_at
                };
            });
            saveChats();
            renderPinnedMessages();
        }
    } catch (e) {
        console.error('Failed to load pinned messages:', e);
    }
}

async function pinMessage(messageId) {
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    const response = await api('/messages/' + messageId + '/pin', {
        method: 'POST'
    });
    
    if (response.ok) {
        const message = chat.messages.find(m => m.id === messageId);
        if (message) {
            message.is_pinned = true;
            
            // Add to pinned list
            if (!chat.pinnedMessages) chat.pinnedMessages = [];
            chat.pinnedMessages.unshift({
                id: message.id,
                sender_id: message.sender_id,
                text: message.text || '📎 File',
                created_at: message.created_at,
                pinned_at: new Date().toISOString()
            });
            
            // Keep max 5
            if (chat.pinnedMessages.length > 5) {
                chat.pinnedMessages = chat.pinnedMessages.slice(0, 5);
            }
            
            saveChats();
            renderPinnedMessages();
            renderMessages();
            closeMessageMenu();
        }
    } else {
        const data = await response.json();
        await showAlert(data.detail || 'Failed to pin message', 'Error', '❌');
    }
}

async function unpinMessage(messageId) {
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    const response = await api('/messages/' + messageId + '/unpin', {
        method: 'POST'
    });
    
    if (response.ok) {
        const message = chat.messages.find(m => m.id === messageId);
        if (message) message.is_pinned = false;
        
        // Remove from pinned list
        if (chat.pinnedMessages) {
            chat.pinnedMessages = chat.pinnedMessages.filter(p => p.id !== messageId);
        }
        
        saveChats();
        renderPinnedMessages();
        renderMessages();
    }
}

function renderPinnedMessages() {
    const container = document.getElementById('pinned-message');
    if (!container) return;
    
    const chat = state.chats[state.currentChatId];
    if (!chat || !chat.pinnedMessages || chat.pinnedMessages.length === 0) {
        container.classList.add('hidden');
        return;
    }
    
    // Show expandable pinned bar
    const count = chat.pinnedMessages.length;
    const firstPinned = chat.pinnedMessages[0];
    const firstPinnedText = escapeHtml((firstPinned.text || '').substring(0, 40));
    const ellipsis = firstPinned.text && firstPinned.text.length > 40 ? '...' : '';
    
    container.classList.remove('hidden');
    container.innerHTML = 
        '<div class="pinned-bar" onclick="togglePinnedExpanded()">' +
            '<div class="pinned-icon">📌</div>' +
            '<div class="pinned-info">' +
                '<div class="pinned-label">' + count + ' Pinned Message' + (count > 1 ? 's' : '') + '</div>' +
                '<div class="pinned-preview">' + firstPinnedText + ellipsis + '</div>' +
            '</div>' +
            '<div class="pinned-expand">▼</div>' +
        '</div>' +
        '<div class="pinned-list hidden">' +
            chat.pinnedMessages.map(msg => 
                '<div class="pinned-item" onclick="scrollToMessage(\'' + escapeJsString(msg.id) + '\')">' +
                    '<div class="pinned-item-text">' + escapeHtml((msg.text || '📎 File').substring(0, 60)) + '</div>' +
                    '<button class="pinned-item-unpin" onclick="event.stopPropagation(); unpinMessage(\'' + escapeJsString(msg.id) + '\')">✕</button>' +
                '</div>'
            ).join('') +
        '</div>';
}

function togglePinnedExpanded() {
    const list = document.querySelector('.pinned-list');
    const expand = document.querySelector('.pinned-expand');
    if (list && expand) {
        list.classList.toggle('hidden');
        expand.textContent = list.classList.contains('hidden') ? '▼' : '▲';
    }
}

function handleMessagePinned(payload) {
    const chatId = payload.chat_id;
    
    // Find which chat this belongs to
    let chat = state.chats[chatId] || state.chats['group_' + chatId];
    
    // For direct chats, chatId might be in format "uuid1_uuid2"
    if (!chat && chatId && chatId.includes('_')) {
        const parts = chatId.split('_');
        chat = state.chats[parts[0]] || state.chats[parts[1]];
    }
    
    if (chat) {
        // Reload pinned messages if this chat is open
        if (state.currentChatId === chatId || 
            state.currentChatId === 'group_' + chatId ||
            (chatId && chatId.includes('_') && chatId.includes(state.currentChatId))) {
            loadPinnedMessages();
        }
    }
}

function handleMessageUnpinned(payload) {
    const chatId = payload.chat_id;
    const messageId = payload.message_id;
    
    // Find which chat this belongs to
    let chat = state.chats[chatId] || state.chats['group_' + chatId];
    
    if (!chat && chatId && chatId.includes('_')) {
        const parts = chatId.split('_');
        chat = state.chats[parts[0]] || state.chats[parts[1]];
    }
    
    if (chat && chat.pinnedMessages) {
        chat.pinnedMessages = chat.pinnedMessages.filter(p => p.id !== messageId);
        
        const message = chat.messages && chat.messages.find(m => m.id === messageId);
        if (message) message.is_pinned = false;
        
        saveChats();
        
        // Update UI if this chat is open
        if (state.currentChatId === chatId || 
            state.currentChatId === 'group_' + chatId ||
            (chatId && chatId.includes('_') && chatId.includes(state.currentChatId))) {
            renderPinnedMessages();
            renderMessages();
        }
    }
}

function scrollToMessage(messageId) {
    const msgEl = document.querySelector('[data-message-id="' + messageId + '"]') || document.querySelector('.message[data-id="' + messageId + '"]');
    if (msgEl) {
        msgEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        msgEl.classList.add('highlight-message');
        setTimeout(() => msgEl.classList.remove('highlight-message'), 2000);
    }
}

// ==================== THEME / DARK MODE ====================

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'system';
    applyTheme(savedTheme);
    updateThemeUI(savedTheme);
}

function setTheme(theme) {
    localStorage.setItem('theme', theme);
    applyTheme(theme);
    updateThemeUI(theme);
    console.log('Theme set to:', theme);
}

function applyTheme(theme) {
    const html = document.documentElement;
    
    if (theme === 'system') {
        // Remove data-theme to let CSS media query handle it
        html.removeAttribute('data-theme');
    } else {
        html.setAttribute('data-theme', theme);
    }
}

function updateThemeUI(activeTheme) {
    const options = document.querySelectorAll('.theme-option');
    options.forEach(opt => {
        const optTheme = opt.getAttribute('data-theme');
        opt.classList.toggle('active', optTheme === activeTheme);
    });
}

function getEffectiveTheme() {
    const savedTheme = localStorage.getItem('theme') || 'system';
    if (savedTheme === 'system') {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return savedTheme;
}

// Listen for system theme changes
if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        const savedTheme = localStorage.getItem('theme') || 'system';
        if (savedTheme === 'system') {
            console.log('System theme changed to:', e.matches ? 'dark' : 'light');
            // CSS handles this automatically via media query, no JS needed
        }
    });
}

// ==================== END THEME / DARK MODE ====================

// ==================== DISAPPEARING MESSAGES ====================

function toggleDisappearingMenu() {
    const menu = document.getElementById('disappearing-menu');
    if (menu) {
        menu.classList.toggle('hidden');
        // Update selected state
        updateDisappearingMenuSelection();
    }
}

function setDisappearingTime(seconds) {
    state.disappearingTime = seconds;
    
    // Update button appearance
    const btn = document.getElementById('disappearing-btn');
    if (btn) {
        btn.classList.toggle('active', seconds > 0);
        btn.title = seconds > 0 ? formatDisappearingTime(seconds) : 'Disappearing messages off';
    }
    
    // Update placeholder
    const input = document.getElementById('message-text');
    if (input) {
        if (seconds > 0) {
            input.placeholder = 'Disappearing message (' + formatDisappearingTime(seconds) + ')...';
        } else {
            input.placeholder = 'Message...';
        }
    }
    
    // Close menu
    const menu = document.getElementById('disappearing-menu');
    if (menu) menu.classList.add('hidden');
    
    console.log('Disappearing time set to:', seconds, 'seconds');
}

function updateDisappearingMenuSelection() {
    const options = document.querySelectorAll('.disappearing-option');
    options.forEach(opt => {
        const time = parseInt(opt.getAttribute('data-time'));
        opt.classList.toggle('selected', time === state.disappearingTime);
    });
}

function formatDisappearingTime(seconds) {
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
    return Math.floor(seconds / 86400) + 'd';
}

// Close disappearing menu when clicking outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('disappearing-menu');
    const btn = document.getElementById('disappearing-btn');
    if (menu && !menu.contains(e.target) && e.target !== btn) {
        menu.classList.add('hidden');
    }
});

// ==================== END DISAPPEARING MESSAGES ====================

// WebRTC config - loaded dynamically from server
let rtcConfig = {
    iceServers: [
        { urls: "stun:stun.l.google.com:19302" }  // Fallback STUN only
    ],
    iceCandidatePoolSize: 10,
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
};

// Load ICE servers from backend (hides TURN credentials from client code)
async function loadIceServers() {
    try {
        const response = await api('/webrtc/ice-servers');
        if (response.ok) {
            const data = await response.json();
            if (data.enabled && data.ice_servers && data.ice_servers.length > 0) {
                rtcConfig.iceServers = data.ice_servers;
                console.log('ICE servers loaded from server:', rtcConfig.iceServers.length, 'servers');
            } else {
                console.log('TURN disabled or no ICE servers configured, using STUN only');
            }
        } else {
            console.log('TURN disabled or no ICE servers configured, using STUN only');
        }
    } catch (err) {
        console.warn('Failed to load ICE servers, using fallback STUN:', err.message);
    }
}

console.log('WebRTC config initialized (ICE servers will be loaded on call start)');

// Audio constraints with echo cancellation
// Safari-compatible constraints
const audioConstraints = {
    audio: {
        echoCancellation: { ideal: true },
        noiseSuppression: { ideal: true },
        autoGainControl: { ideal: true },
        sampleRate: { ideal: 48000 },
        channelCount: { ideal: 1 },
    },
    video: false
};

// Detect Safari/iOS
const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);

// API
async function api(endpoint, options = {}) {
    const headers = { ...options.headers };
    if (!options.isFormData) {
        headers['Content-Type'] = 'application/json';
    }
    if (state.token) headers['Authorization'] = 'Bearer ' + state.token;

    const response = await fetch(API_URL + endpoint, { ...options, headers });

    if (response.status === 401 && state.refreshToken) {
        const refreshed = await refreshTokens();
        if (refreshed === 'ok') {
            headers['Authorization'] = 'Bearer ' + state.token;
            return fetch(API_URL + endpoint, { ...options, headers });
        }
        // КАО#304: an unrecoverable session used to leave a zombie UI — it looked signed in while every
        // request 401'd and each caller showed its own vague message ("Search failed", "User not found").
        // КАО#326: but ONLY an explicit rejection is unrecoverable. The first version treated ANY falsy
        // result as terminal, so one 429 (this deployment rate-limits aggressively), a 5xx or a brief
        // network drop silently destroyed a perfectly valid 30-day session and dumped the user at login.
        if (refreshed === 'rejected') handleSessionExpired();
    }
    return response;
}

// КАО#304: end an unrecoverable session WITHOUT the destructive parts of logout().
// Deliberately does NOT call VibeCrypto.clearAll() — an expired token says nothing about the identity
// keys, and wiping them would make the user's entire message history undecryptable.
let _sessionExpiredHandled = false;
function handleSessionExpired() {
    if (_sessionExpiredHandled) return;   // one 401 storm ⇒ one prompt
    _sessionExpiredHandled = true;
    console.warn('[Auth] Session expired — refresh token rejected');
    try { if (state.ws) state.ws.close(); } catch (e) {}
    state.token = null;
    state.refreshToken = null;
    try { localStorage.removeItem('auth'); } catch (e) {}
    // КАО#327: showScreen() keys off the `screens` map ('auth' | 'chats' | 'chat' | 'settings'), NOT the
    // element id. Passing 'auth-screen' matched nothing, so it hid EVERY screen and left the whole app
    // blank — strictly worse than the zombie session it replaced.
    try { showScreen('auth'); } catch (e) {}
    const err = document.getElementById('auth-error');
    if (err) {
        err.textContent = 'Your session expired. Please sign in again.';
        err.classList.remove('hidden');
    }
}

// КАО#326: tri-state — 'ok' | 'rejected' (the server refused the refresh token: terminal) |
// 'transient' (rate limit / server error / network: the session may well still be valid, so keep it).
// КАО#366: single-flight. /auth/refresh ROTATES — it revokes the presented token and issues a new pair
// (auth_service.py) — so a second concurrent use of the same refresh token gets 401, which maps to the
// TERMINAL 'rejected' and calls handleSessionExpired(). Concurrent 401s are the normal case, not an edge
// one: an expired access token makes loadConversations/loadPendingMessages/loadMyGroups/loadPendingInvites
// 401 together (they run under one Promise.all), and the WS 4001 handler refreshes as well. So reopening
// the app after the 30-minute access-token TTL could log the user out of a perfectly valid 30-day session —
// and mint a pile of extra RefreshToken rows for the requests that did slip through before the first commit.
// Coalescing makes every concurrent caller await ONE rotation and observe the same result.
let _refreshInflight = null;
async function refreshTokens() {
    if (_refreshInflight) return _refreshInflight;
    _refreshInflight = (async () => {
        try {
            const response = await fetch(API_URL + '/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                // КАО#383: use the FRESHEST refresh token, not the one captured at page load. /auth/refresh
            // rotates, so when another tab refreshes first, this tab's in-memory copy is already revoked;
            // posting it returns 401, which maps to the terminal 'rejected' and kills a perfectly valid
            // session. state.refreshToken was only ever written by loadAuth() at startup and by our own
            // rotation, so nothing else could have picked up a sibling tab's newer pair.
            body: JSON.stringify({ refresh_token: _freshestRefreshToken() }),
            });
            if (response.ok) {
                const data = await response.json();
                state.token = data.access_token;
                state.refreshToken = data.refresh_token;
                saveAuth();
                return 'ok';
            }
            return (response.status === 401 || response.status === 403) ? 'rejected' : 'transient';
        } catch (e) {
            console.error('Refresh failed (transient):', e);
            return 'transient';
        }
    })();
    // Always release the latch, including on a transient failure — otherwise one network blip would
    // permanently pin every later caller to that stale result.
    try { return await _refreshInflight; } finally { _refreshInflight = null; }
}

// Auth
async function register() {
    const username = document.getElementById('reg-username').value.trim();
    const displayName = document.getElementById('reg-display-name').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;

    // Validate username
    if (!username) return showError('Username is required');
    if (username.length < 3) return showError('Username must be at least 3 characters');
    if (username.length > 50) return showError('Username must be at most 50 characters');
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) return showError('Username can only contain letters, numbers, underscores and hyphens');
    
    // Validate display name
    if (displayName && displayName.length > 100) return showError('Display name must be at most 100 characters');
    
    // Validate password
    if (!password) return showError('Password is required');
    if (password.length < 8) return showError('Password must be at least 8 characters');
    if (!/[A-Z]/.test(password)) return showError('Password must contain at least one uppercase letter');
    if (!/[a-z]/.test(password)) return showError('Password must contain at least one lowercase letter');
    if (!/[0-9]/.test(password)) return showError('Password must contain at least one number');
    
    if (password !== confirm) return showError('Passwords do not match');

    try {
        const response = await api('/auth/register', {
            method: 'POST',
            body: JSON.stringify({ username, password, display_name: displayName || undefined }),
        });
        const data = await response.json();
        if (response.ok) handleAuthSuccess(data);
        else showError(data.detail || data.error || 'Registration failed');
    } catch (e) { showError('Network error'); }
}

async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) return showError('Enter username and password');

    try {
        const response = await api('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
        });
        const data = await response.json();
        
        if (response.ok) {
            handleAuthSuccess(data);
        // КАО#317: the server's custom exception handler returns {"error": ...}, not FastAPI's {"detail": ...},
        // so this only ever matched on paper — a user with 2FA enabled was told "invalid credentials"
        // instead of being asked for the code, i.e. could not sign in at all. Accept either field.
        } else if (response.status === 403 && (data.error || data.detail) === 'TOTP code required') {
            // 2FA is enabled, show TOTP modal
            showTOTPLoginModal(username, password, null);
        } else {
            showError(data.error || data.detail || 'Invalid credentials');
        }
    } catch (e) { showError('Network error'); }
}

async function handleAuthSuccess(data) {
    // КАО#329: re-arm the one-shot session-expiry guard. It latched forever, so after the FIRST expiry a
    // later one in the same page load did nothing — leaving exactly the zombie session КАО#304 removed.
    _sessionExpiredHandled = false;

    // КАО#370 (critical): bind the retained E2EE identity to the account that owns it.
    // handleSessionExpired() deliberately keeps the identity keys (КАО#325 — correct when the SAME user
    // comes back) but clears neither state.user nor state.chats, and NOTHING tied that key material to a
    // user id: hasKeys() is a bare `!!identityKeyPair` and ensureSelfEncryptionKey() short-circuits on the
    // localStorage copy. It shows the auth screen IN PLACE, so signing in as somebody else right after an
    // expiry is the ordinary flow — and then the next account silently operated with the previous user's
    // private identity key and self-encryption key (so its encrypted_for_self copies were sealed with a key
    // the former user also holds), while loadChats() found no `chats_<newId>` and therefore left the
    // previous user's DECRYPTED chat cache in state.chats — rendered to the new user and then persisted
    // under their id by saveChats(). One choke point fixes both halves.
    // Absent tag ⇒ ADOPT, never wipe: existing installs must not lose their keys on the first login after
    // this update. Only a tag that EXISTS and DIFFERS triggers the wipe.
    const _newOwner = (data.user && data.user.id != null) ? String(data.user.id) : null;
    let _prevOwner = null;
    try { _prevOwner = localStorage.getItem('vibe_key_owner'); } catch (e) {}
    if (_prevOwner && _newOwner && _prevOwner !== _newOwner) {
        console.warn('[E2EE] different account on this browser — clearing the previous identity and cache');
        state.chats = {};
        state.currentChat = null;
        state.currentChatId = null;
        state.keyBundles = {};
        state.e2eeReady = false;
        try {
            // init() FIRST: on a fresh page load the IndexedDB handle is not open yet and clearAll() would
            // throw — which, swallowed, would leave the new user running on the old user's keys.
            await VibeCrypto.init();
            await VibeCrypto.clearAll();
        } catch (e) {
            // Fail CLOSED. Completing this login would mean this account uses another account's identity
            // key. Leave the owner tag untouched so a retry re-attempts the wipe.
            console.error('[E2EE] could not clear the previous account, aborting sign-in:', e);
            showError('Could not clear the previous account’s data. Please reload the page and try again.');
            state.token = null;
            state.refreshToken = null;
            try { showScreen('auth'); } catch (e2) {}
            return;
        }
    }
    if (_newOwner) { try { localStorage.setItem('vibe_key_owner', _newOwner); } catch (e) {} }

    state.user = data.user;
    state.token = data.tokens.access_token;
    state.refreshToken = data.tokens.refresh_token;
    saveAuth();
    initOfflineMode();
    
    // Initialize E2EE
    await initE2EE();
    
    connectWebSocket();
    showScreen('chats');
    loadChats();
    loadFavoriteMessageIds();  // v3.8.37: Load favorite IDs for star indicator
    loadUserPermissions();
    initPushNotifications();
    initPullToRefresh();
    initMentions();
    updateSoundButton();
    
    // v3.11.8: Apply screenshot protection if enabled
    applyScreenshotProtection();
    
    // v3.10.0: Initialize biometric authentication
    if (typeof BiometricAuth !== 'undefined') {
        BiometricAuth.rememberUsername(data.user.username);
        BiometricAuth.init();
    }
}

/**
 * Initialize E2EE system
 */
async function initE2EE() {
    try {
        console.log('[E2EE] Initializing...');
        await VibeCrypto.init();
        
        if (!VibeCrypto.hasKeys()) {
            // First time - generate keys and upload to server
            console.log('[E2EE] No keys found, generating new key bundle...');
            const bundle = await VibeCrypto.generateKeyBundle(100);
            
            // Upload to server
            const response = await api('/keys/bundle', {
                method: 'POST',
                body: JSON.stringify(bundle)
            });
            
            if (response.ok) {
                console.log('[E2EE] Key bundle uploaded successfully');
            } else {
                console.error('[E2EE] Failed to upload key bundle');
            }
        } else {
            console.log('[E2EE] Keys loaded from storage');
            
            // Check if we need to replenish pre-keys
            const newPreKeys = await VibeCrypto.checkAndReplenishPreKeys(10, 50);
            if (newPreKeys) {
                console.log('[E2EE] Replenishing', newPreKeys.length, 'pre-keys');
                await api('/keys/bundle/prekeys', {
                    method: 'POST',
                    body: JSON.stringify(newPreKeys)
                });
            }
        }
        
        // v3.7.27: Ensure self-encryption key exists for multi-device sync
        await VibeCrypto.ensureSelfEncryptionKey(api);
        console.log('[E2EE] Self-encryption key ready:', VibeCrypto.hasSelfEncryptionKey());
        
        state.e2eeReady = true;
        console.log('[E2EE] Ready');
        
        // v3.7.0: Load known identity keys and check SPK rotation
        await loadKnownIdentityKeys();
        await checkSignedPreKeyRotation();
        
    } catch (e) {
        console.error('[E2EE] Initialization failed:', e);
        state.e2eeReady = false;
    }
}

/**
 * Reset E2EE completely - clear all data and regenerate keys
 * Call this from browser console: resetE2EE()
 */
async function resetE2EE() {
    try {
        console.log('[E2EE] Starting full reset...');
        
        // Clear all crypto data
        await VibeCrypto.clearAll();
        console.log('[E2EE] Cleared all crypto data');
        
        // v3.7.27: Clear self-encryption key from localStorage
        localStorage.removeItem('vibe_self_encryption_key');
        console.log('[E2EE] Cleared self-encryption key');
        
        // v3.8.58: Mark that we just reset keys (for showing banner to initiator)
        localStorage.setItem('vibe_keys_just_reset', Date.now().toString());
        console.log('[E2EE] Set keys_just_reset flag');
        
        // v3.11.6: Store per-contact reset timestamps for system message positioning
        const resetNow = Date.now().toString();
        Object.keys(state.chats || {}).forEach(cid => {
            if (state.chats[cid] && !state.chats[cid].isGroup) {
                localStorage.setItem('vibe_key_reset_time_' + cid, resetNow);
            }
        });
        
        // v3.8.54: Clear ALL verification statuses (our keys changed, need to re-verify everyone)
        if (typeof VibeCryptoVerification !== 'undefined') {
            localStorage.removeItem('vibe_verified_keys');
            console.log('[E2EE] Cleared all verification statuses');
        }
        
        // v3.8.56: Clear knownIdentityKeys from IndexedDB (need to re-verify all contacts)
        if (offlineDB && offlineDB.db && offlineDB.db.objectStoreNames.contains('knownIdentityKeys')) {
            try {
                const tx = offlineDB.db.transaction('knownIdentityKeys', 'readwrite');
                const store = tx.objectStore('knownIdentityKeys');
                await new Promise((resolve, reject) => {
                    const request = store.clear();
                    request.onsuccess = () => resolve();
                    request.onerror = () => reject(request.error);
                });
                // Also clear in-memory cache
                Object.keys(knownIdentityKeys).forEach(k => delete knownIdentityKeys[k]);
                console.log('[E2EE] Cleared known identity keys');
            } catch (e) {
                console.warn('[E2EE] Failed to clear known identity keys:', e);
            }
        }
        
        // Clear decrypted messages cache
        if (offlineDB && offlineDB.db) {
            const tx = offlineDB.db.transaction(['decryptedMessages'], 'readwrite');
            const store = tx.objectStore('decryptedMessages');
            await new Promise((resolve, reject) => {
                const request = store.clear();
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });
            console.log('[E2EE] Cleared decrypted messages cache');
        }
        
        // Generate new keys
        console.log('[E2EE] Generating new key bundle...');
        const bundle = await VibeCrypto.generateKeyBundle(100);
        
        // Upload to server
        const response = await api('/keys/bundle', {
            method: 'POST',
            body: JSON.stringify(bundle)
        });
        
        if (response.ok) {
            console.log('[E2EE] New key bundle uploaded successfully');
            
            // v3.8.6: Notify contacts about key reset
            try {
                const notifyResponse = await api('/keys/reset', { method: 'POST' });
                if (notifyResponse.ok) {
                    const result = await notifyResponse.json();
                    console.log('[E2EE] Contacts notified:', result.contacts_notified, 'of', result.contacts_found);
                }
            } catch (e) {
                console.warn('[E2EE] Failed to notify contacts about key reset:', e);
            }
            
            console.log('[E2EE] Reset complete!');
        } else {
            console.error('[E2EE] Failed to upload new key bundle');
        }

        // v3.7.27: Ensure new self-encryption key
        await VibeCrypto.ensureSelfEncryptionKey(api);
        
        state.e2eeReady = true;
        return true;
    } catch (e) {
        console.error('[E2EE] Reset failed:', e);
        return false;
    }
}

// Expose resetE2EE globally for console access
window.resetE2EE = resetE2EE;

// Reset E2EE with confirmation (for UI button)
async function resetE2EEWithConfirm() {
    // v3.10.0: Step-up biometric verification for this sensitive action
    if (typeof BiometricAuth !== 'undefined') {
        const verified = await BiometricAuth.requireVerification('Confirm identity to reset E2EE keys');
        if (!verified) return;
    }
    
    // Step 1: Explain and ask for backup password
    const backupPassword = await showBackupPasswordDialog();
    
    if (backupPassword === null) {
        // User cancelled
        return;
    }
    
    // Step 2: Create backup before reset
    let backupSuccess = false;
    let backupError = null;
    
    if (backupPassword) {
        try {
            showLoadingOverlay('Creating backup...');
            const backupResult = await AccountBackup.createBackup(backupPassword);
            backupSuccess = backupResult.success;
            if (!backupSuccess) {
                backupError = backupResult.error;
            }
        } catch (e) {
            backupError = e.message;
        } finally {
            hideLoadingOverlay();
        }
    }
    
    // Step 3: Handle backup result
    if (!backupSuccess) {
        // Backup failed or skipped - warn user
        const warningMessage = backupError 
            ? `Backup failed: ${backupError}\n\nIf you continue, all old messages will be PERMANENTLY LOST.`
            : 'No backup created. If you continue, all old messages will be PERMANENTLY LOST.';
        
        const proceedAnyway = await showConfirm(
            warningMessage,
            "⚠️ Continue without backup?",
            "Reset anyway",
            "Cancel"
        );
        
        if (!proceedAnyway) {
            return;
        }
    } else {
        // Backup successful - confirm reset
        const confirmed = await showConfirm(
            "Backup created successfully.\n\nProceed with E2EE reset? You can restore messages from backup after reset.",
            "Reset E2EE Keys?",
            "Reset",
            "Cancel"
        );
        
        if (!confirmed) {
            return;
        }
    }
    
    // Step 4: Perform reset
    showLoadingOverlay('Resetting E2EE keys...');
    try {
        await resetE2EE();
        hideLoadingOverlay();
        
        const successMessage = backupSuccess
            ? "E2EE keys reset. Use Settings → Account Backup → Restore to recover your messages."
            : "E2EE keys reset. Old messages are lost (no backup).";
        
        await showAlert(successMessage, "Keys Reset", "✓");
        location.reload();
    } catch (e) {
        hideLoadingOverlay();
        await showAlert("Reset failed: " + e.message, "Error", "✗");
    }
}

/**
 * Show dialog asking for backup password before E2EE reset
 * @returns {Promise<string|null>} Password string, empty string (skip backup), or null (cancel)
 */
async function showBackupPasswordDialog() {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal-content backup-before-reset-modal">
                <h3>🔐 Reset E2EE Keys</h3>
                <p class="modal-description">
                    Before resetting, we recommend creating a backup to preserve your message history.
                </p>
                <div class="form-group">
                    <label for="reset-backup-password">Backup password (min 8 characters):</label>
                    <input type="password" id="reset-backup-password" placeholder="Enter backup password" autocomplete="new-password">
                </div>
                <div class="modal-note">
                    <small>💡 After reset, restore this backup to recover all messages.</small>
                </div>
                <div class="modal-buttons">
                    <button class="btn btn-secondary" id="reset-cancel-btn">Cancel</button>
                    <button class="btn btn-warning" id="reset-skip-btn">Skip backup</button>
                    <button class="btn btn-primary" id="reset-backup-btn">Create backup & reset</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        const passwordInput = modal.querySelector('#reset-backup-password');
        const cancelBtn = modal.querySelector('#reset-cancel-btn');
        const skipBtn = modal.querySelector('#reset-skip-btn');
        const backupBtn = modal.querySelector('#reset-backup-btn');
        
        passwordInput.focus();
        
        const cleanup = () => {
            modal.remove();
        };
        
        cancelBtn.onclick = () => {
            cleanup();
            resolve(null);
        };
        
        skipBtn.onclick = () => {
            cleanup();
            resolve('');  // Empty string = skip backup
        };
        
        backupBtn.onclick = () => {
            const password = passwordInput.value;
            if (password.length < 8) {
                passwordInput.classList.add('error');
                passwordInput.placeholder = 'Minimum 8 characters!';
                passwordInput.value = '';
                passwordInput.focus();
                return;
            }
            cleanup();
            resolve(password);
        };
        
        passwordInput.onkeydown = (e) => {
            if (e.key === 'Enter') {
                backupBtn.click();
            } else if (e.key === 'Escape') {
                cancelBtn.click();
            }
        };
        
        modal.onclick = (e) => {
            if (e.target === modal) {
                cancelBtn.click();
            }
        };
    });
}

/**
 * Show loading overlay
 */
function showLoadingOverlay(message = 'Loading...') {
    let overlay = document.getElementById('loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-content">
                <div class="spinner"></div>
                <div class="loading-message"></div>
            </div>
        `;
        document.body.appendChild(overlay);
    }
    overlay.querySelector('.loading-message').textContent = message;
    overlay.classList.add('visible');
}

/**
 * Hide loading overlay
 */
function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.classList.remove('visible');
    }
}

/**
 * Fetch recipient's key bundle from server
 */
async function fetchKeyBundle(recipientId) {
    // Check cache first
    if (state.keyBundles[recipientId]) {
        return state.keyBundles[recipientId];
    }
    
    try {
        const response = await api('/keys/bundle/' + recipientId);
        if (response.ok) {
            const bundle = await response.json();
            state.keyBundles[recipientId] = bundle;
            return bundle;
        }
    } catch (e) {
        console.error('[E2EE] Failed to fetch key bundle for', recipientId, e);
    }
    return null;
}

async function loadUserPermissions() {
    try {
        const response = await api('/auth/me/permissions');
        if (response.ok) {
            state.permissions = await response.json();
            console.log('User permissions loaded:', state.permissions);
        }
    } catch (e) {
        console.error('Failed to load permissions:', e);
    }
    
    // Also refresh user data (including avatar_url)
    try {
        const response = await api('/auth/me');
        if (response.ok) {
            const userData = await response.json();
            // Update avatar_url if changed
            if (userData.avatar_url !== state.user.avatar_url) {
                state.user.avatar_url = userData.avatar_url;
                saveAuth();
            }
        }
    } catch (e) {
        console.error('Failed to refresh user data:', e);
    }
}

async function logout() {
    // v3.7.2: Call server to revoke refresh token
    if (state.token && state.refreshToken) {
        try {
            await api("/auth/logout", {
                method: "POST",
                body: JSON.stringify({ refresh_token: state.refreshToken })
            });
            console.log("[Auth] Server logout successful");
        } catch (e) {
            console.error("[Auth] Server logout failed:", e);
        }
    }
    
    // Clear E2EE data
    if (state.e2eeReady) {
        try {
            await VibeCrypto.clearAll();
            console.log('[E2EE] Cleared all crypto data');
        } catch (e) {
            console.error('[E2EE] Error clearing crypto data:', e);
        }
    }
    state.e2eeReady = false;
    state.keyBundles = {};
    
    state.user = null;
    state.token = null;
    state.refreshToken = null;
    state.chats = {};
    state.currentChat = null;
    state.currentChatId = null;
    if (state.pingInterval) clearInterval(state.pingInterval);
    if (state.ws) state.ws.close();
    localStorage.removeItem('auth');
    // Keep chats in localStorage - they will be loaded on next login
    showScreen('auth');
}

function saveAuth() {
    localStorage.setItem('auth', JSON.stringify({
        user: state.user,
        token: state.token,
        refreshToken: state.refreshToken,
    }));
}

// КАО#383: cross-tab token freshness.
// Only safe now that КАО#370 binds the E2EE identity to a user id - before that, adopting another tab's
// 'auth' blob could have dragged in a DIFFERENT account's session. Both helpers therefore refuse a blob
// belonging to anyone but the user this tab is signed in as.
function _freshestRefreshToken() {
    try {
        const saved = JSON.parse(localStorage.getItem('auth') || 'null');
        if (saved && saved.refreshToken && saved.user && state.user &&
            String(saved.user.id) === String(state.user.id)) {
            if (saved.refreshToken !== state.refreshToken) {
                console.log('[Auth] КАО#383: adopting a refresh token rotated in another tab');
                state.token = saved.token || state.token;
                state.refreshToken = saved.refreshToken;
            }
        }
    } catch (e) {}
    return state.refreshToken;
}

// Adopt a rotation the moment a sibling tab performs one, so this tab never even attempts the dead token.
// 'storage' only fires in OTHER tabs, never the one that wrote - exactly the semantics wanted here.
try {
    window.addEventListener('storage', (e) => {
        if (e.key !== 'auth' || !e.newValue) return;
        try {
            const d = JSON.parse(e.newValue);
            if (!d || !d.user || !state.user || String(d.user.id) !== String(state.user.id)) return;
            if (d.refreshToken && d.refreshToken !== state.refreshToken) {
                state.token = d.token || state.token;
                state.refreshToken = d.refreshToken;
                console.log('[Auth] КАО#383: picked up a token pair rotated in another tab');
            }
        } catch (err) {}
    });
} catch (e) {}

function loadAuth() {
    const saved = localStorage.getItem('auth');
    if (saved) {
        const data = JSON.parse(saved);
        state.user = data.user;
        state.token = data.token;
        state.refreshToken = data.refreshToken;
        return true;
    }
    return false;
}

// WebSocket
function connectWebSocket() {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
        return;
    }
    if (state.ws) {
        state.ws.close();
    }
    if (state.pingInterval) {
        clearInterval(state.pingInterval);
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = wsProtocol + '//' + window.location.host + '/ws';
    
    // Pass token via Sec-WebSocket-Protocol header instead of URL query param
    // This prevents token from appearing in server access logs
    state.ws = new WebSocket(wsUrl, ['access_token', 'Bearer.' + state.token]);

    state.ws.onopen = () => {
        console.log('WS connected');
        state.wsReconnectAttempts = 0;  // КАО#121: reset backoff on successful connect
        updateConnectionStatus('connected');

        // Load list of online users
        loadOnlineUsers();

        // КАО#270 (#8) Round-2: pull messages that arrived while the socket was down — but ONLY on a
        // RECONNECT. The INITIAL connect's pending fetch is already done by the login/init path (loadChats);
        // running both concurrently would double-decrypt the same still-PENDING DMs (the server marks
        // delivery only on a later ACK) and corrupt the stateful Double Ratchet.
        if (state.wsHasConnected) {
            loadPendingMessages();
        }
        state.wsHasConnected = true;

        state.pingInterval = setInterval(() => {
            if (state.ws && state.ws.readyState === WebSocket.OPEN) {
                state.ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 20000);
    };

    state.ws.onclose = async (event) => {
        console.log('WS disconnected, code:', event.code);
        updateConnectionStatus('disconnected');
        if (state.pingInterval) clearInterval(state.pingInterval);
        
        // If closed due to auth error (4001), try to refresh token first
        if (event.code === 4001 && state.refreshToken) {
            console.log('WS auth failed, refreshing token...');
            const refreshed = await refreshTokens();
            if (refreshed === 'ok') {
                console.log('Token refreshed, reconnecting WS...');
                setTimeout(connectWebSocket, 500);
                return;
            }
            if (refreshed === 'rejected') {
                // КАО#325 (critical): this used to call logout(), which runs VibeCrypto.clearAll() and
                // DESTROYS the identity keys — so an ordinary expired session permanently made the
                // user's whole message history undecryptable. Session state is not key material.
                console.log('Refresh token rejected — ending session without touching E2EE keys');
                handleSessionExpired();
                return;
            }
            // КАО#326: 'transient' (429/5xx/offline) — keep the session and fall through to the normal
            // backoff reconnect below instead of tearing anything down.
            console.log('Token refresh transiently failed — will retry with backoff');
        }
        
        // Normal reconnect — КАО#121: exponential backoff (was fixed 3s) to avoid reconnect storms
        state.wsReconnectAttempts = (state.wsReconnectAttempts || 0) + 1;
        const _wsDelay = Math.min(3000 * Math.pow(2, state.wsReconnectAttempts - 1), 30000);
        setTimeout(() => {
            if (state.token && (!state.ws || state.ws.readyState === WebSocket.CLOSED)) {
                connectWebSocket();
            }
        }, _wsDelay);
    };

    state.ws.onerror = (err) => {
        console.error('WS error:', err);
    };

    state.ws.onmessage = (event) => {
        // КАО#121: guard JSON.parse so one malformed frame doesn't kill the handler
        let msg;
        try { msg = JSON.parse(event.data); } catch (e) { console.error('[WS] bad frame', e); return; }
        handleWSMessage(msg);
    };
}

function sendWS(type, payload) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
        state.ws.send(JSON.stringify({ type, payload }));
    }
}

function handleWSMessage(msg) {
    console.log('WS received:', msg.type);
    if (msg.type === 'pong') {
        // Pong received
    } else if (msg.type === 'new_message') {
        handleNewMessage(msg.payload);
        // v3.6.0: Check mute AND block before playing sound
        const chatId = msg.payload.group_id ? 'group_' + msg.payload.group_id : msg.payload.sender_id;
        const senderId = msg.payload.sender_id;
        if (typeof isChatMuted === 'function' && isChatMuted(chatId)) {
            // Chat is muted, don't play sound
        } else if (typeof isUserBlocked === 'function' && isUserBlocked(senderId)) {
            // User is blocked, don't play sound
        } else {
            playNotificationSound();
        }
    } else if (msg.type === 'message_sent') {
        console.log('[Multi-device] message_sent received:', msg.payload);
        console.log('[Multi-device] client_message_id:', msg.payload.client_message_id);
        console.log('[Multi-device] message object present:', !!msg.payload.message);
        
        // v3.7.1: Multi-device sync - check if this device sent the message
        const localMsg = findMessageByClientId(msg.payload.client_message_id);
        console.log('[Multi-device] Local message found:', !!localMsg);
        
        if (localMsg) {
            // This device sent the message - just update status
            console.log('[Multi-device] Updating local message status');
            updateMessageWithServerId(msg.payload.client_message_id, msg.payload.message_id, msg.payload.status);
        } else if (msg.payload.message) {
            // Another device sent the message - add to UI
            console.log('[Multi-device] Processing message from other device');
            // v3.7.27: Wrap in try-catch to ensure errors are visible
            handleOwnMessageFromOtherDevice(msg.payload.message).catch(e => {
                console.error('[Multi-device] Error in handleOwnMessageFromOtherDevice:', e);
            });
        } else {
            console.warn('[Multi-device] No message object in payload!');
        }
    } else if (msg.type === 'message_status') {
        handleMessageStatusUpdate(msg.payload);
    } else if (msg.type === 'message_deleted') {
        handleMessageDeleted(msg.payload);
    } else if (msg.type === 'message_edited') {
        handleMessageEdited(msg.payload);
    } else if (msg.type === 'user_online') {
        console.log('User online:', msg.payload.user_id);
        handleUserOnlineStatus(msg.payload.user_id, true);
    } else if (msg.type === 'user_offline') {
        console.log('User offline:', msg.payload.user_id);
        handleUserOnlineStatus(msg.payload.user_id, false);
    } else if (msg.type === 'user_typing') {
        handleUserTyping(msg.payload);
    } else if (msg.type === 'call_offer') {
        handleIncomingCall(msg.payload);
        playCallSound();
    } else if (msg.type === 'call_answer') {
        handleCallAnswer(msg.payload);
    } else if (msg.type === 'ice_candidate') {
        handleIceCandidate(msg.payload);
    } else if (msg.type === 'call_end') {
        handleCallEnded(msg.payload);
    } else if (msg.type === 'message_reaction') {
        handleMessageReaction(msg.payload);
    } else if (msg.type === 'poll_update') {
        handlePollUpdate(msg.payload);
    } else if (msg.type === 'low_prekeys') {
        handleLowPrekeys(msg.payload);
    } else if (msg.type === 'key_reset') {
        handleKeyReset(msg.payload);
    }
}

// Online status handling
function handleUserOnlineStatus(userId, isOnline) {
    console.log('handleUserOnlineStatus:', userId, isOnline);
    state.onlineUsers[userId] = isOnline;
    
    // Update UI if this is the current chat
    if (state.currentChatId === userId) {
        console.log('Updating chat header status to:', isOnline);
        updateChatHeaderStatus(isOnline);
    }
    
    // Update chats list
    renderChatsList();
}

function updateChatHeaderStatus(isOnline) {
    const statusEl = document.getElementById('chat-status');
    if (statusEl) {
        statusEl.textContent = isOnline ? 'online' : 'offline';
        statusEl.className = 'user-status ' + (isOnline ? 'online' : 'offline');
    }
}

function updateChatHeaderAvatar(chat) {
    const avatarLetter = document.getElementById('chat-header-avatar');
    const avatarImg = document.getElementById('chat-header-avatar-img');
    
    if (!avatarLetter || !avatarImg) return;
    
    const displayName = chat.displayName || chat.name || chat.username || '?';
    const isGroup = chat.isGroup;
    
    if (chat.avatar_url) {
        avatarImg.src = chat.avatar_url;
        avatarImg.classList.remove('hidden');
        avatarLetter.classList.add('hidden');
    } else {
        avatarLetter.textContent = isGroup ? (chat.isChannel ? '📢' : '👥') : displayName[0].toUpperCase();
        avatarLetter.classList.remove('hidden');
        avatarImg.classList.add('hidden');
    }
}

/**
 * Update E2EE indicator in chat header
 */
function updateE2EEIndicator() {
    const indicator = document.getElementById('e2ee-indicator');
    if (!indicator) return;
    
    if (state.e2eeReady) {
        indicator.classList.remove('hidden');
        indicator.title = 'End-to-end encrypted';
    } else {
        indicator.classList.add('hidden');
    }
}

async function checkUserOnline(userId) {
    try {
        console.log('Checking online status for:', userId);
        const response = await api('/auth/user/' + userId + '/online');
        if (response.ok) {
            const data = await response.json();
            console.log('Server says user', userId, 'is', data.online ? 'online' : 'offline');
            state.onlineUsers[userId] = data.online;
            return data.online;
        } else {
            console.log('Online status check failed with status:', response.status);
        }
    } catch (e) {
        console.error('Failed to check online status:', e);
    }
    return false;
}

// Load all online users from server
async function loadOnlineUsers() {
    try {
        console.log('Loading online users...');
        const response = await api('/auth/users/online');
        if (response.ok) {
            const data = await response.json();
            console.log('Online users:', data.online_users);
            // Reset and set fresh data
            state.onlineUsers = {};
            data.online_users.forEach(userId => {
                state.onlineUsers[userId] = true;
            });
            // Update UI
            renderChatsList();
        }
    } catch (e) {
        console.error('Failed to load online users:', e);
    }
}

// Status polling for current chat
var statusPollingInterval = null;

function startStatusPolling(userId) {
    stopStatusPolling();
    
    // Poll every 15 seconds
    statusPollingInterval = setInterval(async () => {
        if (state.currentChatId === userId) {
            const online = await checkUserOnline(userId);
            updateChatHeaderStatus(online);
        } else {
            stopStatusPolling();
        }
    }, 15000);
}

function stopStatusPolling() {
    if (statusPollingInterval) {
        clearInterval(statusPollingInterval);
        statusPollingInterval = null;
    }
}

// Permission error display
function showPermissionError(message) {
    // Translate common messages to Russian
    const translations = {
        'You are not allowed to send text messages': 'Messaging is disabled by the administrator',
        'You are not allowed to send files': 'File sending is disabled by the administrator',
        'You are not allowed to send voice messages': 'Voice messages are disabled by the administrator',
        'You are not allowed to make calls': 'Voice calls are disabled by the administrator',
    };
    
    const displayMessage = translations[message] || message;
    
    // Show toast notification
    const toast = document.createElement('div');
    toast.className = 'permission-toast';
    toast.textContent = displayMessage;
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.add('visible'), 10);
    
    // Remove after 4 seconds
    setTimeout(() => {
        toast.classList.remove('visible');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// System notification (for admin actions, etc.)
function showSystemNotification(message) {
    if (typeof announceA11y === 'function') announceA11y(message);  // КАО#282 (#14)
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'system-notification-overlay';
    
    const modal = document.createElement('div');
    modal.className = 'system-notification-modal';
    modal.innerHTML = 
        '<div class="system-notification-icon">ℹ️</div>' +
        '<div class="system-notification-title">Notification</div>' +
        '<div class="system-notification-message">' + escapeHtml(message) + '</div>' +
        '<button class="system-notification-btn">OK</button>';
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Animate in
    setTimeout(() => overlay.classList.add('visible'), 10);
    
    // Close on button click
    modal.querySelector('.system-notification-btn').onclick = () => {
        overlay.dataset.dismissing = '1';  // КАО#344: exclude from topmostOverlay() while it fades out
        overlay.classList.remove('visible');
        setTimeout(() => overlay.remove(), 300);
    };
    
    // Close on overlay click
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.dataset.dismissing = '1';  // КАО#344
            overlay.classList.remove('visible');
            setTimeout(() => overlay.remove(), 300);
        }
    };
}

// Admin notification (from administrator)
function showAdminNotification(message) {
    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'system-notification-overlay';
    
    const modal = document.createElement('div');
    modal.className = 'system-notification-modal';
    modal.innerHTML = 
        '<div class="system-notification-icon">📢</div>' +
        '<div class="system-notification-title">Notification from Admin</div>' +
        '<div class="system-notification-message">' + escapeHtml(message) + '</div>' +
        '<button class="system-notification-btn">OK</button>';
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Animate in
    setTimeout(() => overlay.classList.add('visible'), 10);
    
    // Close on button click
    modal.querySelector('.system-notification-btn').onclick = () => {
        overlay.dataset.dismissing = '1';  // КАО#344: exclude from topmostOverlay() while it fades out
        overlay.classList.remove('visible');
        setTimeout(() => overlay.remove(), 300);
    };
    
    // Close on overlay click
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.dataset.dismissing = '1';  // КАО#344
            overlay.classList.remove('visible');
            setTimeout(() => overlay.remove(), 300);
        }
    };
}

// Messages
async function sendMessage() {
    const input = document.getElementById('message-text');
    const text = input.value.trim();
    if (!text || !state.currentChatId) return;

    // Check text permission
    if (state.permissions && !state.permissions.can_send_text) {
        showPermissionError('You are not allowed to send text messages');
        return;
    }

    const chat = state.chats[state.currentChatId];
    const isGroup = chat && chat.isGroup;

    // v3.8.6: Pre-check E2EE availability for 1:1 chats
    let forceUnencrypted = false;
    if (!isGroup && state.e2eeReady) {
        const recipientId = state.currentChatId;
        const canEncrypt = await checkCanEncrypt(recipientId);
        if (!canEncrypt) {
            const recipientName = chat?.displayName || chat?.username || recipientId;
            const confirmed = await showUnencryptedConfirmDialog(recipientName);
            if (!confirmed) {
                return; // User cancelled
            }
            forceUnencrypted = true;
        }
    }

    const messageId = 'msg_' + Date.now();
    
    // Calculate expires_at for UI
    let expiresAt = null;
    if (state.disappearingTime > 0) {
        expiresAt = new Date(Date.now() + state.disappearingTime * 1000).toISOString();
    }
    
    const message = {
        id: messageId,
        text: text,
        sender_id: state.user.id,
        created_at: new Date().toISOString(),
        status: state.isOnline ? 'sending' : 'queued',
        expires_at: expiresAt,
        reply_to_id: state.replyToMessage ? state.replyToMessage.id : null,
        reactions: [],
    };

    addMessageToUI(message);
    input.value = '';
    clearMarkdownPreview();
    
    // v3.6.0: Clear draft after sending
    if (typeof clearDraft === 'function') {
        clearDraft(state.currentChatId);
    }
    
    // Clear reply state
    const replyToId = state.replyToMessage ? state.replyToMessage.id : null;
    cancelReply();

    // E2EE: Encrypt message
    let encryptedPayload;
    let senderKeyDistribution = null;
    let isE2EEEncrypted = false;  // v3.8.6: Track if message was E2EE encrypted

    // v3.11.10: Channels skip E2EE, use plain base64
    if (isChannelChat()) {
        encryptedPayload = btoa(unescape(encodeURIComponent(text)));
        isE2EEEncrypted = false;
    } else
    try {
        // v3.8.6: Skip encryption if user confirmed unencrypted send
        if (forceUnencrypted) {
            console.log('[E2EE] User confirmed unencrypted send');
            encryptedPayload = btoa(unescape(encodeURIComponent(text)));
            isE2EEEncrypted = false;
        } else if (state.e2eeReady) {
            if (isGroup) {
                // Group encryption with Sender Keys
                const groupId = chat.id;
                const result = await VibeCrypto.encryptGroupMessage(groupId, text);
                encryptedPayload = result.payload;
                senderKeyDistribution = result.distribution;
                isE2EEEncrypted = true;
            } else {
                // 1:1 encryption with Double Ratchet
                const recipientId = state.currentChatId;
                // Check if we need to fetch key bundle
                let keyBundle = null;
                try {
                    // Try encrypting with existing session
                    encryptedPayload = await VibeCrypto.encryptMessage(recipientId, text);
                    isE2EEEncrypted = true;
                } catch (e) {
                    // No session - need to fetch key bundle
                    console.log('[E2EE] Fetching key bundle for', recipientId);
                    keyBundle = await fetchKeyBundle(recipientId);
                    if (keyBundle) {
                        encryptedPayload = await VibeCrypto.encryptMessage(recipientId, text, keyBundle);
                        isE2EEEncrypted = true;
                    } else {
                        // v3.11.9: Fail-closed — do NOT send unencrypted
                        console.error('[E2EE] No key bundle available — cannot send encrypted');
                        showEncryptionFailedError('No encryption keys available for this recipient. Ask them to re-login.');
                        removeMessageFromChat(messageId);
                        return;
                    }
                }
            }
        } else {
            // v3.11.9: Fail-closed — E2EE not ready, block send
            console.error('[E2EE] Encryption not initialized — cannot send');
            showEncryptionFailedError('End-to-end encryption is not initialized. Please reload the page or re-login.');
            removeMessageFromChat(messageId);
            return;
        }
    } catch (e) {
        console.error('[E2EE] Encryption failed:', e);
        // v3.11.9: Fail-secure — do NOT send unencrypted
        showEncryptionFailedError('Message encryption failed: ' + (e.message || 'Unknown error') + '. Message was NOT sent.');
        removeMessageFromChat(messageId);
        return;
    }
    
    // v3.8.6: Update message with E2EE status and warn user if not encrypted
    message.e2ee = isE2EEEncrypted;
    if (!isE2EEEncrypted) {
        console.warn('[E2EE] Message sent WITHOUT end-to-end encryption!');
        showE2EEWarning();
    }
    // v3.7.1: Encrypt copy for self (multi-device sync)
    let encryptedForSelf = null;
    if (state.e2eeReady && encryptedPayload) {
        try {
            encryptedForSelf = await VibeCrypto.encryptForSelf(text);
        } catch (e) {
            console.warn("[E2EE] Failed to encrypt for self:", e);
        }
    }

    const payload = {
        encrypted_payload: encryptedPayload,
        client_message_id: messageId,
        encrypted_for_self: encryptedForSelf,
    };
    
    if (isGroup) {
        payload.group_id = chat.id;
        
        // Extract mentions from text
        const mentions = extractMentions(text, chat);
        if (mentions.length > 0) {
            payload.mentions = mentions;
        }
        
        // Include sender key distribution if new
        if (senderKeyDistribution) {
            payload.sender_key_distribution = await encryptDistributionForMembers(chat.id, senderKeyDistribution);  // КАО#100: per-member 1:1-encrypted
        }
    } else {
        payload.recipient_id = state.currentChatId;
    }
    
    // Add disappearing time if set
    if (state.disappearingTime > 0) {
        payload.expires_in_seconds = state.disappearingTime;
    }
    
    // Add reply_to_id if replying
    if (replyToId) {
        payload.reply_to_id = replyToId;
    }
    
    // If offline, add to queue
    if (!state.isOnline) {
        addToMessageQueue(payload);
        return;
    }

    try {
        const response = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        if (response.ok) {
            const data = await response.json();
            // Update with server ID, status, and expires_at from server
            updateMessageWithServerId(messageId, data.id, data.status, data.expires_at);
            
            // Cache our own message for future history loads
            // This is important because we can't decrypt our own E2EE messages
            if (data.id && state.e2eeReady) {
                offlineDB.saveDecryptedMessage(data.id, state.currentChatId, text, null);
            }
        } else {
            updateMessageStatus(messageId, 'failed');
            // Show permission error
            if (response.status === 403) {
                const data = await response.json();
                showPermissionError(data.detail || 'Action not allowed');
            }
        }
    } catch (e) {
        // Network error - add to queue
        addToMessageQueue(payload);
        updateMessageStatus(messageId, 'queued');
    }
}

// File upload
// ==================== VOICE MESSAGES ====================

var mediaRecorder = null;
var audioChunks = [];
var recordingInterval = null;
var recordingStartTime = null;
var recordingElapsed = 0;
var isRecordingPaused = false;

async function startVoiceRecording() {
    if (!state.currentChatId) {
        alert('Open a chat first');
        return;
    }
    
    // If paused, resume recording
    if (isRecordingPaused && mediaRecorder && mediaRecorder.state === 'paused') {
        mediaRecorder.resume();
        isRecordingPaused = false;
        const pauseBtn = document.getElementById('pause-voice');
        const recordingDot = document.getElementById('recording-dot');
        if (pauseBtn) pauseBtn.textContent = '⏸';
        if (recordingDot) recordingDot.classList.add('recording-dot');
        recordingStartTime = Date.now();
        
        recordingInterval = setInterval(() => {
            const elapsed = recordingElapsed + Math.floor((Date.now() - recordingStartTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = elapsed % 60;
            const timeEl = document.getElementById('recording-time');
            if (timeEl) timeEl.textContent = mins + ':' + (secs < 10 ? '0' : '') + secs;
        }, 1000);
        return;
    }
    
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        
        mediaRecorder = new MediaRecorder(stream, { mimeType: 'audio/webm' });
        audioChunks = [];
        recordingElapsed = 0;
        isRecordingPaused = false;
        
        mediaRecorder.ondataavailable = (e) => {
            if (e.data.size > 0) {
                audioChunks.push(e.data);
            }
        };
        
        mediaRecorder.start(100);
        recordingStartTime = Date.now();
        
        // Show recording UI
        const msgInput = document.querySelector('.message-input');
        const voiceRec = document.getElementById('voice-recording');
        const pauseBtn = document.getElementById('pause-voice');
        const recordingDot = document.getElementById('recording-dot');
        if (msgInput) msgInput.classList.add('hidden');
        if (voiceRec) voiceRec.classList.remove('hidden');
        if (pauseBtn) pauseBtn.textContent = '⏸';
        if (recordingDot) recordingDot.classList.add('recording-dot');
        
        // Update timer
        recordingInterval = setInterval(() => {
            const elapsed = recordingElapsed + Math.floor((Date.now() - recordingStartTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = elapsed % 60;
            const timeEl = document.getElementById('recording-time');
            if (timeEl) timeEl.textContent = mins + ':' + (secs < 10 ? '0' : '') + secs;
        }, 1000);
        
    } catch (e) {
        console.error('Microphone error:', e);
        alert('Could not access microphone');
    }
}

function pauseVoiceRecording() {
    if (!mediaRecorder) return;
    
    const pauseBtn = document.getElementById('pause-voice');
    const recordingDot = document.getElementById('recording-dot');
    
    if (mediaRecorder.state === 'recording') {
        // Pause
        mediaRecorder.pause();
        isRecordingPaused = true;
        recordingElapsed += Math.floor((Date.now() - recordingStartTime) / 1000);
        clearInterval(recordingInterval);
        if (pauseBtn) pauseBtn.textContent = '▶';
        if (recordingDot) {
            recordingDot.classList.remove('recording-dot');
            recordingDot.classList.add('paused-dot');
        }
    } else if (mediaRecorder.state === 'paused') {
        // Resume
        mediaRecorder.resume();
        isRecordingPaused = false;
        recordingStartTime = Date.now();
        if (pauseBtn) pauseBtn.textContent = '⏸';
        if (recordingDot) {
            recordingDot.classList.remove('paused-dot');
            recordingDot.classList.add('recording-dot');
        }
        
        recordingInterval = setInterval(() => {
            const elapsed = recordingElapsed + Math.floor((Date.now() - recordingStartTime) / 1000);
            const mins = Math.floor(elapsed / 60);
            const secs = elapsed % 60;
            const timeEl = document.getElementById('recording-time');
            if (timeEl) timeEl.textContent = mins + ':' + (secs < 10 ? '0' : '') + secs;
        }, 1000);
    }
}

function deleteVoiceRecording() {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
    
    clearInterval(recordingInterval);
    audioChunks = [];
    recordingElapsed = 0;
    isRecordingPaused = false;
    mediaRecorder = null;
    
    // Hide recording UI
    document.getElementById('voice-recording').classList.add('hidden');
    document.querySelector('.message-input').classList.remove('hidden');
    document.getElementById('recording-time').textContent = '0:00';
}

async function sendVoiceMessage() {
    if (!mediaRecorder || audioChunks.length === 0) return;
    
    // Check voice permission
    if (state.permissions && !state.permissions.can_send_voice) {
        showPermissionError('You are not allowed to send voice messages');
        deleteVoiceRecording();
        return;
    }
    
    // Calculate total duration
    let duration = recordingElapsed;
    if (!isRecordingPaused && recordingStartTime) {
        duration += Math.floor((Date.now() - recordingStartTime) / 1000);
    }
    
    if (mediaRecorder.state !== 'inactive') {
        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
    clearInterval(recordingInterval);
    
    // Wait for final data
    await new Promise(resolve => setTimeout(resolve, 200));
    
    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
    const filename = 'voice_' + Date.now() + '.webm';
    
    // КАО#090 + Round-2: fail-closed BEFORE upload (was: plaintext voice upload if e2ee not ready → orphaned plaintext file on server)
    if (!state.e2eeReady) {
        showEncryptionFailedError('End-to-end encryption is not initialized. Voice message was NOT sent.');
        return;
    }
    const _enc = await VibeCrypto.encryptFile(await audioBlob.arrayBuffer());
    const _vFileKey = _enc.key;
    const _vUploadBlob = new Blob([_enc.encrypted], { type: 'application/octet-stream' });
    // Upload file
    const formData = new FormData();
    formData.append('file', _vUploadBlob, filename);

    try {
        const response = await fetch(API_URL + '/files/upload', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + state.token },
            body: formData,
        });

        if (!response.ok) {
            alert('Upload failed');
            deleteVoiceRecording();
            return;
        }

        const data = await response.json();

        const messageId = 'msg_' + Date.now();
        const fileInfo = {
            file_id: data.file_id,
            filename: filename,
            size: data.size,
            extension: 'webm',
            is_voice: true,
            duration: duration,
        };
        if (_vFileKey) { fileInfo.fileKey = _vFileKey; state.fileKeys[data.file_id] = _vFileKey; }
        
        const message = {
            id: messageId,
            text: '🎤 Voice message',
            file: fileInfo,
            sender_id: state.user.id,
            created_at: new Date().toISOString(),
            status: 'sending',
        };
        
        addMessageToUI(message);
        
        // Determine if this is a group chat
        const chat = state.chats[state.currentChatId];
        const isGroup = chat && chat.isGroup;
        
        // E2EE: Encrypt file info
        let encryptedPayload;
        let senderKeyDistribution = null;
        const fileInfoStr = JSON.stringify(fileInfo);
        
        try {
            if (state.e2eeReady) {
                if (isGroup) {
                    const groupId = chat.id;
                    const result = await VibeCrypto.encryptGroupMessage(groupId, fileInfoStr);
                    encryptedPayload = result.payload;
                    senderKeyDistribution = result.distribution;
                } else {
                    const recipientId = state.currentChatId;
                    try {
                        encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fileInfoStr);
                    } catch (e) {
                        const keyBundle = await fetchKeyBundle(recipientId);
                        if (keyBundle) {
                            encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fileInfoStr, keyBundle);
                        } else {
                            // v3.11.10: Fail-closed — no silent base64 fallback
                            console.error('[E2EE] No key bundle for voice recipient — cannot encrypt');
                            const recipientName = chat?.displayName || chat?.username || recipientId;
                            const confirmed = await showUnencryptedConfirmDialog(recipientName);
                            if (!confirmed) {
                                removeMessageFromChat(messageId);
                                return;
                            }
                            encryptedPayload = btoa(unescape(encodeURIComponent(fileInfoStr)));
                        }
                    }
                }
            } else {
                // v3.11.10: Fail-closed — E2EE not ready, block voice send
                console.error('[E2EE] Encryption not initialized — cannot send voice');
                showEncryptionFailedError('End-to-end encryption is not initialized. Please reload the page or re-login.');
                removeMessageFromChat(messageId);
                return;
            }
        } catch (e) {
            console.error('[E2EE] Voice encryption failed:', e);
            showEncryptionFailedError('Voice message encryption failed. Message was NOT sent.');
            return;
        }
        
        // v3.7.2: Encrypt copy for self (multi-device sync)
        let encryptedForSelf = null;
        if (state.e2eeReady && encryptedPayload) {
            try {
                encryptedForSelf = await VibeCrypto.encryptForSelf(fileInfoStr);
            } catch (e) {
                console.warn("[E2EE] Failed to encrypt voice for self:", e);
            }
        }
        
        const payload = {
            encrypted_payload: encryptedPayload,
            message_type: 'voice',
            file_id: data.file_id,
            client_message_id: messageId,
            encrypted_for_self: encryptedForSelf,
        };
        if (isGroup) {
            payload.group_id = state.currentChatId.replace('group_', '');
            if (senderKeyDistribution) {
                payload.sender_key_distribution = await encryptDistributionForMembers(state.currentChatId.replace('group_', ''), senderKeyDistribution);  // КАО#100
            }
        } else {
            payload.recipient_id = state.currentChatId;
        }
        
        // Send via REST API (same as files)
        const msgResponse = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        
        if (msgResponse.ok) {
            const msgData = await msgResponse.json();
            updateMessageWithServerId(messageId, msgData.id, msgData.status);
        } else {
            updateMessageStatus(messageId, 'failed');
            if (msgResponse.status === 403) {
                const errData = await msgResponse.json();
                showPermissionError(errData.detail || 'Action not allowed');
            }
        }
        
    } catch (e) {
        console.error('Voice upload error:', e);
        alert('Failed to send voice message');
    }
    
    // Reset UI
    document.getElementById('voice-recording').classList.add('hidden');
    document.querySelector('.message-input').classList.remove('hidden');
    document.getElementById('recording-time').textContent = '0:00';
    audioChunks = [];
    recordingElapsed = 0;
    isRecordingPaused = false;
    mediaRecorder = null;
}

function playVoiceMessage(fileId, btn) {
    const existingAudio = document.getElementById('audio-' + fileId);
    
    if (existingAudio) {
        if (existingAudio.paused) {
            existingAudio.play();
            btn.textContent = '⏸';
        } else {
            existingAudio.pause();
            btn.textContent = '▶';
        }
        return;
    }
    
    // Create new audio element
    const audio = document.createElement('audio');
    audio.id = 'audio-' + fileId;
    audio.style.display = 'none';
    document.body.appendChild(audio);
    
    btn.textContent = '...';
    
    // Fetch and play
    fetchFileBlob(fileId)  // КАО#090: fetch + at-rest decrypt
    .then(blob => {
        audio.src = URL.createObjectURL(blob);
        audio.play();
        btn.textContent = '⏸';
        
        audio.onended = () => {
            btn.textContent = '▶';
            // КАО#134: release object URL + element so they don't accumulate per played voice message
            try { URL.revokeObjectURL(audio.src); } catch (e) {}
            audio.remove();
        };

        audio.onpause = () => {
            btn.textContent = '▶';
        };
        
        audio.onplay = () => {
            btn.textContent = '⏸';
        };
    })
    .catch(e => {
        console.error('Audio playback error:', e);
        btn.textContent = '▶';
    });
}

// ==================== FILE HANDLING ====================

async function sendFile() {
    if (!state.currentChatId) {
        alert('Open a chat first');
        return;
    }
    
    // Check file permission
    if (state.permissions && !state.permissions.can_send_files) {
        showPermissionError('You are not allowed to send files');
        return;
    }
    
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*,video/*,audio/*,.pdf,.doc,.docx,.txt,.zip';
    
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        if (file.size > 10 * 1024 * 1024) {
            alert('File too large. Max 10MB');
            return;
        }
        
        // КАО#090 + Round-2: fail-closed BEFORE upload (was: plaintext upload if e2ee not ready → orphaned plaintext file on server)
        if (!state.e2eeReady) {
            showEncryptionFailedError('End-to-end encryption is not initialized. File was NOT sent.');
            return;
        }
        const _enc = await VibeCrypto.encryptFile(await file.arrayBuffer());
        const _fileKey = _enc.key;
        const _uploadBlob = new Blob([_enc.encrypted], { type: 'application/octet-stream' });
        const formData = new FormData();
        formData.append('file', _uploadBlob, file.name);

        try {
            const response = await fetch(API_URL + '/files/upload', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + state.token },
                body: formData,
            });

            if (!response.ok) {
                alert('Upload failed');
                return;
            }

            const data = await response.json();

            const messageId = 'msg_' + Date.now();
            const fileInfo = {
                file_id: data.file_id,
                filename: data.filename,
                size: data.size,
                extension: data.extension,
            };
            if (_fileKey) { fileInfo.fileKey = _fileKey; state.fileKeys[data.file_id] = _fileKey; }
            
            const message = {
                id: messageId,
                text: '📎 ' + file.name,
                file: fileInfo,
                sender_id: state.user.id,
                created_at: new Date().toISOString(),
                status: 'sending',
            };
            
            addMessageToUI(message);
            
            // Determine if this is a group chat
            const chat = state.chats[state.currentChatId];
            const isGroup = chat && chat.isGroup;
            
            // E2EE: Encrypt file info
            let encryptedPayload;
            let senderKeyDistribution = null;
            const fileInfoStr = JSON.stringify(fileInfo);
            
            try {
                if (state.e2eeReady) {
                    if (isGroup) {
                        const groupId = chat.id;
                        const result = await VibeCrypto.encryptGroupMessage(groupId, fileInfoStr);
                        encryptedPayload = result.payload;
                        senderKeyDistribution = result.distribution;
                    } else {
                        const recipientId = state.currentChatId;
                        try {
                            encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fileInfoStr);
                        } catch (e) {
                            const keyBundle = await fetchKeyBundle(recipientId);
                            if (keyBundle) {
                                encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fileInfoStr, keyBundle);
                            } else {
                                // v3.11.10: Fail-closed — no silent base64 fallback
                                console.error('[E2EE] No key bundle for file recipient — cannot encrypt');
                                const recipientName = chat?.displayName || chat?.username || recipientId;
                                const confirmed = await showUnencryptedConfirmDialog(recipientName);
                                if (!confirmed) {
                                    removeMessageFromChat(messageId);
                                    return;
                                }
                                encryptedPayload = btoa(unescape(encodeURIComponent(fileInfoStr)));
                            }
                        }
                    }
                } else {
                    // v3.11.10: Fail-closed — E2EE not ready, block file send
                    console.error('[E2EE] Encryption not initialized — cannot send file');
                    showEncryptionFailedError('End-to-end encryption is not initialized. Please reload the page or re-login.');
                    removeMessageFromChat(messageId);
                    return;
                }
            } catch (e) {
                console.error('[E2EE] File encryption failed:', e);
                showEncryptionFailedError('File encryption failed. File was NOT sent.');
                return;
            }
            
            // v3.7.2: Encrypt copy for self (multi-device sync)
            let encryptedForSelf = null;
            if (state.e2eeReady && encryptedPayload) {
                try {
                    encryptedForSelf = await VibeCrypto.encryptForSelf(fileInfoStr);
                } catch (e) {
                    console.warn("[E2EE] Failed to encrypt file for self:", e);
                }
            }
            
            const payload = {
                encrypted_payload: encryptedPayload,
                message_type: 'file',
                file_id: data.file_id,
                client_message_id: messageId,
                encrypted_for_self: encryptedForSelf,
            };
            if (isGroup) {
                payload.group_id = state.currentChatId.replace('group_', '');
                if (senderKeyDistribution) {
                    payload.sender_key_distribution = await encryptDistributionForMembers(state.currentChatId.replace('group_', ''), senderKeyDistribution);  // КАО#100
                }
            } else {
                payload.recipient_id = state.currentChatId;
            }
            
            const msgResponse = await api('/messages/send', {
                method: 'POST',
                body: JSON.stringify(payload),
            });
            
            if (msgResponse.ok) {
                const msgData = await msgResponse.json();
                updateMessageWithServerId(messageId, msgData.id, msgData.status);
            } else {
                updateMessageStatus(messageId, 'failed');
                if (msgResponse.status === 403) {
                    const errData = await msgResponse.json();
                    showPermissionError(errData.detail || 'Action not allowed');
                }
            }
        } catch (e) {
            console.error('Upload error:', e);
            alert('Upload failed');
        }
    };
    
    input.click();
}

// КАО#100 (C0): encrypt the group sender-key distribution PER-MEMBER over the 1:1 Double Ratchet.
// The raw symmetric chainKey must NEVER reach the server in cleartext. Returns {memberId: ciphertext}.
async function encryptDistributionForMembers(groupId, distribution) {
    if (!distribution) return null;
    // КАО#100 Round-2 fix: offline, the /members fetch fails → empty map → recipients can't decrypt.
    // Defer per-member encryption; the offline-queue flush re-encrypts this once back online.
    if (!state.isOnline) return { _deferred: distribution };
    let members = [];
    try {
        const r = await api('/groups/' + groupId + '/members');
        if (r.ok) members = await r.json();
    } catch (e) { console.error('[C0] members fetch failed', e); }
    const distStr = JSON.stringify(distribution);
    const map = {};
    for (const m of members) {
        const mid = String(m.user_id || m.id || '');
        if (!mid || mid === String(state.user.id)) continue;
        try {
            let ct;
            try { ct = await VibeCrypto.encryptMessage(mid, distStr); }
            catch (e) {
                const kb = await fetchKeyBundle(mid);
                if (!kb) { console.warn('[C0] no key bundle for member', mid); continue; }
                ct = await VibeCrypto.encryptMessage(mid, distStr, kb);
            }
            map[mid] = ct;
        } catch (e) { console.error('[C0] encrypt distribution failed for', mid, e); }
    }
    return map;
}

// КАО#090: register an at-rest file key from a decrypted fileInfo
function regFileKey(fi) {
    if (fi && fi.fileKey && fi.file_id) state.fileKeys[fi.file_id] = fi.fileKey;
}

// КАО#090: fetch a file (auth) and decrypt its bytes at-rest when we hold the key.
// Legacy plaintext files (no key in registry) are returned as-is.
async function fetchFileBlob(fileId) {
    const resp = await fetch(API_URL + '/files/download/' + fileId, {
        headers: { 'Authorization': 'Bearer ' + state.token }
    });
    if (!resp.ok) throw new Error('Download failed: HTTP ' + resp.status);  // КАО#041
    const buf = await resp.arrayBuffer();
    const key = state.fileKeys[fileId];
    if (key) {
        const dec = await VibeCrypto.decryptFile(buf, key);
        return new Blob([dec]);
    }
    return new Blob([buf]);
}

function downloadFile(fileId, filename) {
    fetchFileBlob(fileId)  // КАО#090: fetch + at-rest decrypt
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename || 'file';
        link.click();
        window.URL.revokeObjectURL(url);
    })
    .catch(e => {
        console.error('Download error:', e);
        alert('Download failed');
    });
}

// КАО#278 (#30): buffer group messages that arrive BEFORE their sender-key distribution, then retry
// once the distribution is processed — otherwise such an out-of-order message is permanently undecryptable.
const pendingGroupMessages = {};  // "groupId:senderId" -> [payloads awaiting sender key]
function bufferPendingGroupMessage(groupId, senderId, payload) {
    const k = groupId + ':' + senderId;
    if (!pendingGroupMessages[k]) pendingGroupMessages[k] = [];
    if (pendingGroupMessages[k].length >= 50) return;  // bound memory
    if (payload.id && pendingGroupMessages[k].some(p => p.id === payload.id)) return;  // dedup
    pendingGroupMessages[k].push(payload);
    console.log('[E2EE] Buffered group message awaiting sender key:', payload.id, 'for', k);
}
function flushPendingGroupMessages(groupId, senderId) {
    const k = groupId + ':' + senderId;
    const buffered = pendingGroupMessages[k];
    if (!buffered || !buffered.length) return;
    delete pendingGroupMessages[k];
    console.log('[E2EE] Flushing', buffered.length, 'buffered group messages for', k);
    for (const p of buffered) {
        handleNewMessage(p).catch(e => console.error('[E2EE] buffered-message retry failed', e));
    }
}

async function handleNewMessage(payload) {
    console.log('handleNewMessage:', payload.id, payload.expires_at ? '(disappearing)' : '');
    
    // Handle pinned message notifications
    if (payload.type === 'message_pinned') {
        handleMessagePinned(payload);
        return;
    }
    
    if (payload.type === 'message_unpinned') {
        handleMessageUnpinned(payload);
        return;
    }
    
    // Handle group notifications
    if (payload.type === 'group_created' || payload.type === 'group_joined') {
        // Reload groups
        loadMyGroups();
        return;
    }
    
    if (payload.type === 'group_left') {
        // Remove group from chats
        const chatKey = 'group_' + payload.group_id;
        delete state.chats[chatKey];
        saveChats();
        renderChatsList();
        if (state.currentChatId === chatKey) {
            showScreen('chats');
        }
        return;
    }
    
    if (payload.type === 'group_deleted') {
        // Group was deleted by owner
        const chatKey = 'group_' + payload.group_id;
        delete state.chats[chatKey];
        saveChats();
        renderChatsList();
        if (state.currentChatId === chatKey) {
            showScreen('chats');
        }
        const ownerName = payload.owner_name || 'Owner'; showSystemNotification(ownerName + ' deleted the group "' + payload.group_name + '"');
        return;
    }
    
    if (payload.type === 'admin_group_deleted') {
        // Group was deleted by admin
        const chatKey = 'group_' + payload.group_id;
        delete state.chats[chatKey];
        saveChats();
        renderChatsList();
        if (state.currentChatId === chatKey) {
            showScreen('chats');
        }
        showSystemNotification('Group "' + payload.group_name + '" was deleted by Administrator');
        return;
    }
    
    if (payload.type === 'admin_removed_from_group') {
        // User was removed from group by admin
        const chatKey = 'group_' + payload.group_id;
        delete state.chats[chatKey];
        saveChats();
        renderChatsList();
        if (state.currentChatId === chatKey) {
            showScreen('chats');
        }
        showSystemNotification('You were removed from "' + payload.group_name + '" by Administrator');
        return;
    }
    
    if (payload.type === 'admin_notification') {
        // Admin notification
        const message = payload.message || '';
        showAdminNotification(message);
        playNotificationSound();
        return;
    }
    
    if (payload.type === 'group_invite') {
        handleGroupInvite(payload);
        return;
    }
    
    if (payload.type === 'invite_accepted') {
        // Reload group members
        loadMyGroups();
        return;
    }

    // КАО#275 (#12): group membership/role metadata events. Previously unhandled → fell through to the
    // message-render path and injected a phantom "[Unable to decrypt message]". Refresh group state instead.
    if (payload.type === 'member_joined' || payload.type === 'role_changed'
        || payload.type === 'ownership_transferred' || payload.type === 'group_owner_changed'
        || payload.type === 'member_removed' || payload.type === 'members_added') {
        const gid = payload.group_id;
        if (gid && state.currentChatId === 'group_' + gid && typeof loadGroupMembers === 'function') {
            loadGroupMembers(gid)
                .then(() => { if (typeof renderGroupMembersList === 'function') renderGroupMembersList(); })
                .catch(() => {});
        }
        loadMyGroups();
        return;
    }

    const senderId = String(payload.sender_id);
    const groupId = payload.group_id;
    
    // v3.8.10: Handle admin/system messages specially
    const isAdminMessage = payload.is_admin_message === true;
    const SYSTEM_SENDER_ID = "00000000-0000-0000-0000-000000000000";
    
    // Determine chat key
    let chatKey;
    if (groupId) {
        chatKey = 'group_' + groupId;
    } else if (isAdminMessage || senderId === SYSTEM_SENDER_ID) {
        chatKey = SYSTEM_SENDER_ID;  // All admin messages go to VibeAdmin chat
    } else {
        chatKey = senderId;
    }
    
    // Check if this chat was deleted and message is older than deletion
    const key = state.user ? 'deletedChats_' + state.user.id : 'deletedChats';
    const deletedChats = JSON.parse(localStorage.getItem(key) || '{}');
    const deletedAt = deletedChats[chatKey] ? new Date(deletedChats[chatKey]) : null;
    if (deletedAt && new Date(payload.created_at) < deletedAt) {
        console.log('Skipping message from deleted chat period');
        return;
    }
    
    // Handle CALL messages specially (not encrypted)
    if (payload.message_type === 'call' || payload.message_type === 'CALL') {
        await handleCallMessageFromServer(payload, chatKey, senderId);
        return;
    }
    
    // Process sender key distribution if present (group E2EE)
    if (payload.sender_key_distribution && groupId && state.e2eeReady) {
        try {
            // КАО#100 (C0): distribution is a per-member 1:1-encrypted map {userId: ciphertext}.
            // КАО#324 (critical): the "legacy raw object" fallback is GONE. A distribution carrying a
            // plaintext `chainKey` was accepted with no decryption and no authentication, and the sender
            // no longer produces that shape — so it was purely an attacker-reachable input. Combined with
            // КАО#308 (which decides by signing key) a hostile server could push
            // {chainKey, signingPublicKey, iteration} for any sender_id, silently replace that member's
            // sender key, and then post messages that verify and decrypt AS THAT MEMBER. Only accept a
            // distribution that we could actually decrypt from this sender over the authenticated 1:1
            // Double Ratchet.
            let dist = payload.sender_key_distribution;
            if (!dist || typeof dist !== 'object' || dist.chainKey) {
                throw new Error('Rejected unauthenticated sender-key distribution from ' + senderId);
            }
            const myEntry = dist[String(state.user.id)];
            dist = myEntry ? JSON.parse(await VibeCrypto.decryptMessage(senderId, myEntry)) : null;
            if (dist) {
                await VibeCrypto.processGroupKeyDistribution(groupId, senderId, dist);
                flushPendingGroupMessages(groupId, senderId);  // КАО#278 (#30): retry messages that arrived before this distribution
            }
            console.log('[E2EE] Processed sender key distribution from', senderId);
        } catch (e) {
            console.error('[E2EE] Failed to process sender key distribution:', e);
        }
    }
    
    let text;
    let fileInfo = null;
    let wasE2EEDecrypted = undefined;  // v3.8.6: Track if message was E2EE encrypted
    
    // v3.8.10: If server explicitly says not E2EE, respect that
    if (payload.is_e2ee === false) {
        wasE2EEDecrypted = false;
    }
    
    // E2EE Decryption
    try {
        let decrypted = null;
        let fromCache = false;
        
        // IMPORTANT: Check cache FIRST to avoid double decryption!
        // Double Ratchet is stateful - decrypting same message twice corrupts session
        if (payload.id) {
            const cached = await offlineDB.getDecryptedMessage(payload.id);
            if (cached) {
                console.log('[E2EE] Message already in cache, using cached version');
                decrypted = cached.text;
                fileInfo = cached.file_info;
                fromCache = true;
                wasE2EEDecrypted = true;  // Cached messages were E2EE
            }
        }
        
        if (!fromCache && state.e2eeReady && payload.encrypted_payload) {
            try {
                // Check if this is an E2EE encrypted message by looking at payload structure
                // E2EE payloads are base64 of JSON starting with {"v":
                const firstBytes = atob(payload.encrypted_payload.slice(0, 24));
                const isE2EE = firstBytes.startsWith('{"v":');
                
                if (isE2EE) {
                    wasE2EEDecrypted = true;
                    // Try E2EE decryption
                    if (groupId) {
                        // Group message - use Sender Keys
                        try {
                            decrypted = await VibeCrypto.decryptGroupMessage(groupId, senderId, payload.encrypted_payload);
                        } catch (gerr) {
                            // КАО#278 (#30): arrived before its sender-key distribution → buffer and retry
                            // when the distribution is processed, rather than show a permanent failure.
                            if (/no sender key|no group session/i.test(gerr && gerr.message || '') && payload.id) {
                                bufferPendingGroupMessage(groupId, senderId, payload);  // КАО#278 Round-2: also buffer brand-new-group "No group session"
                                return;
                            }
                            throw gerr;
                        }
                    } else {
                        // Direct message - use Double Ratchet
                        decrypted = await VibeCrypto.decryptMessage(senderId, payload.encrypted_payload);
                    }
                    console.log('[E2EE] Message decrypted successfully');
                    
                    // Cache decrypted message for future history loads
                    if (payload.id && decrypted) {
                        // Parse file info if it's a file message to cache properly
                        let cacheText = decrypted;
                        let cacheFileInfo = null;
                        if (payload.message_type === 'FILE' || payload.message_type === 'file' || 
                            payload.message_type === 'voice' || payload.message_type === 'VOICE' ||
                            (decrypted.startsWith('{') && !decrypted.startsWith('{"v":'))) {
                            try {
                                cacheFileInfo = JSON.parse(decrypted);
                                if (payload.message_type === 'voice' || payload.message_type === 'VOICE' || cacheFileInfo.is_voice) {
                                    cacheText = '🎤 Voice message';
                                } else {
                                    cacheText = '📎 ' + (cacheFileInfo.filename || 'File');
                                }
                            } catch {
                                // Not JSON, keep as text
                            }
                        }
                        offlineDB.saveDecryptedMessage(payload.id, chatKey, cacheText, cacheFileInfo);
                    }
                }
            } catch (e) {
                console.log('[E2EE] E2EE decryption failed, trying legacy:', e);
                // Fall through to legacy decoding
            }
        }
        
        // Legacy decoding fallback (only if not from cache and not decrypted)
        if (!fromCache && !decrypted) {
            decrypted = decodeURIComponent(escape(atob(payload.encrypted_payload)));
            wasE2EEDecrypted = false;  // v3.8.6: Legacy encoding = not E2EE
            // Check if this is an undecrypted E2EE payload
            if (decrypted.startsWith('{"v":')) {
                decrypted = null; // Mark as failed E2EE
                wasE2EEDecrypted = undefined;  // Unknown - decryption failed
            }
        }
        
        // Handle decryption failure
        if (!decrypted) {
            text = '🔒 Encrypted message (key expired)';
        }
        // If from cache, text and fileInfo already set correctly
        else if (fromCache) {
            text = decrypted; // decrypted contains cached text
            // fileInfo already set from cache
        }
        // Parse file info if applicable
        else if (payload.message_type === 'FILE' || payload.message_type === 'file' || 
            payload.message_type === 'voice' || payload.message_type === 'VOICE' ||
            (typeof decrypted === 'string' && decrypted.startsWith('{') && !decrypted.startsWith('{"v":'))) {
            try {
                fileInfo = JSON.parse(decrypted);
                if (payload.message_type === 'voice' || payload.message_type === 'VOICE' || fileInfo.is_voice) {
                    text = '🎤 Voice message';
                    fileInfo.is_voice = true;
                } else {
                    text = '📎 ' + (fileInfo.filename || 'File');
                }
            } catch {
                text = decrypted;
            }
        } else {
            text = decrypted;
        }
    }
    catch (e) { 
        console.error('[E2EE] Decryption error:', e);
        try {
            text = atob(payload.encrypted_payload); 
        } catch {
            text = '[Unable to decrypt message]';
        }
    }

    const message = {
        id: payload.id,
        text: text,
        file: fileInfo,
        sender_id: senderId,
        sender_name: payload.sender_name,
        group_id: groupId,
        created_at: payload.created_at,
        status: 'received',
        forwarded_from_id: payload.forwarded_from_id,
        forwarded_from_name: payload.forwarded_from_name,
        expires_at: payload.expires_at,
        reply_to_id: payload.reply_to_id,
        reactions: [],
        e2ee: wasE2EEDecrypted,  // v3.8.6: Mark if message was E2EE encrypted
    };
    
    
    // v3.11.10: Handle channel comments — update comment count on parent post
    if (chatKey && state.chats[chatKey] && state.chats[chatKey].isChannel && payload.reply_to_id) {
        const btn = document.querySelector('[data-comment-btn="' + payload.reply_to_id + '"]');
        if (btn) {
            const current = parseInt(btn.dataset.count || '0');
            const newCount = current + 1;
            btn.dataset.count = newCount;
            btn.textContent = '💬 ' + newCount + ' comment' + (newCount !== 1 ? 's' : '');

            // If comments section is expanded, add the new comment
            const section = document.getElementById('comments-' + payload.reply_to_id);
            if (section) {
                toggleChannelComments(payload.reply_to_id);  // close
                toggleChannelComments(payload.reply_to_id);  // reopen (refreshes)
            }
        }
    }

    // Debug: log expires_at
    if (payload.expires_at) {
        console.log('Received disappearing message:', {
            id: payload.id,
            expires_at: payload.expires_at,
            expires_in_ms: new Date(payload.expires_at) - new Date()
        });
    }

    // Create chat if needed
    if (groupId) {
        // Group message
        if (!state.chats[chatKey]) {
            // Load group info
            try {
                const response = await api('/groups/' + groupId);
                if (response.ok) {
                    const group = await response.json();
                    // v3.11.10: Store channel flag and user's role
                    const myMember = (group.members || []).find(m => String(m.user_id) === String(state.user.id));
                    state.chats[chatKey] = {
                        id: group.id,
                        isGroup: true,
                        isChannel: group.is_channel || false,
                        name: group.name,
                        displayName: group.name,
                        avatar_url: group.avatar_url || null,
                        members: group.members,
                        myRole: myMember ? myMember.role : 'member',
                        messages: [],
                        unreadCount: 0,
                    };
                }
            } catch (e) {
                console.error('Failed to load group:', e);
                return;
            }
        }
    } else {
        // Direct message
        if (isAdminMessage || senderId === SYSTEM_SENDER_ID) {
            // v3.8.10: VibeAdmin system chat
            if (!state.chats[chatKey]) {
                state.chats[chatKey] = { 
                    id: SYSTEM_SENDER_ID, 
                    username: 'VibeAdmin', 
                    displayName: 'VibeAdmin', 
                    avatar_url: null, 
                    isSystem: true,  // Mark as system chat
                    messages: [], 
                    unreadCount: 0, 
                    missedCalls: 0 
                };
            }
        } else if (!state.chats[chatKey] || state.chats[chatKey].username === chatKey) {
            try {
                const response = await api('/auth/user/id/' + senderId);
                if (response.ok) {
                    const userData = await response.json();
                    if (!state.chats[chatKey]) {
                        state.chats[chatKey] = { id: chatKey, username: userData.username, displayName: userData.display_name || userData.username, avatar_url: userData.avatar_url || null, messages: [], unreadCount: 0, missedCalls: 0 };
                    } else {
                        state.chats[chatKey].username = userData.username;
                        state.chats[chatKey].displayName = userData.display_name || userData.username;
                        state.chats[chatKey].avatar_url = userData.avatar_url || null;
                    }
                }
            } catch (e) {
                if (!state.chats[chatKey]) {
                    state.chats[chatKey] = { id: chatKey, username: chatKey, displayName: chatKey, avatar_url: null, messages: [], unreadCount: 0, missedCalls: 0 };
                }
            }
        }
    }

    if (state.chats[chatKey].messages.find(m => m.id === message.id)) {
        return;
    }

    state.chats[chatKey].messages.push(message);
    state.chats[chatKey].lastMessage = message;
    
    // Increase unread count if chat is not currently open
    if (state.currentChatId !== chatKey) {
        state.chats[chatKey].unreadCount = (state.chats[chatKey].unreadCount || 0) + 1;
    }
    
    saveChats();

    if (state.currentChatId === chatKey) {
        state.currentChat = state.chats[chatKey];
        renderMessages();
    }
    renderChatsList();

    // Acknowledge delivery (only for direct messages)
    if (!groupId) {
        console.log('Sending ACK delivered for message:', payload.id);
        try {
            const ackResponse = await api('/messages/ack', {
                method: 'POST',
                body: JSON.stringify({ message_ids: [payload.id], status: 'delivered' }),
            });
            console.log('ACK delivered response:', ackResponse.status);
        } catch (e) {
            console.error('ACK delivered failed:', e);
        }
        
        // If chat is open AND app is visible, mark as read immediately
        if (state.currentChatId === chatKey && document.visibilityState === 'visible') {
            console.log('Chat is open and visible, marking as read:', payload.id);
            markMessagesAsRead([payload.id]);
        }
    }
}

// Handle status update from server (delivered/read notifications)
function handleMessageStatusUpdate(payload) {
    const messageId = payload.message_id;
    const newStatus = payload.status;
    
    console.log('Status update received:', messageId, '->', newStatus);
    
    // Find message in all chats and update status
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        
        const message = chat.messages.find(m => m.id === messageId || m.client_message_id === messageId);
        if (message) {
            // Only update if new status is "higher" (delivered < read)
            const statusPriority = { pending: 0, sent: 1, delivered: 2, read: 3 };
            if (statusPriority[newStatus] >= statusPriority[message.status] || !message.status) {
                console.log('Found message, updating status from', message.status, 'to', newStatus);
                message.status = newStatus;
                saveChats();
                if (state.currentChatId === chatId) {
                    renderMessages();
                }
            }
            return; // Found and updated
        }
    }
    
    // Message not found - save to pending buffer (message_sent may arrive later)
    console.log('Message not found, buffering status update:', messageId, '->', newStatus);
    state.pendingStatusUpdates[messageId] = { 
        status: newStatus, 
        timestamp: Date.now() 
    };
    
    // Clean old pending updates (older than 30 seconds)
    const now = Date.now();
    for (const id in state.pendingStatusUpdates) {
        if (now - state.pendingStatusUpdates[id].timestamp > 30000) {
            delete state.pendingStatusUpdates[id];
        }
    }
}

// Handle message deleted notification from server
function handleMessageDeleted(payload) {
    const messageId = payload.message_id;
    const forEveryone = payload.for_everyone;
    
    // Find and remove message from all chats
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        
        const messageIdx = chat.messages.findIndex(m => m.id === messageId);
        if (messageIdx !== -1) {
            chat.messages.splice(messageIdx, 1);
            
            // Update last message
            if (chat.messages.length > 0) {
                chat.lastMessage = chat.messages[chat.messages.length - 1];
            } else {
                chat.lastMessage = null;
            }
            
            saveChats();
            if (state.currentChatId === chatId) {
                renderMessages();
            }
            renderChatsList();
            break;
        }
    }
}

// Handle message edited notification from server
async function handleMessageEdited(payload) {
    const messageId = payload.message_id;
    const newPayload = payload.encrypted_payload;
    const editedAt = payload.edited_at;
    
    // Find and update message in all chats
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        
        const message = chat.messages.find(m => m.id === messageId);
        if (message) {
            // Decrypt new text with E2EE if available
            let decryptedText;
            const isOwnEdit = message.sender_id === state.user.id;
            try {
                if (state.e2eeReady) {
                    if (isOwnEdit && payload.encrypted_for_self) {
                        // КАО#150 (SER#14): our own edit — main payload is encrypted to others; decrypt the self-copy
                        decryptedText = await VibeCrypto.decryptForSelf(payload.encrypted_for_self);
                        console.log('[E2EE] Decrypted own edited message via encrypted_for_self');
                    } else if (chat.isGroup) {
                        // Group message - decrypt with sender key
                        decryptedText = await VibeCrypto.decryptGroupMessage(
                            chat.id,
                            message.sender_id,
                            newPayload
                        );
                        console.log('[E2EE] Decrypted edited group message');
                    } else {
                        // Direct message - determine who sent it
                        const otherUserId = message.sender_id === state.user.id
                            ? chatId
                            : message.sender_id;
                        decryptedText = await VibeCrypto.decryptMessage(otherUserId, newPayload);
                        console.log('[E2EE] Decrypted edited direct message');
                    }
                } else {
                    // Fallback: base64 decode
                    decryptedText = decodeURIComponent(escape(atob(newPayload)));
                }
            } catch (e) {
                console.warn('[E2EE] Failed to decrypt edited message, trying base64:', e);
                try {
                    decryptedText = decodeURIComponent(escape(atob(newPayload)));
                } catch (e2) {
                    decryptedText = atob(newPayload);
                }
            }
            
            message.text = decryptedText;
            message.edited_at = editedAt;
            message.is_edited = true;
            
            // Update decrypted cache
            if (state.e2eeReady && decryptedText) {
                offlineDB.saveDecryptedMessage(messageId, chatId, decryptedText, null);
            }
            
            saveChats();
            if (state.currentChatId === chatId) {
                renderMessages();
            }
            break;
        }
    }
}

// Mark messages as read
async function markMessagesAsRead(messageIds) {
    if (!messageIds || messageIds.length === 0) return;
    
    console.log('Sending ACK read for messages:', messageIds);
    try {
        const response = await api('/messages/ack', {
            method: 'POST',
            body: JSON.stringify({ message_ids: messageIds, status: 'read' }),
        });
        console.log('ACK read response:', response.status);
    } catch (e) {
        console.error('Failed to mark as read:', e);
    }
}

// Mark all unread messages in current chat as read
function markCurrentChatAsRead() {
    if (!state.currentChatId || !state.chats[state.currentChatId]) return;
    
    const chat = state.chats[state.currentChatId];
    const unreadIds = [];
    
    chat.messages.forEach(msg => {
        // Only mark received messages that aren't already read
        if (msg.sender_id !== state.user.id && msg.status !== 'read') {
            unreadIds.push(msg.id);
            msg.status = 'read'; // Optimistic update
        }
    });
    
    if (unreadIds.length > 0) {
        markMessagesAsRead(unreadIds);
        saveChats();
    }
}

// ==================== SETTINGS ====================

function showSettings() {
    // Update user info
    if (state.user) {
        const avatarLetter = document.getElementById('settings-avatar');
        const avatarImg = document.getElementById('settings-avatar-img');
        
        avatarLetter.textContent = (state.user.display_name || state.user.username || 'U')[0].toUpperCase();
        document.getElementById('settings-display-name').textContent = state.user.display_name || state.user.username;
        document.getElementById('settings-username').textContent = '@' + state.user.username;
        
        // Show avatar image if exists
        if (state.user.avatar_url) {
            avatarImg.src = state.user.avatar_url;
            avatarImg.classList.remove('hidden');
            avatarLetter.classList.add('hidden');
            document.querySelector('.avatar-upload-hint').classList.add('hidden');
        } else {
            avatarImg.classList.add('hidden');
            avatarLetter.classList.remove('hidden');
            document.querySelector('.avatar-upload-hint').classList.remove('hidden');
        }
    }
    
    // Update theme toggle UI
    updateThemeUI(localStorage.getItem('theme') || 'system');
    
    // Load TOTP status
    loadTOTPStatus();
    
    // v3.7.0: Load active sessions
    loadSessions();
    
    // v3.10.0: Load biometric/passkey settings
    if (typeof BiometricAuth !== 'undefined') {
        BiometricAuth.renderSettingsSection();
    }
    
    // v3.11.8: Screenshot protection toggle
    updateScreenshotToggleUI();
    
    showScreen('settings');
}

function triggerAvatarUpload() {
    document.getElementById('avatar-input').click();
}

async function uploadAvatar(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Validate file type
    if (!file.type.startsWith('image/')) {
        showLocalMessage('avatar-message', 'Please select an image file', 'error');
        return;
    }
    
    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
        showLocalMessage('avatar-message', 'Image too large (max 5MB)', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/v1/auth/avatar', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + state.token,
            },
            body: formData,
        });
        
        if (response.ok) {
            const data = await response.json();
            state.user.avatar_url = data.avatar_url;
            saveAuth(); // Save to correct localStorage key
            
            // Update UI
            const avatarImg = document.getElementById('settings-avatar-img');
            const avatarLetter = document.getElementById('settings-avatar');
            const uploadHint = document.querySelector('.avatar-upload-hint');
            avatarImg.src = data.avatar_url + '?t=' + Date.now(); // Cache bust
            avatarImg.classList.remove('hidden');
            avatarLetter.classList.add('hidden');
            if (uploadHint) uploadHint.classList.add('hidden');
            
            showLocalMessage('avatar-message', 'Avatar updated', 'success');
        } else {
            const data = await response.json();
            showLocalMessage('avatar-message', data.detail || 'Failed to upload avatar', 'error');
        }
    } catch (e) {
        console.error('Avatar upload error:', e);
        showLocalMessage('avatar-message', 'Network error', 'error');
    }
    
    // Clear input
    event.target.value = '';
}

async function changePassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
        showLocalMessage('change-password-message', 'Please fill all fields', 'error');
        return;
    }
    
    // Validate new password
    if (newPassword.length < 8) {
        showLocalMessage('change-password-message', 'New password must be at least 8 characters', 'error');
        return;
    }
    
    if (!/[A-Z]/.test(newPassword)) {
        showLocalMessage('change-password-message', 'Password must contain at least one uppercase letter', 'error');
        return;
    }
    
    if (!/[a-z]/.test(newPassword)) {
        showLocalMessage('change-password-message', 'Password must contain at least one lowercase letter', 'error');
        return;
    }
    
    if (!/[0-9]/.test(newPassword)) {
        showLocalMessage('change-password-message', 'Password must contain at least one number', 'error');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showLocalMessage('change-password-message', 'New passwords do not match', 'error');
        return;
    }
    
    try {
        const response = await api('/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword,
            }),
        });
        
        if (response.ok) {
            showLocalMessage('change-password-message', 'Password changed successfully', 'success');
            // Clear fields
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('confirm-new-password').value = '';
            // Close modal after 1.5 seconds
            setTimeout(() => {
                closeChangePasswordModal();
            }, 1500);
        } else {
            const data = await response.json();
            showLocalMessage('change-password-message', data.error || data.detail || 'Failed to change password', 'error');
        }
    } catch (e) {
        console.error('Change password error:', e);
        showLocalMessage('change-password-message', 'Network error', 'error');
    }
}

function showChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    modal.classList.remove('hidden');
    // Clear fields
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-new-password').value = '';
    // Hide any messages
    document.getElementById('change-password-message').classList.add('hidden');
}

function closeChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    modal.classList.add('hidden');
    // Clear fields
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-new-password').value = '';
    // Hide message
    document.getElementById('change-password-message').classList.add('hidden');
}

// Local settings message with auto-hide after 4 seconds
function showLocalMessage(elementId, message, type) {
    const msgEl = document.getElementById(elementId);
    if (!msgEl) return;
    
    msgEl.textContent = message;
    msgEl.className = 'local-settings-message ' + type;
    msgEl.classList.remove('hidden');
    
    // Auto-hide after 4 seconds
    setTimeout(() => {
        msgEl.classList.add('hidden');
    }, 4000);
}

// Deprecated - keeping for backward compatibility if needed elsewhere
function showSettingsMessage(message, type) {
    // This function is deprecated, but keeping it to avoid breaking existing code
    console.warn('showSettingsMessage is deprecated, use showLocalMessage instead');
}

function hideSettingsMessage() {
    // Deprecated
}

// ==================== TWO-FACTOR AUTHENTICATION (TOTP) ====================

// Temporary storage for TOTP setup
let totpSetupData = {
    secret: null,
    recoveryCodes: []
};

// Pending login credentials for TOTP verification
let pendingLoginCredentials = null;

async function loadTOTPStatus() {
    try {
        const response = await api('/auth/totp/status');
        if (response.ok) {
            const data = await response.json();
            updateTOTPUI(data.enabled);
        }
    } catch (e) {
        console.error('Failed to load TOTP status:', e);
    }
}

function updateTOTPUI(enabled) {
    const statusEl = document.getElementById('totp-status');
    const statusText = document.getElementById('totp-status-text');
    const disabledSection = document.getElementById('totp-disabled-section');
    const enabledSection = document.getElementById('totp-enabled-section');
    
    if (enabled) {
        statusText.textContent = '✓ Enabled';
        statusEl.classList.add('enabled');
        statusEl.classList.remove('disabled');
        disabledSection.classList.add('hidden');
        enabledSection.classList.remove('hidden');
    } else {
        statusText.textContent = 'Disabled';
        statusEl.classList.add('disabled');
        statusEl.classList.remove('enabled');
        disabledSection.classList.remove('hidden');
        enabledSection.classList.add('hidden');
    }
}

async function setupTOTP() {
    try {
        const response = await api('/auth/totp/setup', {
            method: 'POST'
        });
        
        if (response.ok) {
            const data = await response.json();
            totpSetupData.secret = data.secret;
            
            // Show QR code
            const qrContainer = document.getElementById('totp-qr-container');
            qrContainer.innerHTML = '<img src="data:image/png;base64,' + data.qr_code + '" alt="QR Code">';
            
            // Show secret
            document.getElementById('totp-secret-code').textContent = data.secret;
            
            // Reset modal state
            document.getElementById('totp-setup-step1').classList.remove('hidden');
            document.getElementById('totp-setup-step2').classList.add('hidden');
            document.getElementById('totp-verify-code').value = '';
            document.getElementById('totp-setup-error').classList.add('hidden');
            
            // Show modal
            document.getElementById('totp-setup-modal').classList.remove('hidden');
        } else {
            const data = await response.json();
            showLocalMessage('totp-message', data.detail || 'Failed to setup 2FA', 'error');
        }
    } catch (e) {
        console.error('TOTP setup error:', e);
        showLocalMessage('totp-message', 'Network error', 'error');
    }
}

function hideTOTPSetupModal() {
    document.getElementById('totp-setup-modal').classList.add('hidden');
}

async function verifyAndEnableTOTP() {
    const code = document.getElementById('totp-verify-code').value.trim();
    const errorEl = document.getElementById('totp-setup-error');
    
    if (!code || code.length !== 6) {
        errorEl.textContent = 'Enter a 6-digit code';
        errorEl.classList.remove('hidden');
        return;
    }
    
    try {
        const response = await api('/auth/totp/enable', {
            method: 'POST',
            body: JSON.stringify({ code })
        });
        
        if (response.ok) {
            const data = await response.json();
            totpSetupData.recoveryCodes = data.recovery_codes;
            
            // Show recovery codes
            const codesContainer = document.getElementById('recovery-codes');
            codesContainer.innerHTML = data.recovery_codes.map(function(code) {
                return '<div class="code">' + escapeHtml(code) + '</div>';
            }).join('');
            
            // Switch to step 2
            // КАО#347: markup is a 3-step flow (1 QR, 2 verify, 3 success+codes); the code was written
            // for an older 2-step version and revealed step2 — the verification pane — after success.
            document.getElementById('totp-setup-step1').classList.add('hidden');
            document.getElementById('totp-setup-step2').classList.add('hidden');
            document.getElementById('totp-setup-step3').classList.remove('hidden');
        } else {
            const data = await response.json();
            errorEl.textContent = data.detail || 'Invalid code';
            errorEl.classList.remove('hidden');
        }
    } catch (e) {
        console.error('TOTP enable error:', e);
        errorEl.textContent = 'Network error';
        errorEl.classList.remove('hidden');
    }
}

function copyRecoveryCodes() {
    const codes = totpSetupData.recoveryCodes.join('\n');
    navigator.clipboard.writeText(codes).then(function() {
        showLocalMessage('totp-message', 'Recovery codes copied!', 'success');
    }).catch(function() {
        showLocalMessage('totp-message', 'Failed to copy', 'error');
    });
}

function finishTOTPSetup() {
    hideTOTPSetupModal();
    updateTOTPUI(true);
    showLocalMessage('totp-message', 'Two-factor authentication enabled!', 'success');
}

// TOTP Login Modal
function showTOTPLoginModal(username, password, deviceId) {
    pendingLoginCredentials = { username, password, deviceId };
    document.getElementById('totp-login-code').value = '';
    document.getElementById('totp-login-error').classList.add('hidden');
    // КАО#367: reset the recovery field on every open. It was never cleared and its section was never
    // re-hidden, so anything left there from a previous attempt kept winning over the 6-digit code below.
    const _recSec = document.getElementById('recovery-code-section');
    const _recIn = document.getElementById('recovery-code-input');
    if (_recIn) _recIn.value = '';
    if (_recSec) _recSec.classList.add('hidden');
    document.getElementById('totp-login-modal').classList.remove('hidden');
    document.getElementById('totp-login-code').focus();
}

function hideTOTPLoginModal() {
    document.getElementById('totp-login-modal').classList.add('hidden');
    pendingLoginCredentials = null;
}

// КАО#328: referenced by the "Use recovery code" link in the 2FA modal but never defined — clicking it
// threw and left the user stuck. Reveals the recovery-code field; submitTOTPLogin() accepts either input
// (the server takes a TOTP code or a recovery code in the same field).
function showRecoveryCodeInput() {
    const section = document.getElementById('recovery-code-section');
    if (section) section.classList.remove('hidden');
    // КАО#367: blank the 6-digit field when switching modes, so the two can never both hold a value.
    const totpIn = document.getElementById('totp-login-code');
    if (totpIn) totpIn.value = '';
    const input = document.getElementById('recovery-code-input');
    if (input) input.focus();
}

async function submitTOTPLogin() {
    if (!pendingLoginCredentials) return;

    // КАО#328: accept whichever field the user filled in — the 6-digit code or a recovery code.
    // КАО#367: but only honour the recovery field while its section is actually VISIBLE, and let a freshly
    // typed 6-digit code win. `recovery || totp` meant that once a wrong/spent recovery code had been typed,
    // every later Verify press re-sent that stale string and silently discarded the correct TOTP code — with
    // no way out of the modal, while burning the 5/min login limit until the user hit 429.
    const _recSec = document.getElementById('recovery-code-section');
    const recoveryEl = document.getElementById('recovery-code-input');
    const recovery = (recoveryEl && _recSec && !_recSec.classList.contains('hidden'))
        ? recoveryEl.value.trim() : '';
    const totpVal = document.getElementById('totp-login-code').value.trim();
    const code = totpVal || recovery;
    const errorEl = document.getElementById('totp-login-error');

    if (!code) {
        errorEl.textContent = 'Enter your verification code';
        errorEl.classList.remove('hidden');
        return;
    }
    
    try {
        const response = await api('/auth/login', {
            method: 'POST',
            body: JSON.stringify({
                username: pendingLoginCredentials.username,
                password: pendingLoginCredentials.password,
                device_id: pendingLoginCredentials.deviceId,
                totp_code: code
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            hideTOTPLoginModal();
            handleAuthSuccess(data);
        } else {
            errorEl.textContent = data.detail || data.error || 'Invalid code';
            errorEl.classList.remove('hidden');
        }
    } catch (e) {
        console.error('TOTP login error:', e);
        errorEl.textContent = 'Network error';
        errorEl.classList.remove('hidden');
    }
}

// Disable TOTP Modal
function showDisableTOTPModal() {
    document.getElementById('disable-totp-password').value = '';
    document.getElementById('disable-totp-code').value = '';
    document.getElementById('disable-totp-error').classList.add('hidden');
    document.getElementById('disable-totp-modal').classList.remove('hidden');
}

function hideDisableTOTPModal() {
    document.getElementById('disable-totp-modal').classList.add('hidden');
}

async function disableTOTP() {
    const password = document.getElementById('disable-totp-password').value;
    const code = document.getElementById('disable-totp-code').value.trim();
    const errorEl = document.getElementById('disable-totp-error');
    
    if (!password || !code) {
        errorEl.textContent = 'Enter both password and verification code';
        errorEl.classList.remove('hidden');
        return;
    }
    
    try {
        const response = await api('/auth/totp/disable', {
            method: 'POST',
            body: JSON.stringify({ password, code })
        });
        
        if (response.ok) {
            hideDisableTOTPModal();
            updateTOTPUI(false);
            showLocalMessage('totp-message', 'Two-factor authentication disabled', 'success');
        } else {
            const data = await response.json();
            errorEl.textContent = data.detail || 'Failed to disable 2FA';
            errorEl.classList.remove('hidden');
        }
    } catch (e) {
        console.error('TOTP disable error:', e);
        errorEl.textContent = 'Network error';
        errorEl.classList.remove('hidden');
    }
}

// Regenerate Recovery Codes Modal
function showRegenerateCodesModal() {
    // КАО#347: the markup has a single-pane regenerate dialog (no step1/step2 elements) — reset the
    // output area instead of toggling steps that never existed.
    const _newCodes = document.getElementById('new-recovery-codes');
    if (_newCodes) { _newCodes.innerHTML = ''; _newCodes.classList.add('hidden'); }
    document.getElementById('regenerate-totp-code').value = '';
    document.getElementById('regenerate-totp-error').classList.add('hidden');
    document.getElementById('regenerate-codes-modal').classList.remove('hidden');
}

function hideRegenerateCodesModal() {
    document.getElementById('regenerate-codes-modal').classList.add('hidden');
}

async function regenerateRecoveryCodes() {
    const code = document.getElementById('regenerate-totp-code').value.trim();
    const errorEl = document.getElementById('regenerate-totp-error');
    
    if (!code || code.length !== 6) {
        errorEl.textContent = 'Enter a 6-digit code';
        errorEl.classList.remove('hidden');
        return;
    }
    
    try {
        const response = await api('/auth/totp/regenerate-recovery-codes', {
            method: 'POST',
            body: JSON.stringify({ code })
        });
        
        if (response.ok) {
            const data = await response.json();
            totpSetupData.recoveryCodes = data.recovery_codes;
            
            // Show new recovery codes
            const codesContainer = document.getElementById('new-recovery-codes');
            codesContainer.classList.remove('hidden');  // КАО#347: starts hidden in the markup
            codesContainer.innerHTML = data.recovery_codes.map(function(code) {
                return '<div class="code">' + escapeHtml(code) + '</div>';
            }).join('');
            
            // Switch to step 2
            // КАО#347: single-pane dialog — the codes container above is revealed instead of switching
            // to a "step2" element that does not exist in the markup (this threw and aborted the handler
            // AFTER the server had already rotated the codes, so the user never saw their new codes).
            const _regenBtn = document.getElementById('regenerate-codes-confirm-btn');
            if (_regenBtn) _regenBtn.classList.add('hidden');
        } else {
            const data = await response.json();
            errorEl.textContent = data.detail || 'Invalid code';
            errorEl.classList.remove('hidden');
        }
    } catch (e) {
        console.error('Regenerate codes error:', e);
        errorEl.textContent = 'Network error';
        errorEl.classList.remove('hidden');
    }
}

function copyNewRecoveryCodes() {
    const codes = totpSetupData.recoveryCodes.join('\n');
    navigator.clipboard.writeText(codes).then(function() {
        showLocalMessage('totp-message', 'Recovery codes copied!', 'success');
    }).catch(function() {
        showLocalMessage('totp-message', 'Failed to copy', 'error');
    });
}

// ==================== VOICE CALLS ====================

function attachRemoteAudio(retryCount) {
    retryCount = retryCount || 0;
    console.log('attachRemoteAudio called, retry:', retryCount, 'remoteStream:', !!state.remoteStream);
    
    if (!state.remoteStream) {
        console.log('No remote stream yet');
        if (retryCount < 10) {
            setTimeout(function() { attachRemoteAudio(retryCount + 1); }, 300);
        }
        return;
    }
    
    var audio = document.getElementById('remote-audio');
    console.log('Audio element found:', !!audio);
    
    if (!audio) {
        console.log('No audio element, retrying...');
        if (retryCount < 10) {
            setTimeout(function() { attachRemoteAudio(retryCount + 1); }, 300);
        }
        return;
    }
    
    console.log('Attaching remote stream to audio element');
    audio.srcObject = state.remoteStream;
    audio.volume = 1;
    audio.muted = false;
    audio.play().then(function() {
        console.log('Audio playing successfully');
    }).catch(function(e) {
        console.log('Audio play error:', e);
    });
}

// Call menu
function toggleCallMenu() {
    const menu = document.getElementById('call-menu');
    if (menu) {
        menu.classList.toggle('hidden');
    }
}

// Close call menu when clicking outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('call-menu');
    const btn = document.getElementById('call-btn');
    if (menu && !menu.contains(e.target) && e.target !== btn) {
        menu.classList.add('hidden');
    }
});

async function startCall(withVideo = false) {
    // Close call menu
    const menu = document.getElementById('call-menu');
    if (menu) menu.classList.add('hidden');
    
    if (!state.currentChatId) {
        alert('Open a chat first');
        return;
    }
    
    if (state.call) {
        alert('Already in a call');
        return;
    }
    
    // Check call permission
    if (state.permissions && !state.permissions.can_call) {
        showPermissionError('You are not allowed to make calls');
        return;
    }
    
    // Load ICE servers from backend before starting call
    await loadIceServers();
    
    try {
        console.log('Starting ' + (withVideo ? 'video' : 'audio') + ' call to:', state.currentChatId);
        console.log('TURN config ready, servers:', rtcConfig.iceServers.length);
        
        // Get media access
        const constraints = {
            audio: isSafari || isIOS ? true : audioConstraints.audio,
            video: withVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false
        };
        state.localStream = await navigator.mediaDevices.getUserMedia(constraints);
        console.log('Got local stream, video:', withVideo);
        
        // Create peer connection
        state.peerConnection = new RTCPeerConnection(rtcConfig);
        console.log('Created peer connection');
        
        // Add local stream
        state.localStream.getTracks().forEach(track => {
            state.peerConnection.addTrack(track, state.localStream);
        });
        
        // Handle ICE candidates
        state.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                // Log candidate type for debugging
                const candidate = event.candidate;
                const candidateType = candidate.candidate.includes('relay') ? 'RELAY (TURN)' :
                                     candidate.candidate.includes('srflx') ? 'SRFLX (STUN)' :
                                     candidate.candidate.includes('host') ? 'HOST (local)' : 'unknown';
                console.log('ICE candidate:', candidateType, candidate.candidate.substring(0, 80));
                
                sendWS('ice_candidate', {
                    target_id: state.currentChatId,
                    candidate: event.candidate
                });
            }
        };
        
        // Log ICE gathering state
        state.peerConnection.onicegatheringstatechange = () => {
            console.log('ICE gathering state:', state.peerConnection.iceGatheringState);
        };
        
        // Handle remote stream
        state.peerConnection.ontrack = (event) => {
            console.log('Remote track received:', event.track.kind);
            state.remoteStream = event.streams[0];
            setTimeout(() => attachRemoteMedia(), 300);
        };
        
        // ICE connection state monitoring
        state.peerConnection.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', state.peerConnection.iceConnectionState);
            handleIceConnectionStateChange();
        };
        
        // Connection state
        state.peerConnection.onconnectionstatechange = () => {
            console.log('Connection state:', state.peerConnection.connectionState);
            if (state.peerConnection.connectionState === 'connected') {
                setTimeout(() => attachRemoteMedia(), 300);
                startCallKeepalive();
            } else if (state.peerConnection.connectionState === 'failed') {
                console.log('Connection failed, attempting restart...');
                attemptIceRestart();
            } else if (state.peerConnection.connectionState === 'disconnected') {
                console.log('Connection disconnected, waiting for recovery...');
                setTimeout(() => {
                    if (state.peerConnection && state.peerConnection.connectionState === 'disconnected') {
                        attemptIceRestart();
                    }
                }, 3000);
            }
        };
        
        // Create offer
        const offer = await state.peerConnection.createOffer();
        await state.peerConnection.setLocalDescription(offer);
        console.log('Created and set local offer');
        
        // Send offer
        state.call = {
            peerId: state.currentChatId,
            direction: 'outgoing',
            status: 'calling',
            isVideo: withVideo,
            isMuted: false,
            isCameraOff: false,
            currentFacingMode: 'user'
        };
        
        sendWS('call_offer', {
            target_id: state.currentChatId,
            offer: offer,
            isVideo: withVideo
        });
        console.log('Sent call offer');
        
        showCallUI('outgoing', null, withVideo);
        playDialingSound();  // Play dialing tone while waiting for answer
        
    } catch (e) {
        console.error('Failed to start call:', e);
        alert('Failed to access ' + (withVideo ? 'camera/microphone' : 'microphone') + ': ' + e.message);
        endCall();
    }
}

async function handleIncomingCall(payload) {
    console.log('Incoming call from:', payload.caller_id, 'isVideo:', payload.isVideo);

    // КАО#277 (#11): an ICE-restart re-offer arrives as a call_offer DURING the active call. Renegotiate
    // on the existing peer connection instead of treating it as a new call (the busy-check below would
    // reply 'busy' and tear the call down). The answer flows back through handleCallAnswer.
    if (payload.iceRestart && state.call && state.peerConnection && state.call.peerId === payload.caller_id) {
        try {
            await state.peerConnection.setRemoteDescription(new RTCSessionDescription(payload.offer));
            const answer = await state.peerConnection.createAnswer();
            await state.peerConnection.setLocalDescription(answer);
            sendWS('call_answer', { target_id: payload.caller_id, answer: answer });
            console.log('[Call] Applied ICE-restart re-offer, sent answer');
        } catch (e) {
            console.error('[Call] ICE-restart renegotiation failed:', e);
        }
        return;
    }

    if (state.call) {
        // Already in a call, reject
        sendWS('call_end', { target_id: payload.caller_id, reason: 'busy' });
        return;
    }
    
    // Get caller info - first check local chats, then fetch from server
    let callerName = payload.caller_id;
    
    if (state.chats[payload.caller_id]) {
        callerName = state.chats[payload.caller_id].displayName || state.chats[payload.caller_id].username;
    } else {
        // Fetch user info from server
        try {
            const response = await api('/auth/user/id/' + payload.caller_id);
            if (response.ok) {
                const userData = await response.json();
                callerName = userData.display_name || userData.username;
                // Save to chats for future reference
                state.chats[payload.caller_id] = {
                    id: payload.caller_id,
                    username: userData.username,
                    displayName: userData.display_name || userData.username,
                    avatar_url: userData.avatar_url || null,
                    messages: [],
                    unreadCount: 0,
                    missedCalls: 0
                };
                saveChats();
            }
        } catch (e) {
            console.error('Failed to get caller info:', e);
        }
    }
    
    state.call = {
        peerId: payload.caller_id,
        direction: 'incoming',
        status: 'ringing',
        offer: payload.offer,
        isVideo: payload.isVideo || false,
        isMuted: false,
        isCameraOff: false,
        currentFacingMode: 'user'
    };
    
    showCallUI('incoming', callerName, payload.isVideo);
}

async function acceptCall() {
    if (!state.call || state.call.status !== 'ringing') return;
    
    stopCallSound();
    
    // Load ICE servers from backend before accepting call
    await loadIceServers();
    
    const isVideo = state.call.isVideo;
    
    try {
        console.log('Accepting ' + (isVideo ? 'video' : 'audio') + ' call from:', state.call.peerId);
        console.log('TURN config ready, servers:', rtcConfig.iceServers.length);
        
        // Get media access
        const constraints = {
            audio: isSafari || isIOS ? true : audioConstraints.audio,
            video: isVideo ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false
        };
        state.localStream = await navigator.mediaDevices.getUserMedia(constraints);
        console.log('Got local stream, video:', isVideo);
        
        // Create peer connection
        state.peerConnection = new RTCPeerConnection(rtcConfig);
        console.log('Created peer connection');
        
        // Add local stream
        state.localStream.getTracks().forEach(track => {
            state.peerConnection.addTrack(track, state.localStream);
        });
        
        // Handle ICE candidates
        state.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                // Log candidate type for debugging
                const candidate = event.candidate;
                const candidateType = candidate.candidate.includes('relay') ? 'RELAY (TURN)' :
                                     candidate.candidate.includes('srflx') ? 'SRFLX (STUN)' :
                                     candidate.candidate.includes('host') ? 'HOST (local)' : 'unknown';
                console.log('ICE candidate:', candidateType, candidate.candidate.substring(0, 80));
                
                sendWS('ice_candidate', {
                    target_id: state.call.peerId,
                    candidate: event.candidate
                });
            }
        };
        
        // Log ICE gathering state
        state.peerConnection.onicegatheringstatechange = () => {
            console.log('ICE gathering state:', state.peerConnection.iceGatheringState);
        };
        
        // Handle remote stream
        state.peerConnection.ontrack = (event) => {
            console.log('Remote track received:', event.track.kind);
            state.remoteStream = event.streams[0];
            setTimeout(() => attachRemoteMedia(), 300);
        };
        
        // ICE connection state monitoring
        state.peerConnection.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', state.peerConnection.iceConnectionState);
            handleIceConnectionStateChange();
        };
        
        // Connection state
        state.peerConnection.onconnectionstatechange = () => {
            console.log('Connection state:', state.peerConnection.connectionState);
            if (state.peerConnection.connectionState === 'connected') {
                setTimeout(() => attachRemoteMedia(), 300);
                startCallKeepalive();
            } else if (state.peerConnection.connectionState === 'failed') {
                console.log('Connection failed, attempting restart...');
                attemptIceRestart();
            } else if (state.peerConnection.connectionState === 'disconnected') {
                console.log('Connection disconnected, waiting for recovery...');
                setTimeout(() => {
                    if (state.peerConnection && state.peerConnection.connectionState === 'disconnected') {
                        attemptIceRestart();
                    }
                }, 3000);
            }
        };
        
        // Set remote description (the offer)
        await state.peerConnection.setRemoteDescription(new RTCSessionDescription(state.call.offer));
        console.log('Set remote description');
        
        // Process buffered ICE candidates
        console.log('Processing', state.iceCandidateBuffer.length, 'buffered ICE candidates');
        for (const candidate of state.iceCandidateBuffer) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                console.error('Failed to add buffered ICE candidate:', e);
            }
        }
        state.iceCandidateBuffer = [];
        
        // Create answer
        const answer = await state.peerConnection.createAnswer();
        await state.peerConnection.setLocalDescription(answer);
        console.log('Created and set local answer');
        
        // Send answer
        sendWS('call_answer', {
            target_id: state.call.peerId,
            answer: answer
        });
        console.log('Sent call answer');
        
        state.call.status = 'active';
        showCallUI('active', null, isVideo);
        
    } catch (e) {
        console.error('Failed to accept call:', e);
        alert('Failed to access ' + (isVideo ? 'camera/microphone' : 'microphone') + ': ' + e.message);
        endCall();
    }
}

function rejectCall() {
    if (!state.call) return;
    
    sendWS('call_end', { target_id: state.call.peerId, reason: 'rejected' });
    endCall();
}

async function handleCallAnswer(payload) {
    console.log('Call answered, setting remote description');
    
    stopDialingSound();  // Stop dialing tone
    
    if (!state.peerConnection) {
        console.error('No peer connection');
        return;
    }
    
    try {
        await state.peerConnection.setRemoteDescription(new RTCSessionDescription(payload.answer));
        console.log('Remote description set');
        state.call.status = 'active';
        showCallUI('active', null, state.call.isVideo);
        
        // Process buffered ICE candidates
        console.log('Processing', state.iceCandidateBuffer.length, 'buffered ICE candidates');
        for (const candidate of state.iceCandidateBuffer) {
            try {
                await state.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
            } catch (e) {
                console.error('Failed to add buffered ICE candidate:', e);
            }
        }
        state.iceCandidateBuffer = [];
        
        // Attach audio after answer
        setTimeout(function() { attachRemoteAudio(0); }, 500);
    } catch (e) {
        console.error('Failed to handle answer:', e);
        endCall();
    }
}

async function handleIceCandidate(payload) {
    if (!state.peerConnection) {
        console.log('No peer connection, buffering ICE candidate');
        state.iceCandidateBuffer.push(payload.candidate);
        return;
    }
    
    if (!state.peerConnection.remoteDescription) {
        console.log('No remote description yet, buffering ICE candidate');
        state.iceCandidateBuffer.push(payload.candidate);
        return;
    }
    
    try {
        await state.peerConnection.addIceCandidate(new RTCIceCandidate(payload.candidate));
        console.log('ICE candidate added');
    } catch (e) {
        console.error('Failed to add ICE candidate:', e);
    }
}

// Call stability helpers
var callKeepaliveInterval = null;
var iceRestartAttempts = 0;
const MAX_ICE_RESTART_ATTEMPTS = 3;

function handleIceConnectionStateChange() {
    if (!state.peerConnection) return;
    
    const iceState = state.peerConnection.iceConnectionState;
    console.log('ICE state changed to:', iceState);
    
    if (iceState === 'failed') {
        console.log('ICE connection failed, attempting restart...');
        attemptIceRestart();
    } else if (iceState === 'disconnected') {
        console.log('ICE disconnected, will attempt restart if not recovered');
        setTimeout(() => {
            if (state.peerConnection && state.peerConnection.iceConnectionState === 'disconnected') {
                attemptIceRestart();
            }
        }, 5000);
    } else if (iceState === 'connected' || iceState === 'completed') {
        iceRestartAttempts = 0;  // Reset counter on successful connection
    }
}

async function attemptIceRestart() {
    if (!state.peerConnection || !state.call) {
        console.log('No active call, skipping ICE restart');
        return;
    }
    
    if (iceRestartAttempts >= MAX_ICE_RESTART_ATTEMPTS) {
        console.log('Max ICE restart attempts reached, ending call');
        showSystemNotification('Call connection lost');
        endCall();
        return;
    }
    
    iceRestartAttempts++;
    console.log('Attempting ICE restart, attempt', iceRestartAttempts);
    
    try {
        const offer = await state.peerConnection.createOffer({ iceRestart: true });
        await state.peerConnection.setLocalDescription(offer);
        
        sendWS('call_offer', {
            target_id: state.call.peerId,
            offer: offer,
            iceRestart: true
        });
        console.log('Sent ICE restart offer');
    } catch (e) {
        console.error('ICE restart failed:', e);
    }
}

function startCallKeepalive() {
    stopCallKeepalive();
    
    // Send keepalive ping every 10 seconds
    callKeepaliveInterval = setInterval(() => {
        if (state.call && state.call.peerId) {
            sendWS('call_ping', { target_id: state.call.peerId });
        }
    }, 10000);
}

function stopCallKeepalive() {
    if (callKeepaliveInterval) {
        clearInterval(callKeepaliveInterval);
        callKeepaliveInterval = null;
    }
}

function handleCallEnded(payload) {
    console.log('Call ended:', payload.reason);
    
    stopDialingSound();
    
    // Check if this was a missed incoming call (we were ringing but didn't answer)
    if (state.call && state.call.status === 'ringing' && state.call.direction === 'incoming') {
        const callerId = state.call.peerId;
        if (state.chats[callerId]) {
            state.chats[callerId].missedCalls = (state.chats[callerId].missedCalls || 0) + 1;
            saveChats();
            renderChatsList();
        }
        // Add missed call message
        addCallMessage(callerId, 'missed', 0, state.call.isVideo);
    }
    
    // Check if outgoing call was not answered
    if (state.call && state.call.status === 'calling' && state.call.direction === 'outgoing') {
        const reason = payload.reason || 'offline';
        const msgType = reason === 'rejected' ? 'declined' : reason === 'busy' ? 'declined' : 'no_answer';
        addCallMessage(state.call.peerId, msgType, 0, state.call.isVideo);
    }
    
    // Check if active call was ended by the other party
    if (state.call && state.call.status === 'active') {
        const duration = callStartTime ? Math.floor((Date.now() - callStartTime) / 1000) : 0;
        addCallMessage(state.call.peerId, 'ended', duration, state.call.isVideo, state.call.direction);
    }
    
    endCall(true);  // Pass flag to skip adding message again
}

function endCall(skipMessage = false) {
    console.log('Ending call');
    
    stopCallSound();
    stopDialingSound();
    
    // Stop keepalive
    stopCallKeepalive();
    iceRestartAttempts = 0;
    
    // Stop screen sharing if active
    if (state.call?.isScreenSharing && state.call.screenTrack) {
        state.call.screenTrack.stop();
    }
    if (state.call?.screenAudioTrack) {
        state.call.screenAudioTrack.stop();
    }
    hideScreenShareIndicator();
    
    // Calculate call duration and add message
    if (!skipMessage && state.call && state.call.peerId) {
        const duration = callStartTime ? Math.floor((Date.now() - callStartTime) / 1000) : 0;
        let reason = 'ended';
        
        if (state.call.status === 'active' && duration > 0) {
            // Call was connected and ended normally
            addCallMessage(state.call.peerId, 'ended', duration, state.call.isVideo, state.call.direction);
        } else if (state.call.status === 'calling' && state.call.direction === 'outgoing') {
            // Outgoing call was cancelled before answer
            addCallMessage(state.call.peerId, 'cancelled', 0, state.call.isVideo, 'outgoing');
        } else if (state.call.status === 'ringing' && state.call.direction === 'incoming') {
            // Incoming call was rejected by us
            addCallMessage(state.call.peerId, 'declined', 0, state.call.isVideo, 'incoming');
            reason = 'rejected';
        }
        
        sendWS('call_end', { target_id: state.call.peerId, reason: reason });
    }
    
    // Stop timer
    stopCallTimer();
    
    if (state.localStream) {
        state.localStream.getTracks().forEach(track => track.stop());
        state.localStream = null;
    }
    
    if (state.peerConnection) {
        state.peerConnection.close();
        state.peerConnection = null;
    }
    
    state.remoteStream = null;
    state.call = null;
    state.iceCandidateBuffer = [];
    
    hideCallUI();
}

function showCallUI(type, callerName, isVideo = false) {
    let callModal = document.getElementById('call-modal');
    if (!callModal) {
        callModal = document.createElement('div');
        callModal.id = 'call-modal';
        callModal.className = 'call-modal';
        document.body.appendChild(callModal);
    }
    
    // Update isVideo from state if available
    if (state.call && state.call.isVideo !== undefined) {
        isVideo = state.call.isVideo;
    }
    
    let html = '<div class="call-content' + (isVideo ? '' : ' audio-only') + '">';
    
    // Video elements (always include, show/hide based on isVideo)
    if (isVideo) {
        html += '<div class="call-video-container">';
        html += '<video id="remote-video" class="remote-video" autoplay playsinline></video>';
        html += '<div class="local-video-wrapper">';
        html += '<video id="local-video" class="local-video" autoplay playsinline muted></video>';
        html += '</div>';
        html += '</div>';
    }
    
    // Audio element (always needed)
    html += '<audio id="remote-audio" autoplay playsinline></audio>';
    
    // Call info overlay
    html += '<div class="call-info-overlay">';
    
    if (type === 'incoming') {
        const callTypeText = isVideo ? 'Incoming video call' : 'Incoming voice call';
        html += '<div class="call-status">' + callTypeText + '</div>';
        html += '<div class="call-name">' + escapeHtml(callerName || 'Unknown') + '</div>';
    } else if (type === 'outgoing') {
        html += '<div class="call-status calling">Calling...</div>';
        html += '<div class="call-name">' + escapeHtml(state.currentChat?.displayName || state.currentChat?.username || 'User') + '</div>';
    } else if (type === 'active') {
        html += '<div class="call-status">Connected</div>';
        html += '<div class="call-timer" id="call-timer">00:00</div>';
    }
    
    html += '</div>'; // end call-info-overlay
    
    // Avatar for audio-only calls
    if (!isVideo) {
        const displayName = callerName || state.currentChat?.displayName || state.currentChat?.username || 'User';
        const initial = escapeHtml(displayName.charAt(0).toUpperCase());
        html += '<div class="call-avatar">' + initial + '</div>';
    }
    
    // Call actions
    html += '<div class="call-actions">';
    
    if (type === 'incoming') {
        // Reject call button (red phone icon - industry standard)
        html += '<button class="call-btn reject" onclick="rejectCall()">';
        html += '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">';
        html += '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>';
        html += '</svg>';
        html += '</button>';
        html += '<button class="call-btn accept" onclick="acceptCall()">' + (isVideo ? '📹' : '<svg class="phone-icon" viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/></svg>') + '</button>';
    } else if (type === 'outgoing') {
        // End call button (red phone icon - industry standard)
        html += '<button class="call-btn reject" onclick="endCall()">';
        html += '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">';
        html += '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>';
        html += '</svg>';
        html += '</button>';
    } else if (type === 'active') {
        // Mute button (КАО#283 #32: accessible name)
        const isMuted = state.call?.isMuted || false;
        html += '<button id="mute-btn" aria-label="Toggle microphone" aria-pressed="' + (isMuted ? 'true' : 'false') + '" class="call-btn' + (isMuted ? ' muted' : '') + '" onclick="toggleMute()">';
        html += isMuted ? '🔇' : '🎤';
        html += '</button>';

        // Camera button (only for video calls)
        if (isVideo) {
            const isCameraOff = state.call?.isCameraOff || false;
            html += '<button id="camera-btn" aria-label="Toggle camera" aria-pressed="' + (isCameraOff ? 'true' : 'false') + '" class="call-btn' + (isCameraOff ? ' muted' : '') + '" onclick="toggleCamera()">';
            html += isCameraOff ? '📷' : '📹';
            html += '</button>';

            // Switch camera button (mobile only)
            if (/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)) {
                html += '<button class="call-btn" aria-label="Switch camera" onclick="switchCamera()">🔄</button>';
            }

            // Screen share button (desktop only)
            if (!/Android|iPhone|iPad|iPod/i.test(navigator.userAgent)) {
                const isScreenSharing = state.call?.isScreenSharing || false;
                html += '<button id="screen-share-btn" aria-label="Toggle screen share" aria-pressed="' + (isScreenSharing ? 'true' : 'false') + '" class="call-btn' + (isScreenSharing ? ' active' : '') + '" onclick="toggleScreenShare()">';
                html += isScreenSharing ? '🖥️' : '🖥️';
                html += '</button>';
            }
        }
        
        // Audio output button
        html += '<div class="audio-output-wrapper">';
        html += '<button id="audio-output-btn" aria-label="Audio output" class="call-btn" onclick="toggleAudioOutputMenu()">';
        html += getAudioOutputIcon();
        html += '</button>';
        html += '<div id="audio-output-menu" class="audio-output-menu"></div>';
        html += '</div>';

        // End call button (red phone icon - industry standard)
        html += '<button class="call-btn reject" aria-label="End call" onclick="endCall()">';
        html += '<svg width="28" height="28" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">';
        html += '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>';
        html += '</svg>';
        html += '</button>';
        
        startCallTimer();
        // Initialize audio output after UI is ready
        setTimeout(initAudioOutputSelector, 100);
    }
    
    html += '</div>'; // end call-actions
    html += '</div>'; // end call-content
    
    callModal.innerHTML = html;
    callModal.classList.add('active');
    
    // Attach media streams after UI is created
    setTimeout(() => {
        attachRemoteMedia();
        attachLocalVideo();
    }, 200);
}

// Attach remote media (audio and/or video)
function attachRemoteMedia() {
    if (!state.remoteStream) {
        console.log('No remote stream yet');
        return;
    }
    
    // Attach video if video call
    const remoteVideo = document.getElementById('remote-video');
    if (remoteVideo && state.call?.isVideo) {
        remoteVideo.srcObject = state.remoteStream;
        remoteVideo.play().catch(e => console.log('Remote video play error:', e));
    }
    
    // Always attach audio
    const remoteAudio = document.getElementById('remote-audio');
    if (remoteAudio) {
        remoteAudio.srcObject = state.remoteStream;
        remoteAudio.play().catch(e => console.log('Remote audio play error:', e));
    }
}

// Attach local video preview
function attachLocalVideo() {
    if (!state.localStream || !state.call?.isVideo) return;
    
    const localVideo = document.getElementById('local-video');
    if (localVideo) {
        localVideo.srcObject = state.localStream;
        localVideo.play().catch(e => console.log('Local video play error:', e));
    }
}

// Toggle microphone mute
function toggleMute() {
    if (!state.localStream || !state.call) return;
    
    const audioTrack = state.localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        state.call.isMuted = !audioTrack.enabled;
        
        const muteBtn = document.getElementById('mute-btn');
        if (muteBtn) {
            muteBtn.innerHTML = state.call.isMuted ? '🔇' : '🎤';
            muteBtn.classList.toggle('muted', state.call.isMuted);
            muteBtn.setAttribute('aria-pressed', state.call.isMuted ? 'true' : 'false');  // КАО#283 Round-2: keep aria-pressed in sync
        }
        console.log('Microphone', state.call.isMuted ? 'muted' : 'unmuted');
    }
}

// Toggle camera on/off
function toggleCamera() {
    if (!state.localStream || !state.call) return;
    
    const videoTrack = state.localStream.getVideoTracks()[0];
    if (videoTrack) {
        videoTrack.enabled = !videoTrack.enabled;
        state.call.isCameraOff = !videoTrack.enabled;
        
        const cameraBtn = document.getElementById('camera-btn');
        if (cameraBtn) {
            cameraBtn.innerHTML = state.call.isCameraOff ? '📷' : '📹';
            cameraBtn.classList.toggle('muted', state.call.isCameraOff);
            cameraBtn.setAttribute('aria-pressed', state.call.isCameraOff ? 'true' : 'false');  // КАО#283 Round-2
        }
        
        // Show/hide local video preview
        const localVideo = document.getElementById('local-video');
        if (localVideo) {
            localVideo.style.opacity = state.call.isCameraOff ? '0.3' : '1';
        }
        
        console.log('Camera', state.call.isCameraOff ? 'off' : 'on');
    }
}

// Switch between front and back camera
async function switchCamera() {
    if (!state.localStream || !state.call?.isVideo) return;
    
    try {
        // Get current facing mode from state (more reliable than getSettings)
        const currentFacing = state.call.currentFacingMode || 'user';
        const newFacing = currentFacing === 'user' ? 'environment' : 'user';
        
        console.log('Switching camera from', currentFacing, 'to', newFacing);
        
        // Stop current video track first
        const oldVideoTrack = state.localStream.getVideoTracks()[0];
        if (oldVideoTrack) {
            oldVideoTrack.stop();
        }
        
        // Try to get new video stream with exact facingMode
        let newStream;
        try {
            // First try with exact constraint (more reliable on mobile)
            newStream = await navigator.mediaDevices.getUserMedia({
                video: { 
                    facingMode: { exact: newFacing },
                    width: { ideal: 1280 }, 
                    height: { ideal: 720 } 
                }
            });
        } catch (exactError) {
            console.log('Exact facingMode failed, trying without exact:', exactError.message);
            // Fallback without exact (some devices don't support exact)
            newStream = await navigator.mediaDevices.getUserMedia({
                video: { 
                    facingMode: newFacing,
                    width: { ideal: 1280 }, 
                    height: { ideal: 720 } 
                }
            });
        }
        
        const newVideoTrack = newStream.getVideoTracks()[0];
        
        if (!newVideoTrack) {
            throw new Error('No video track in new stream');
        }
        
        // Replace track in peer connection
        const sender = state.peerConnection?.getSenders().find(s => s.track?.kind === 'video');
        if (sender) {
            await sender.replaceTrack(newVideoTrack);
        } else {
            console.warn('No video sender found in peer connection');
        }
        
        // Update local stream
        if (oldVideoTrack) {
            state.localStream.removeTrack(oldVideoTrack);
        }
        state.localStream.addTrack(newVideoTrack);
        
        // Save current facing mode to state
        state.call.currentFacingMode = newFacing;
        
        // Update local video preview
        const localVideo = document.getElementById('local-video');
        if (localVideo) {
            localVideo.srcObject = null; // Clear first
            localVideo.srcObject = state.localStream;
            await localVideo.play().catch(e => console.log('Local video play:', e.message));
        }
        
        // Update button to show current camera
        updateSwitchCameraButton(newFacing);
        
        console.log('Successfully switched to', newFacing, 'camera');
    } catch (e) {
        console.error('Failed to switch camera:', e);
        showError('Failed to switch camera');
        
        // Try to restore front camera if switch failed
        try {
            const fallbackStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } }
            });
            const fallbackTrack = fallbackStream.getVideoTracks()[0];
            
            const sender = state.peerConnection?.getSenders().find(s => s.track?.kind === 'video');
            if (sender && fallbackTrack) {
                await sender.replaceTrack(fallbackTrack);
            }
            
            state.localStream.getVideoTracks().forEach(t => t.stop());
            state.localStream.addTrack(fallbackTrack);
            state.call.currentFacingMode = 'user';
            
            const localVideo = document.getElementById('local-video');
            if (localVideo) {
                localVideo.srcObject = state.localStream;
            }
        } catch (restoreError) {
            console.error('Failed to restore camera:', restoreError);
        }
    }
}

// Update switch camera button to show current mode
function updateSwitchCameraButton(facingMode) {
    const btn = document.querySelector('.call-btn[onclick="switchCamera()"]');
    if (btn) {
        // Show different icon based on which camera will be switched TO
        btn.innerHTML = facingMode === 'user' ? '📷' : '🤳';
        btn.title = facingMode === 'user' ? 'Switch to rear camera' : 'Switch to front camera';
    }
}

// ==================== Screen Sharing ====================

/**
 * Toggle screen sharing on/off
 * Following industry standard (Zoom/Meet/Teams):
 * - Replaces camera video with screen
 * - Captures system audio when available
 * - Shows indicator when sharing
 * - Returns to camera when stopped
 */
async function toggleScreenShare() {
    if (!state.peerConnection || !state.call) return;
    
    if (state.call.isScreenSharing) {
        await stopScreenShare();
    } else {
        await startScreenShare();
    }
}

/**
 * Start screen sharing
 */
async function startScreenShare() {
    try {
        // Request screen with system audio
        const screenStream = await navigator.mediaDevices.getDisplayMedia({
            video: {
                cursor: 'always',
                displaySurface: 'monitor'
            },
            audio: true // Capture system audio if available
        });
        
        const screenTrack = screenStream.getVideoTracks()[0];
        const audioTrack = screenStream.getAudioTracks()[0]; // May be null
        
        if (!screenTrack) {
            throw new Error('No video track from screen share');
        }
        
        // Save current camera track to restore later
        const currentVideoTrack = state.localStream?.getVideoTracks()[0];
        state.call.savedCameraTrack = currentVideoTrack;
        state.call.wasCameraEnabled = currentVideoTrack?.enabled || false;
        
        // Replace video track in peer connection
        const videoSender = state.peerConnection.getSenders().find(s => s.track?.kind === 'video');
        if (videoSender) {
            await videoSender.replaceTrack(screenTrack);
        }
        
        // If screen has audio, add it as additional track
        if (audioTrack) {
            // Check if we already have an audio sender
            const existingAudioSender = state.peerConnection.getSenders().find(s => s.track?.kind === 'audio');
            if (existingAudioSender) {
                // Mix screen audio with mic (simplified: just use screen audio)
                state.call.screenAudioTrack = audioTrack;
            }
        }
        
        // Update local stream for preview
        if (state.localStream) {
            state.localStream.getVideoTracks().forEach(t => {
                state.localStream.removeTrack(t);
            });
            state.localStream.addTrack(screenTrack);
        }
        
        // Update local video preview
        const localVideo = document.getElementById('local-video');
        if (localVideo) {
            localVideo.srcObject = state.localStream;
        }
        
        // Set state
        state.call.isScreenSharing = true;
        state.call.screenTrack = screenTrack;
        
        // Handle when user stops sharing via browser UI
        screenTrack.onended = () => {
            stopScreenShare();
        };
        
        // Update button and show indicator
        updateScreenShareButton();
        showScreenShareIndicator();
        
        console.log('Screen sharing started');
        
    } catch (e) {
        if (e.name === 'NotAllowedError') {
            console.log('Screen share cancelled by user');
        } else {
            console.error('Failed to start screen share:', e);
            showError('Failed to start screen sharing');
        }
    }
}

/**
 * Stop screen sharing and return to camera
 */
async function stopScreenShare() {
    if (!state.call) return;
    
    try {
        // Stop screen track
        if (state.call.screenTrack) {
            state.call.screenTrack.stop();
        }
        
        // Stop screen audio track
        if (state.call.screenAudioTrack) {
            state.call.screenAudioTrack.stop();
        }
        
        // Restore camera
        const savedTrack = state.call.savedCameraTrack;
        
        if (savedTrack && savedTrack.readyState === 'live') {
            // Use saved camera track
            const videoSender = state.peerConnection?.getSenders().find(s => s.track?.kind === 'video');
            if (videoSender) {
                await videoSender.replaceTrack(savedTrack);
            }
            
            // Update local stream
            if (state.localStream) {
                state.localStream.getVideoTracks().forEach(t => {
                    state.localStream.removeTrack(t);
                });
                state.localStream.addTrack(savedTrack);
            }
            
            // Restore enabled state
            savedTrack.enabled = state.call.wasCameraEnabled;
        } else {
            // Camera track is gone, get a new one
            try {
                const newStream = await navigator.mediaDevices.getUserMedia({
                    video: { width: { ideal: 1280 }, height: { ideal: 720 } }
                });
                const newTrack = newStream.getVideoTracks()[0];
                
                const videoSender = state.peerConnection?.getSenders().find(s => s.track?.kind === 'video');
                if (videoSender) {
                    await videoSender.replaceTrack(newTrack);
                }
                
                if (state.localStream) {
                    state.localStream.getVideoTracks().forEach(t => {
                        state.localStream.removeTrack(t);
                    });
                    state.localStream.addTrack(newTrack);
                }
                
                newTrack.enabled = state.call.wasCameraEnabled;
            } catch (camError) {
                console.error('Failed to restore camera:', camError);
            }
        }
        
        // Update local video preview
        const localVideo = document.getElementById('local-video');
        if (localVideo) {
            localVideo.srcObject = state.localStream;
        }
        
        // Clear state
        state.call.isScreenSharing = false;
        state.call.screenTrack = null;
        state.call.screenAudioTrack = null;
        state.call.savedCameraTrack = null;
        
        // Update button and hide indicator
        updateScreenShareButton();
        hideScreenShareIndicator();
        
        console.log('Screen sharing stopped');
        
    } catch (e) {
        console.error('Error stopping screen share:', e);
    }
}

/**
 * Update screen share button appearance
 */
function updateScreenShareButton() {
    const btn = document.getElementById('screen-share-btn');
    if (!btn) return;
    
    const isSharing = state.call?.isScreenSharing || false;
    btn.classList.toggle('active', isSharing);
    btn.title = isSharing ? 'Stop sharing' : 'Screen sharing';
    btn.setAttribute('aria-pressed', isSharing ? 'true' : 'false');  // КАО#283 Round-2: keep aria-pressed in sync
}

/**
 * Show screen sharing indicator
 */
function showScreenShareIndicator() {
    let indicator = document.getElementById('screen-share-indicator');
    if (!indicator) {
        indicator = document.createElement('div');
        indicator.id = 'screen-share-indicator';
        indicator.className = 'screen-share-indicator';
        indicator.innerHTML = '<span class="screen-share-dot"></span> Screen sharing';
        
        const callContent = document.querySelector('.call-content');
        if (callContent) {
            callContent.appendChild(indicator);
        }
    }
    indicator.classList.add('visible');
}

/**
 * Hide screen sharing indicator
 */
function hideScreenShareIndicator() {
    const indicator = document.getElementById('screen-share-indicator');
    if (indicator) {
        indicator.classList.remove('visible');
    }
}

// ==================== Audio Output Management ====================

// Audio output state
const audioOutputState = {
    currentType: 'default', // 'default', 'speaker', 'bluetooth', 'earpiece'
    currentDeviceId: 'default',
    availableDevices: [],
    isMobile: /Android|iPhone|iPad|iPod/i.test(navigator.userAgent)
};

// Get icon for current audio output
function getAudioOutputIcon() {
    switch (audioOutputState.currentType) {
        case 'bluetooth':
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M17.71 7.71L12 2h-1v7.59L6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 11 14.41V22h1l5.71-5.71-4.3-4.29 4.3-4.29zM13 5.83l1.88 1.88L13 9.59V5.83zm1.88 10.46L13 18.17v-3.76l1.88 1.88z"/></svg>';
        case 'speaker':
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>';
        case 'earpiece':
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56-.35-.12-.74-.03-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>';
        default:
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02z"/></svg>';
    }
}

// Initialize audio output selector
async function initAudioOutputSelector() {
    // Check if setSinkId is supported
    const audio = document.createElement('audio');
    if (typeof audio.setSinkId !== 'function') {
        console.log('Audio output selection not supported in this browser');
        // Hide the button if not supported
        const btn = document.getElementById('audio-output-btn');
        if (btn) btn.style.display = 'none';
        return;
    }
    
    try {
        // Request permission to enumerate devices
        await navigator.mediaDevices.getUserMedia({ audio: true });
        await updateAudioDevices();
        
        // Set initial output based on priority: bluetooth > earpiece (mobile) > default
        await selectInitialAudioOutput();
        
        // Listen for device changes
        navigator.mediaDevices.addEventListener('devicechange', updateAudioDevices);
    } catch (e) {
        console.error('Failed to initialize audio output selector:', e);
    }
}

// Update available audio devices
async function updateAudioDevices() {
    try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        audioOutputState.availableDevices = devices.filter(d => d.kind === 'audiooutput');
        console.log('Available audio outputs:', audioOutputState.availableDevices.map(d => d.label || d.deviceId));
    } catch (e) {
        console.error('Failed to enumerate devices:', e);
    }
}

// Select initial audio output based on priority
async function selectInitialAudioOutput() {
    const devices = audioOutputState.availableDevices;
    
    // Priority 1: Bluetooth
    const bluetooth = devices.find(d => 
        d.label.toLowerCase().includes('bluetooth') || 
        d.label.toLowerCase().includes('airpods') ||
        d.label.toLowerCase().includes('wireless')
    );
    if (bluetooth) {
        await setAudioOutput(bluetooth.deviceId, 'bluetooth');
        return;
    }
    
    // Priority 2: Earpiece on mobile (try to find it)
    if (audioOutputState.isMobile) {
        // On mobile, 'default' usually means earpiece
        // 'Communications' on some devices means earpiece
        const earpiece = devices.find(d => 
            d.label.toLowerCase().includes('earpiece') ||
            d.label.toLowerCase().includes('phone') ||
            d.label.toLowerCase().includes('receiver') ||
            d.label.toLowerCase().includes('communications')
        );
        if (earpiece) {
            await setAudioOutput(earpiece.deviceId, 'earpiece');
            return;
        }
        // Default to 'default' which is usually earpiece on mobile
        audioOutputState.currentType = 'earpiece';
        audioOutputState.currentDeviceId = 'default';
        updateAudioOutputButton();
        return;
    }
    
    // Priority 3: Default output (desktop)
    audioOutputState.currentType = 'default';
    audioOutputState.currentDeviceId = 'default';
    updateAudioOutputButton();
}

// Set audio output device
async function setAudioOutput(deviceId, type) {
    const remoteAudio = document.getElementById('remote-audio');
    if (!remoteAudio) return;
    
    try {
        if (typeof remoteAudio.setSinkId === 'function') {
            await remoteAudio.setSinkId(deviceId);
            audioOutputState.currentDeviceId = deviceId;
            audioOutputState.currentType = type;
            updateAudioOutputButton();
            console.log('Audio output set to:', type, deviceId);
        }
    } catch (e) {
        console.error('Failed to set audio output:', e);
        showError('Failed to switch audio output');
    }
}

// Update the audio output button icon
function updateAudioOutputButton() {
    const btn = document.getElementById('audio-output-btn');
    if (btn) {
        btn.innerHTML = getAudioOutputIcon();
    }
}

// Toggle audio output menu
function toggleAudioOutputMenu() {
    const menu = document.getElementById('audio-output-menu');
    if (!menu) return;
    
    if (menu.classList.contains('active')) {
        menu.classList.remove('active');
        return;
    }
    
    // Build menu
    let menuHtml = '';
    const devices = audioOutputState.availableDevices;
    
    // Speaker option (always available)
    const speakerDevice = devices.find(d => 
        d.label.toLowerCase().includes('speaker') ||
        d.label.toLowerCase().includes('speaker')
    );
    const speakerId = speakerDevice ? speakerDevice.deviceId : 'speaker';
    
    menuHtml += '<div class="audio-output-item' + (audioOutputState.currentType === 'speaker' ? ' active' : '') + '" onclick="selectAudioOutput(\'' + safeOnclickArg(speakerId) + '\', \'speaker\')">';
    menuHtml += '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>';
    menuHtml += '<span>Speakerphone</span>';
    menuHtml += '</div>';
    
    // Earpiece option (mobile only)
    if (audioOutputState.isMobile) {
        const earpieceDevice = devices.find(d => 
            d.label.toLowerCase().includes('earpiece') ||
            d.label.toLowerCase().includes('phone') ||
            d.label.toLowerCase().includes('receiver')
        );
        const earpieceId = earpieceDevice ? earpieceDevice.deviceId : 'default';
        
        menuHtml += '<div class="audio-output-item' + (audioOutputState.currentType === 'earpiece' ? ' active' : '') + '" onclick="selectAudioOutput(\'' + safeOnclickArg(earpieceId) + '\', \'earpiece\')">';
        menuHtml += '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M20.01 15.38c-1.23 0-2.42-.2-3.53-.56-.35-.12-.74-.03-1.01.24l-1.57 1.97c-2.83-1.35-5.48-3.9-6.89-6.83l1.95-1.66c.27-.28.35-.67.24-1.02-.37-1.11-.56-2.3-.56-3.53 0-.54-.45-.99-.99-.99H4.19C3.65 3 3 3.24 3 3.99 3 13.28 10.73 21 20.01 21c.71 0 .99-.63.99-1.18v-3.45c0-.54-.45-.99-.99-.99z"/></svg>';
        menuHtml += '<span>Phone</span>';
        menuHtml += '</div>';
    }
    
    // Bluetooth devices
    const bluetoothDevices = devices.filter(d => 
        d.label.toLowerCase().includes('bluetooth') || 
        d.label.toLowerCase().includes('airpods') ||
        d.label.toLowerCase().includes('wireless') ||
        d.label.toLowerCase().includes('headphone') ||
        d.label.toLowerCase().includes('headset')
    );
    
    bluetoothDevices.forEach(device => {
        const isActive = audioOutputState.currentDeviceId === device.deviceId;
        const label = device.label || 'Bluetooth device';
        menuHtml += '<div class="audio-output-item' + (isActive ? ' active' : '') + '" onclick="selectAudioOutput(\'' + safeOnclickArg(device.deviceId) + '\', \'bluetooth\')">';
        menuHtml += '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M17.71 7.71L12 2h-1v7.59L6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 11 14.41V22h1l5.71-5.71-4.3-4.29 4.3-4.29zM13 5.83l1.88 1.88L13 9.59V5.83zm1.88 10.46L13 18.17v-3.76l1.88 1.88z"/></svg>';
        menuHtml += '<span>' + escapeHtml(label.substring(0, 25)) + '</span>';
        menuHtml += '</div>';
    });
    
    // Default option for desktop
    if (!audioOutputState.isMobile && bluetoothDevices.length === 0) {
        menuHtml += '<div class="audio-output-item' + (audioOutputState.currentType === 'default' ? ' active' : '') + '" onclick="selectAudioOutput(\'default\', \'default\')">';
        menuHtml += '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02z"/></svg>';
        menuHtml += '<span>Speaker</span>';
        menuHtml += '</div>';
    }
    
    menu.innerHTML = menuHtml;
    menu.classList.add('active');
    
    // Close menu when clicking outside
    setTimeout(() => {
        document.addEventListener('click', closeAudioMenuOnClickOutside, { once: true });
    }, 10);
}

// Close menu when clicking outside
function closeAudioMenuOnClickOutside(e) {
    const menu = document.getElementById('audio-output-menu');
    const btn = document.getElementById('audio-output-btn');
    if (menu && !menu.contains(e.target) && !btn.contains(e.target)) {
        menu.classList.remove('active');
    }
}

// Select audio output from menu
async function selectAudioOutput(deviceId, type) {
    // Close menu
    const menu = document.getElementById('audio-output-menu');
    if (menu) menu.classList.remove('active');
    
    // For speaker on mobile, we need special handling
    if (type === 'speaker' && audioOutputState.isMobile) {
        // Try to find actual speaker device
        const devices = audioOutputState.availableDevices;
        const speaker = devices.find(d => 
            d.label.toLowerCase().includes('speaker') ||
            d.deviceId === 'default' // Sometimes speaker is default on mobile
        );
        if (speaker && speaker.deviceId !== 'default') {
            deviceId = speaker.deviceId;
        }
    }
    
    await setAudioOutput(deviceId, type);
}

// Cleanup audio output on call end
function cleanupAudioOutput() {
    audioOutputState.currentType = 'default';
    audioOutputState.currentDeviceId = 'default';
    audioOutputState.availableDevices = [];
    navigator.mediaDevices.removeEventListener('devicechange', updateAudioDevices);
}

// ==================== End Audio Output Management ====================

function hideCallUI() {
    const callModal = document.getElementById('call-modal');
    if (callModal) {
        callModal.classList.remove('active');
    }
    stopCallTimer();
    cleanupAudioOutput();
}

let callTimerInterval = null;
let callStartTime = null;

function startCallTimer() {
    callStartTime = Date.now();
    callTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');
        const timerEl = document.getElementById('call-timer');
        if (timerEl) timerEl.textContent = mins + ':' + secs;
    }, 1000);
}

function stopCallTimer() {
    if (callTimerInterval) {
        clearInterval(callTimerInterval);
        callTimerInterval = null;
    }
    callStartTime = null;
}

// Render call message HTML
function renderCallMessageHTML(msg) {
    const isSuccess = msg.callSuccess;
    const isVideo = msg.callIsVideo;
    const duration = msg.callDuration || 0;
    const callType = msg.callType;
    const direction = msg.callDirection || 'outgoing';
    
    // Determine if this is a sent (outgoing) or received (incoming) message
    const isSent = direction === 'outgoing';
    
    // Arrow: ↗ for outgoing, ↙ for incoming
    const arrow = isSent ? '↗' : '↙';
    
    // Icon for video calls
    const videoIcon = isVideo ? ' 📹' : '';
    
    // Build call message content
    let callText = '';
    let durationText = '';
    
    if (isSuccess) {
        // Successful call: "Voice Call" or "Video Call" + duration on next line
        callText = isVideo ? 'Video Call' : 'Voice Call';
        const mins = Math.floor(duration / 60);
        const secs = duration % 60;
        durationText = mins > 0 ? mins + ':' + (secs < 10 ? '0' : '') + secs : '0:' + (secs < 10 ? '0' : '') + secs;
    } else {
        // Unsuccessful call: show reason
        switch (callType) {
            case 'missed':
                callText = 'Missed ' + (isVideo ? 'video' : 'voice') + ' call';
                break;
            case 'cancelled':
                callText = 'Cancelled';
                break;
            case 'declined':
                callText = 'Declined';
                break;
            case 'no_answer':
                callText = 'No answer';
                break;
            default:
                callText = (isVideo ? 'Video' : 'Voice') + ' call';
        }
    }
    
    // Color class: green for success, red for missed/failed
    const colorClass = isSuccess ? 'call-success' : 'call-missed';
    
    // Build content like a regular message
    const content = '<div class="call-message-content ' + colorClass + '">' +
        '<span class="call-arrow ' + colorClass + '">' + arrow + videoIcon + '</span>' +
        '<div class="call-message-info">' +
        '<div class="call-message-title">' + escapeHtml(callText) + '</div>' +
        (durationText ? '<div class="call-message-duration">' + durationText + '</div>' : '') +
        '</div>' +
        '</div>';
    
    // Return as regular message with context menu support
    return '<div class="message ' + (isSent ? 'sent' : 'received') + ' call-message" data-id="' + msg.id + '" data-message-id="' + msg.id + '" data-is-sent="' + isSent + '">' +
        content +
        '<div class="message-meta">' +
        '<span class="message-time">' + formatTime(msg.created_at) + '</span>' +
        '</div>' +
        '</div>';
}

// Add call message to chat (sends to server)
async function addCallMessage(peerId, type, duration = 0, isVideo = false, direction = 'outgoing') {
    const chat = state.chats[peerId];
    if (!chat) return;
    
    // Determine if call was successful (connected)
    const isSuccess = type === 'ended' && duration > 0;
    
    // Determine direction based on type if not explicit
    let callDirection = direction;
    if (type === 'missed') {
        callDirection = 'incoming';  // Missed calls are always incoming
    } else if (type === 'cancelled' || type === 'no_answer') {
        callDirection = 'outgoing';  // These are always outgoing
    }
    // 'declined' and 'ended' use the passed direction parameter
    
    // Call message data
    const callData = {
        callType: type,
        callDuration: duration,
        callIsVideo: isVideo,
        callSuccess: isSuccess,
        callDirection: callDirection
    };
    
    // Send to server
    try {
        const response = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify({
                recipient_id: peerId,
                message_type: 'call',
                // v3.11.10: E2EE encrypt call data when possible
                encrypted_payload: await (async () => {
                    // КАО#080 (SER#21): fail-closed — never silently downgrade to plaintext on encryption error
                    if (state.e2eeReady) {
                        return await VibeCrypto.encryptMessage(peerId, JSON.stringify(callData));
                    }
                    // E2EE not initialized: call metadata sent in cleartext (intentional degraded fallback)
                    return btoa(JSON.stringify(callData));
                })(),
                client_message_id: 'call_' + Date.now()
            })
        });
        
        if (response.ok) {
            const serverMsg = await response.json();
            
            // Create local message object
            const msg = {
                id: serverMsg.id,
                sender_id: serverMsg.sender_id,
                recipient_id: serverMsg.recipient_id,
                created_at: serverMsg.created_at,
                message_type: 'call',
                isCallMessage: true,
                callType: type,
                callDuration: duration,
                callIsVideo: isVideo,
                callSuccess: isSuccess,
                callDirection: callDirection
            };
            
            // Add to chat
            if (!chat.messages) chat.messages = [];
            
            // Check if already exists (by server id)
            if (!chat.messages.find(m => m.id === msg.id)) {
                chat.messages.push(msg);
            }
            
            // Update preview
            const callTypeText = isVideo ? 'Video call' : 'Voice call';
            let previewText = '';
            switch (type) {
                case 'missed':
                    previewText = '↙ Missed ' + callTypeText.toLowerCase();
                    break;
                case 'ended':
                    previewText = (callDirection === 'outgoing' ? '↗ ' : '↙ ') + callTypeText;
                    break;
                default:
                    previewText = '↗ ' + callTypeText;
            }
            
            chat.lastMessage = previewText;
            chat.lastMessageTime = msg.created_at;
            
            saveChats();
            
            // Re-render if this chat is open
            if (state.currentChatId === peerId) {
                renderMessages();
            }
            renderChatsList();
        } else {
            console.error('Failed to save call message:', response.status);
            // Fallback to local-only
            addCallMessageLocal(peerId, type, duration, isVideo, callDirection);
        }
    } catch (e) {
        console.error('Error saving call message:', e);
        // Fallback to local-only
        addCallMessageLocal(peerId, type, duration, isVideo, callDirection);
    }
}

// Local-only call message (fallback if API fails)
function addCallMessageLocal(peerId, type, duration, isVideo, callDirection) {
    const chat = state.chats[peerId];
    if (!chat) return;
    
    const isSuccess = type === 'ended' && duration > 0;
    
    const msg = {
        id: 'call_' + Date.now(),
        sender_id: callDirection === 'incoming' ? peerId : state.userId,
        recipient_id: callDirection === 'incoming' ? state.userId : peerId,
        created_at: new Date().toISOString(),
        isCallMessage: true,
        callType: type,
        callDuration: duration,
        callIsVideo: isVideo,
        callSuccess: isSuccess,
        callDirection: callDirection
    };
    
    const callTypeText = isVideo ? 'Video call' : 'Voice call';
    let previewText = '';
    switch (type) {
        case 'missed':
            previewText = '↙ Missed ' + callTypeText.toLowerCase();
            break;
        case 'ended':
            previewText = (callDirection === 'outgoing' ? '↗ ' : '↙ ') + callTypeText;
            break;
        default:
            previewText = '↗ ' + callTypeText;
    }
    
    if (!chat.messages) chat.messages = [];
    chat.messages.push(msg);
    chat.lastMessage = previewText;
    chat.lastMessageTime = msg.created_at;
    
    saveChats();
    
    if (state.currentChatId === peerId) {
        renderMessages();
    }
    renderChatsList();
}

// Handle call message received from server (WebSocket or history load)
async function handleCallMessageFromServer(payload, chatKey, senderId) {
    console.log('Handling call message from server:', payload.id);
    
    // Parse call data from encrypted_payload (base64 JSON)
    let callData = {};
    try {
        callData = JSON.parse(atob(payload.encrypted_payload));
    } catch (e) {
        console.error('Failed to parse call message payload:', e);
        return;
    }
    
    // Determine direction relative to current user
    // If we sent this message, direction from payload; otherwise flip it
    const isSentByMe = senderId === state.user?.id || senderId === state.userId;
    let callDirection;
    
    if (isSentByMe) {
        // We sent this message, use the direction from payload
        callDirection = callData.callDirection || 'outgoing';
    } else {
        // We received this message, flip the direction
        // If sender marked it as outgoing (they called), for us it's incoming
        callDirection = callData.callDirection === 'outgoing' ? 'incoming' : 'outgoing';
    }
    
    const msg = {
        id: payload.id,
        sender_id: senderId,
        recipient_id: payload.recipient_id,
        created_at: payload.created_at,
        message_type: 'call',
        isCallMessage: true,
        callType: callData.callType,
        callDuration: callData.callDuration || 0,
        callIsVideo: callData.callIsVideo || false,
        callSuccess: callData.callSuccess || false,
        callDirection: callDirection
    };
    
    // Create chat if needed
    if (!state.chats[chatKey]) {
        try {
            const response = await api('/auth/user/id/' + chatKey);
            if (response.ok) {
                const userData = await response.json();
                state.chats[chatKey] = { 
                    id: chatKey, 
                    username: userData.username, 
                    displayName: userData.display_name || userData.username, 
                    avatar_url: userData.avatar_url || null, 
                    messages: [], 
                    unreadCount: 0, 
                    missedCalls: 0 
                };
            }
        } catch (e) {
            state.chats[chatKey] = { 
                id: chatKey, 
                username: chatKey, 
                displayName: chatKey, 
                avatar_url: null, 
                messages: [], 
                unreadCount: 0, 
                missedCalls: 0 
            };
        }
    }
    
    const chat = state.chats[chatKey];
    if (!chat.messages) chat.messages = [];
    
    // Check if already exists
    if (chat.messages.find(m => m.id === msg.id)) {
        return;
    }
    
    chat.messages.push(msg);
    
    // Update preview
    const callTypeText = callData.callIsVideo ? 'Video call' : 'Voice call';
    let previewText = '';
    switch (callData.callType) {
        case 'missed':
            previewText = '↙ Missed ' + callTypeText.toLowerCase();
            break;
        case 'ended':
            previewText = (callDirection === 'outgoing' ? '↗ ' : '↙ ') + callTypeText;
            break;
        default:
            previewText = '↗ ' + callTypeText;
    }
    
    chat.lastMessage = previewText;
    chat.lastMessageTime = msg.created_at;
    
    // Increment unread if chat not open
    if (state.currentChatId !== chatKey) {
        chat.unreadCount = (chat.unreadCount || 0) + 1;
    }
    
    saveChats();
    
    if (state.currentChatId === chatKey) {
        renderMessages();
    }
    renderChatsList();
}

// ==================== UI ====================

function showScreen(name) {
    // Clear countdown interval when leaving chat screen
    if (name !== 'chat' && disappearingCountdownInterval) {
        clearInterval(disappearingCountdownInterval);
        disappearingCountdownInterval = null;
    }
    
    Object.values(screens).forEach(s => s.classList.remove('active'));
    const el = screens[name];
    el.classList.add('active');
    // КАО#281 (#34): move keyboard focus into the newly shown screen so it isn't stranded on the
    // now-hidden one. Skip if focus is already inside this screen (don't steal an autofocused input).
    try {
        if (!el.contains(document.activeElement)) {
            el.setAttribute('tabindex', '-1');
            el.focus({ preventScroll: true });
        }
    } catch (e) {}
}

function showError(message) {
    if (typeof announceA11y === 'function') announceA11y(message, true);  // КАО#282 (#14): assertive
    const errorDiv = document.getElementById('auth-error');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
    setTimeout(() => errorDiv.classList.add('hidden'), 5000);
}

function updateConnectionStatus(status) {
    const dot = document.querySelector('.status-dot');
    const text = document.querySelector('.status-text');
    if (dot) dot.className = 'status-dot ' + status;
    if (text) text.textContent = status === 'connected' ? 'Connected' : 'Reconnecting...';
    
    // Update offline banner based on WebSocket connection
    if (status === 'connected') {
        hideOfflineBanner();
        // Send queued messages when reconnected
        sendQueuedMessages();
    } else if (status === 'disconnected') {
        // Show banner on any disconnect (network or server)
        showOfflineBanner();
    }
}

function renderChatsList() {
    const list = document.getElementById('chats-list');
    const chatEntries = Object.values(state.chats);

    if (chatEntries.length === 0) {
        list.innerHTML = '<div class="empty-state"><span>💬</span><p>No chats yet</p><button onclick="showNewMenu()" class="btn primary">Start Chat</button></div>';
        return;
    }

    list.innerHTML = chatEntries.map(chat => {
        const unread = (chat.unreadCount || 0) + (chat.missedCalls || 0);
        const badgeHtml = unread > 0 ? '<div class="chat-badge">' + unread + '</div>' : '';
        const isGroup = chat.isGroup;
        const displayName = escapeHtml(chat.displayName || chat.name || chat.username || '?');
        const avatarClass = isGroup ? 'chat-avatar group-avatar' : 'chat-avatar';
        const avatarLetter = isGroup ? (chat.isChannel ? '📢' : '👥') : (chat.displayName || chat.name || chat.username || '?')[0].toUpperCase();
        const clickHandler = isGroup ? 'openGroupChat(\'' + escapeHtml(chat.id) + '\')' : 'openChat(\'' + escapeHtml(chat.id) + '\')';
        const chatKey = isGroup ? 'group_' + chat.id : chat.id;
        
        // Online indicator for direct chats
        const isOnline = !isGroup && state.onlineUsers && state.onlineUsers[chat.id];
        const onlineIndicator = isOnline ? '<div class="online-indicator"></div>' : '';
        
        // Avatar with image support
        let avatarContent;
        if (chat.avatar_url) {
            avatarContent = '<img src="' + escapeHtml(chat.avatar_url) + '" class="chat-avatar-img" alt="">' + badgeHtml + onlineIndicator;
        } else {
            avatarContent = escapeHtml(avatarLetter) + badgeHtml + onlineIndicator;
        }
        
        // v3.11.12: Clean up stale/encrypted previews
        let lastMessageText;
        if (chat.lastMessage) {
            let rawText = typeof chat.lastMessage === 'string' ? chat.lastMessage : (chat.lastMessage.text || '');
            // КАО#230 (SER#18): never surface the poll marker / per-poll content key in the preview
            rawText = rawText.replace(/\s*\[poll:[a-fA-F0-9-]+\]/g, '').replace(/\s*\[pollkey:[^\]\s]*\]/g, '').trim();
            if (rawText.includes('Encrypted message') || rawText.includes('\u{1F512}')) {
                lastMessageText = escapeHtml('No messages');
            } else {
                lastMessageText = escapeHtml(rawText || 'No messages');
            }
        } else {
            lastMessageText = escapeHtml('No messages');
        }
        
        return '<div class="chat-item">' +
            // КАО#280 (#13): keyboard-accessible chat row (was a click-only div) — role/tabindex + Enter/Space
            '<div class="chat-content" role="button" tabindex="0" aria-label="Open chat with ' + escapeHtml(typeof displayName === "string" ? displayName.replace(/<[^>]*>/g, "") : "") + '" onclick="' + clickHandler + '" onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();this.click();}">' +
            '<div class="' + avatarClass + '">' + avatarContent + '</div>' +
            '<div class="chat-details">' +
            '<div class="chat-name">' + displayName + '</div>' +
            '<div class="chat-last-message">' + lastMessageText + '</div>' +
            '</div>' +
            '</div>' +
            '<button class="delete-chat-btn" aria-label="Delete chat" onclick="deleteChat(\'' + escapeHtml(chatKey) + '\')">✕</button>' +
            '</div>';
    }).join('');
}

async function deleteChat(chatId) {
    const chat = state.chats[chatId];
    
    if (chat && chat.isGroup) {
        // For groups
        const isOwner = chat.created_by === state.user.id;
        
        if (isOwner) {
            const confirmed = await showConfirm(
                'This will delete the group for all members.',
                'Delete Group?',
                'Delete',
                'Cancel'
            );
            if (!confirmed) return;
            
            try {
                const response = await api('/groups/' + chat.id, { method: 'DELETE' });
                if (!response.ok && response.status !== 204) {
                    const data = await response.json();
                    await showAlert(data.detail || 'Failed to delete group', 'Error', '❌');
                    return;
                }
            } catch (e) {
                console.error('Delete group error:', e);
                await showAlert('Failed to delete group', 'Error', '❌');
                return;
            }
        } else {
            const confirmed = await showConfirm(
                'You will leave this group.',
                'Leave Group?',
                'Leave',
                'Cancel'
            );
            if (!confirmed) return;
            
            try {
                const response = await api('/groups/' + chat.id + '/members/' + state.user.id, { method: 'DELETE' });
                if (!response.ok && response.status !== 204) {
                    const data = await response.json();
                    await showAlert(data.detail || 'Failed to leave group', 'Error', '❌');
                    return;
                }
            } catch (e) {
                console.error('Leave group error:', e);
                await showAlert('Failed to leave group', 'Error', '❌');
                return;
            }
        }
    } else {
        // For direct chats
        const confirmed = await showConfirm(
            'This will delete the chat history.',
            'Delete Chat?',
            'Delete',
            'Cancel'
        );
        if (!confirmed) return;
    }
    
    // Save deletion time to filter old messages if chat is reopened
    if (state.user && state.user.id) {
        const key = 'deletedChats_' + state.user.id;
        const deletedChats = JSON.parse(localStorage.getItem(key) || '{}');
        deletedChats[chatId] = new Date().toISOString();
        localStorage.setItem(key, JSON.stringify(deletedChats));
    }
    
    // Clear decrypted messages cache for this chat
    offlineDB.deleteDecryptedMessagesForChat(chatId);
    
    delete state.chats[chatId];
    saveChats();
    renderChatsList();
    if (state.currentChatId === chatId) {
        state.currentChat = null;
        state.currentChatId = null;
        showScreen('chats');
    }
}

async function openChat(recipientId) {
    // Проверка на null/undefined
    if (!recipientId) {
        console.error('openChat: recipientId is null or undefined');
        return;
    }
    
    // v3.8.57: Hide identity key changed banner from previous chat
    hideIdentityKeyChangedBanner();
    
    // v3.8.36: Exit multi-select mode when switching chats
    if (state.multiSelectMode) {
        exitMultiSelectMode();
    }
    
    // Close search if open
    if (typeof closeSearch === 'function') closeSearch();
    
    let recipientName = recipientId;
    let recipientUsername = recipientId;
    let recipientAvatarUrl = null;

    // If recipientId is display_name (no dashes), we MUST look up by display name to get UUID
    // This is a blocking request because we need the UUID to continue
    if (!recipientId.includes('-')) {
        try {
            const response = await api('/auth/user/' + recipientId);
            if (response.ok) {
                const userData = await response.json();
                recipientId = userData.id;
                recipientUsername = userData.username;
                recipientName = userData.display_name || userData.username;
                recipientAvatarUrl = userData.avatar_url || null;
            } else {
                await showAlert('User not found', 'Error', '❌');
                return;
            }
        } catch (e) {
            await showAlert('Error finding user', 'Error', '❌');
            return;
        }
    } else {
        // v3.7.3: recipientId is UUID - use cached data immediately, fetch fresh data in background
        // This eliminates the 10-15 second delay when opening chats
        if (state.chats[recipientId]) {
            // Use cached data immediately
            recipientUsername = state.chats[recipientId].username || recipientId;
            recipientName = state.chats[recipientId].displayName || recipientUsername;
            recipientAvatarUrl = state.chats[recipientId].avatar_url;
        }
        // Fetch fresh data in background (non-blocking)
        fetchUserInfoAsync(recipientId);
    }

    if (!state.chats[recipientId]) {
        state.chats[recipientId] = { id: recipientId, username: recipientUsername, displayName: recipientName, avatar_url: recipientAvatarUrl, messages: [], unreadCount: 0, missedCalls: 0 };
    } else {
        // Update user info only if we have valid data
        if (recipientUsername && recipientUsername !== recipientId) {
            state.chats[recipientId].username = recipientUsername;
            state.chats[recipientId].displayName = recipientName;
        }
        // Update avatar_url only if we got it from server (not null from failed request)
        if (recipientAvatarUrl !== undefined) {
            state.chats[recipientId].avatar_url = recipientAvatarUrl;
        }
    }

    state.currentChat = state.chats[recipientId];
    state.currentChatId = recipientId;
    
    // Reset unread count and missed calls when opening chat
    state.chats[recipientId].unreadCount = 0;
    state.chats[recipientId].missedCalls = 0;
    
    // Mark all messages as read
    markCurrentChatAsRead();
    
    // Check if this is a group chat
    const isGroup = state.currentChat && state.currentChat.isGroup;
    
    document.getElementById('chat-name').textContent = state.currentChat.displayName || state.currentChat.username;
    
    // Update avatar in header
    updateChatHeaderAvatar(state.currentChat);
    
    // Update online status for direct chats
    const statusEl = document.getElementById('chat-status');
    if (statusEl) {
        if (isGroup) {
            statusEl.textContent = (state.currentChat.members?.length || 0) + ' members';
            statusEl.className = 'user-status';
        } else {
            // Show checking while fetching status
            statusEl.textContent = '...';
            statusEl.className = 'user-status';
            
            // Fetch fresh status from server
            checkUserOnline(recipientId).then(online => {
                updateChatHeaderStatus(online);
            });
            
            // Also set up periodic status check while in this chat
            startStatusPolling(recipientId);
        }
    }
    
    // Update E2EE indicator
    updateE2EEIndicator();
    
    renderMessages();
    renderPinnedMessages();
    showScreen('chat');
    
    // v3.11.1: Show untrusted key banner SYNCHRONOUSLY before any async calls
    // This ensures banner/message survive even when loadChatHistory gets 429
    if (!isGroup && state.e2eeReady) {
        // v3.11.4: Ensure knownIdentityKeys are loaded (initE2EE may have failed due to offlineDB not ready)
        if (Object.keys(knownIdentityKeys).length === 0 && offlineDB?.db) {
            await loadKnownIdentityKeys();
        }
        const known = knownIdentityKeys[recipientId];
        if (known && known.trusted === false) {
            const dn = state.currentChat?.displayName || state.currentChat?.username || recipientId;
            const keysJustReset = localStorage.getItem('vibe_keys_just_reset');
            const resetTime = keysJustReset ? parseInt(keysJustReset) : 0;
            const weReset = (Date.now() - resetTime) < 5 * 60 * 1000;
            showIdentityKeyChangedBanner(recipientId, dn, weReset);
            showKeyResetInChat(dn);
        }
    }
    
    loadChatHistory(recipientId);
    loadFavoriteMessageIds();  // v3.8.39: Refresh favorites for star indicators
    loadPinnedMessages();
    saveChats();
    renderChatsList();
    setupGroupMenuForChat();
    
    // v3.6.0: Load draft for this chat
    if (typeof loadDraft === 'function') {
        const draft = loadDraft(recipientId);
        const input = document.getElementById('message-text');
        if (input && draft) {
            input.value = draft;
        }
    }
    
    // v3.6.0: Update mute button
    if (typeof updateMuteButton === 'function') {
        updateMuteButton();
    }
    
    // Init pull to refresh for messages
    setTimeout(() => {
        initMessagesPullToRefresh();
        scrollToBottom();
    addChannelCommentButtons();  // v3.11.10: channel comments
    }, 100);
}

/**
 * v3.8.8: Check and show pending key reset notification for this chat
 */
function checkPendingKeyReset(userId) {
    if (state.keyResetPending[userId]) {
        const displayName = state.keyResetPending[userId];
        delete state.keyResetPending[userId];
        console.log('[E2EE] Showing queued key reset message for', userId);
        showKeyResetInChat(displayName);
        // v3.11.2: Banner is now shown by openChat sync block, no need to duplicate here
    }
}

async function loadChatHistory(recipientId) {
    try {
        const response = await api('/messages/history/' + recipientId + '?limit=50');
        if (response.ok) {
            const messages = await response.json();
            console.log('[E2EE] loadChatHistory: server returned', messages.length, 'messages for', recipientId);
            
            const chat = state.chats[recipientId];
            if (!chat) return;
            
            // Get deletion time for this chat (if was deleted before)
            const key = state.user ? 'deletedChats_' + state.user.id : 'deletedChats';
            const deletedChats = JSON.parse(localStorage.getItem(key) || '{}');
            const deletedAt = deletedChats[recipientId] ? new Date(deletedChats[recipientId]) : null;
            if (deletedAt) {
                console.log('[E2EE] loadChatHistory: deletedAt filter active:', deletedAt);
            }
            
            // Determine if this is a group chat
            const isGroup = chat.isGroup;
            const groupId = isGroup ? chat.id : null;
            
            // v3.7.2: Batch load cached messages for performance
            const messageIds = messages.map(m => m.id);
            const cachedMessages = await offlineDB.getDecryptedMessages(messageIds);
            
            let skippedByDate = 0;
            let skippedByCalls = 0;
            let addedCount = 0;
            
            for (const msg of messages) {
                // Skip messages from before chat was deleted
                if (deletedAt && new Date(msg.created_at) < deletedAt) {
                    skippedByDate++;
                    continue;
                }
                
                // Handle CALL messages specially (not encrypted)
                if (msg.message_type === 'call' || msg.message_type === 'CALL') {
                    skippedByCalls++;
                    await handleCallMessageFromServer(msg, recipientId, String(msg.sender_id));
                    continue;
                }
                
                let text;
                let fileInfo = null;
                let decrypted = null;
                let fromCache = false;
                
                // Check decrypted messages cache first (from batch load)
                const cached = cachedMessages.get(msg.id);
                if (cached) {
                    text = cached.text;
                    fileInfo = cached.file_info;
                    fromCache = true;
                }
                
                // Try E2EE decryption if not cached
                // IMPORTANT: We can only decrypt messages FROM others, not our own messages
                // Our own messages were encrypted FOR the recipient, not for us
                const isOurMessage = String(msg.sender_id) === String(state.user.id);

                // v3.7.1: For our own messages, try to decrypt encrypted_for_self
                if (!fromCache && isOurMessage && state.e2eeReady && msg.encrypted_for_self) {
                    try {
                        decrypted = await VibeCrypto.decryptForSelf(msg.encrypted_for_self);
                        if (decrypted) {
                            // КАО#090 Round-2: own file/voice store fileInfo JSON in encrypted_for_self —
                            // parse it back so the attachment (+ at-rest fileKey) isn't lost on reload.
                            let selfFileInfo = null;
                            if ((msg.message_type === 'file' || msg.message_type === 'voice' || msg.file_id) && decrypted.startsWith('{')) {
                                try {
                                    const fi = JSON.parse(decrypted);
                                    if (fi && fi.file_id) { selfFileInfo = fi; regFileKey(fi); decrypted = fi.is_voice ? '🎤 Voice message' : ('📎 ' + (fi.filename || 'File')); }
                                } catch (e) {}
                            }
                            offlineDB.saveDecryptedMessage(msg.id, state.currentChatId, decrypted, selfFileInfo);
                            if (selfFileInfo) msg.file = selfFileInfo;
                            // КАО#364: same omission as the group loader — the cache got the plaintext but the
                            // locals that actually build the message did not, so a successfully self-decrypted
                            // own message rendered blank (and file/voice lost its play/download control), then
                            // the undefined text overwrote the readable local copy and was persisted.
                            text = decrypted;
                            if (selfFileInfo) fileInfo = selfFileInfo;
                            fromCache = true;
                        }
                    } catch (e) {
                        // v3.11.10: Self-key mismatch after reset is expected
                        if (!window._selfDecryptWarnShown) {
                            console.warn("[E2EE] Self-decrypt failed (key changed):", e.message);
                            window._selfDecryptWarnShown = true;
                        }
                    }
                }
                
                // CRITICAL: Double Ratchet is STATEFUL - we CANNOT decrypt old messages from history!
                // Each decryption attempt changes session state, making future decryption fail.
                // History messages MUST come from cache only. If not cached = undecryptable.
                // Real-time messages via WebSocket are decrypted in handleNewMessage() and cached there.
                
                if (!fromCache && state.e2eeReady && msg.encrypted_payload && !isOurMessage) {
                    // Check if this looks like E2EE message
                    try {
                        const firstBytes = atob(msg.encrypted_payload.slice(0, 20));
                        if (firstBytes.startsWith('{"v":')) {
                            // This is E2EE but NOT in cache - cannot decrypt from history
                            // Mark as encrypted, user needs to receive it in real-time to decrypt
                            console.log('[E2EE] History msg', msg.id, 'not in cache - showing as encrypted');
                            decrypted = null; // Will show as "🔒 Encrypted message (key expired)"
                        }
                    } catch (e) {
                        // Not E2EE, try legacy below
                    }
                }
                
                // Legacy decoding fallback (only if not from cache)
                if (!fromCache) {
                    try {
                        if (!decrypted) {
                            decrypted = decodeURIComponent(escape(atob(msg.encrypted_payload)));
                            // Check if this is an undecrypted E2EE payload
                            if (decrypted.startsWith('{"v":')) {
                                decrypted = null; // Mark as failed E2EE
                            }
                        }
                        
                        // Handle decryption failure
                        if (!decrypted) {
                            text = '🔒 Encrypted message (key expired)';
                        }
                        // Parse file info if applicable
                        else if (msg.message_type === 'FILE' || msg.message_type === 'file' || 
                            msg.message_type === 'voice' || msg.message_type === 'VOICE' ||
                            (typeof decrypted === 'string' && decrypted.startsWith('{') && !decrypted.startsWith('{"v":'))) {
                            try {
                                fileInfo = JSON.parse(decrypted);
                                if (msg.message_type === 'voice' || msg.message_type === 'VOICE' || fileInfo.is_voice) {
                                    text = '🎤 Voice message';
                                    fileInfo.is_voice = true;
                                } else {
                                    text = '📎 ' + (fileInfo.filename || 'File');
                                }
                            } catch {
                                text = decrypted;
                            }
                        } else {
                            text = decrypted;
                        }
                    }
                    catch (e) { 
                        try {
                            text = atob(msg.encrypted_payload); 
                        } catch {
                            text = '[Unable to decrypt]';
                        }
                    }
                }

                const message = {
                    id: msg.id,
                    client_message_id: msg.client_message_id,
                    text: text,
                    file: fileInfo,
                    sender_id: msg.sender_id,
                    created_at: msg.created_at,
                    status: msg.status,
                    edited_at: msg.edited_at,
                    is_edited: !!msg.edited_at,
                    forwarded_from_id: msg.forwarded_from_id,
                    forwarded_from_name: msg.forwarded_from_name,
                    expires_at: msg.expires_at,
                    reply_to_id: msg.reply_to_id,
                    is_pinned: msg.is_pinned,
                    reactions: msg.reactions || [],
                };
                
                // Check for existing message by id or client_message_id
                const existingIdx = chat.messages.findIndex(m => 
                    m.id === message.id || 
                    (message.client_message_id && m.client_message_id === message.client_message_id) ||
                    (message.client_message_id && m.id === message.client_message_id)
                );
                
                if (existingIdx !== -1) {
                    // Update existing message with server data (preserving any local fields)
                    // v3.9.2: Don't overwrite readable text with decryption failure
                    const existingText = chat.messages[existingIdx].text;
                    const newTextIsFailure = message.text === '🔒 Encrypted message (key expired)' || 
                                             message.text === '[Unable to decrypt message]';
                    const existingTextIsReadable = existingText && 
                                                   !existingText.startsWith('🔒') && 
                                                   existingText !== '[Unable to decrypt message]';
                    
                    chat.messages[existingIdx] = {
                        ...chat.messages[existingIdx],
                        id: message.id,
                        status: message.status,
                        client_message_id: message.client_message_id || chat.messages[existingIdx].client_message_id,
                        edited_at: message.edited_at,
                        is_edited: message.is_edited,
                        // Only update text if new text is readable OR existing text is not readable
                        text: (newTextIsFailure && existingTextIsReadable) ? existingText : message.text,
                        forwarded_from_id: message.forwarded_from_id,
                        forwarded_from_name: message.forwarded_from_name,
                        expires_at: message.expires_at,
                        is_pinned: message.is_pinned,
                        reply_to_id: message.reply_to_id,
                        reactions: message.reactions || chat.messages[existingIdx].reactions || [],
                    };
                } else {
                    chat.messages.push(message);
                    addedCount++;
                }
            }
            // КАО#380: reconcile deletions inside the window the server just described. This loop is
            // purely additive - it updates a match or pushes, and never removes - so a "delete for everyone"
            // that happened while this device had no socket was never learned: ws_manager DROPS the
            // message_deleted event when the recipient is offline and nothing replays it on reconnect
            // (/pending returns messages only). The server omits the row, the loop keeps the local copy, and
            // saveChats() re-persists it, so a retracted message stayed visible on that device for ever.
            // This is the 1:1 twin of КАО#376, which fixed the group loader.
            // Scope is everything: prune ONLY at or after the OLDEST message the server returned - that is
            // the region it spoke about authoritatively - and never touch anything that has not reached the
            // server yet. An empty page carries no window and prunes nothing.
            if (Array.isArray(messages) && messages.length) {
                const serverIds = new Set(messages.map(m => m.id));
                const times = messages
                    .map(m => new Date(m.created_at || 0).getTime())
                    .filter(t => Number.isFinite(t));
                const windowStart = times.length ? Math.min.apply(null, times) : null;
                if (windowStart !== null) {
                    chat.messages = chat.messages.filter(m => {
                        if (serverIds.has(m.id)) return true;
                        // never reached the server yet, or still being retried
                        if (String(m.id).startsWith('msg_') || String(m.id).startsWith('call_')) return true;
                        if (m.status === 'sending' || m.status === 'queued' || m.status === 'failed') return true;
                        // older than the page the server described - this is the history it did not speak about
                        return new Date(m.created_at || 0).getTime() < windowStart;
                    });
                }
            }

            chat.messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
            console.log('[E2EE] loadChatHistory: skippedByDate:', skippedByDate, 'skippedByCalls:', skippedByCalls, 'added:', addedCount, 'total in chat:', chat.messages.length);
            
            // Find pinned message
            const pinnedMsg = chat.messages.find(m => m.is_pinned);
            if (pinnedMsg) {
                chat.pinnedMessage = pinnedMsg;
            }
            
            saveChats();
            if (state.currentChatId === recipientId) {
                renderMessages();
                renderPinnedMessages();

                // КАО#271 (#28): mark as read AFTER history is loaded — the early call in openChat ran
                // before chat.messages was populated from the server, so messages present only in server
                // history were never marked read (sender saw them stuck as delivered).
                markCurrentChatAsRead();

                // v3.8.9: Show pending key reset message after history loaded
                checkPendingKeyReset(recipientId);
                
                // v3.8.57: Verify contact's identity key AFTER history is loaded
                // This ensures chat.messages is populated for the "we reset keys" check
                if (!isGroup && state.e2eeReady) {
                    const displayName = chat.displayName || chat.username || recipientId;
                    console.log('[E2EE] About to verify identity key for', recipientId, 'messages count:', chat.messages?.length);
                    verifyContactIdentityKey(recipientId, displayName);
                }
            }
        }
    } catch (e) { console.error('Failed to load history:', e); }
}

// Get status icon for sent messages
function getStatusIcon(status) {
    switch (status) {
        case 'sending':
            return '<span class="message-status sending">⏳</span>';
        case 'queued':
            return '<span class="message-status queued">🕐</span>';
        case 'failed':
            return '<span class="message-status failed">❌</span>';
        case 'sent':
        case 'pending':
            return '<span class="message-status sent">✓</span>';
        case 'delivered':
            return '<span class="message-status delivered">✓✓</span>';
        case 'read':
            return '<span class="message-status read">✓✓</span>';
        default:
            return '<span class="message-status sent">✓</span>';
    }
}

// v3.8.6: Get E2EE indicator for message
function getE2EEIndicator(isE2EE) {
    if (isE2EE === true) {
        return '<span class="e2ee-indicator encrypted" title="End-to-end encrypted">🔒</span>';
    } else if (isE2EE === false) {
        return '<span class="e2ee-indicator not-encrypted" title="Not encrypted - message readable on server">🔓</span>';
    }
    // undefined = old message, don't show indicator
    return '';
}

// v3.8.6: Show warning when message sent without E2EE
let e2eeWarningShown = false;
function showE2EEWarning() {
    // Only show once per session to avoid annoyance
    if (e2eeWarningShown) return;
    e2eeWarningShown = true;
    
    const warning = document.createElement('div');
    warning.className = 'e2ee-warning-toast';
    warning.innerHTML = `
        <div class="e2ee-warning-content">
            <span class="e2ee-warning-icon">⚠️</span>
            <div class="e2ee-warning-text">
                <strong>Message not encrypted</strong>
                <p>This message was sent without end-to-end encryption. The recipient may not support E2EE.</p>
            </div>
            <button class="e2ee-warning-close" onclick="this.parentElement.parentElement.remove()">✕</button>
        </div>
    `;
    document.body.appendChild(warning);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (warning.parentElement) {
            warning.remove();
        }
    }, 5000);
}

// v3.11.9: Fail-closed encryption error UI
function showEncryptionFailedError(detail) {
    showAlert(detail || 'Message encryption failed. Message was NOT sent.', 'Encryption Error', '🔒');
}

// Get disappearing message time display (countdown instead of send time)
function getDisappearingTimeDisplay(expiresAt, createdAt) {
    if (!expiresAt) {
        // Regular message - show send time
        return '<span class="message-time">' + formatTime(createdAt) + '</span>';
    }
    
    const expiresDate = new Date(expiresAt);
    const now = new Date();
    const remainingMs = expiresDate - now;
    
    if (remainingMs <= 0) {
        return '<span class="message-time disappearing-time">expired</span>';
    }
    
    // Format remaining time with more precision for short durations
    let timeStr;
    const remainingSec = Math.floor(remainingMs / 1000);
    if (remainingSec < 60) {
        timeStr = remainingSec + 's';
    } else if (remainingSec < 3600) {
        const mins = Math.floor(remainingSec / 60);
        const secs = remainingSec % 60;
        timeStr = mins + ':' + (secs < 10 ? '0' : '') + secs;
    } else if (remainingSec < 86400) {
        const hours = Math.floor(remainingSec / 3600);
        const mins = Math.floor((remainingSec % 3600) / 60);
        timeStr = hours + 'h ' + mins + 'm';
    } else {
        const days = Math.floor(remainingSec / 86400);
        const hours = Math.floor((remainingSec % 86400) / 3600);
        timeStr = days + 'd ' + hours + 'h';
    }
    
    return '<span class="message-time disappearing-time" title="Disappears in ' + timeStr + '">⏱️ ' + timeStr + '</span>';
}

function renderMessages() {
    const container = document.getElementById('messages');
    if (!state.currentChatId || !state.chats[state.currentChatId]) {
        container.innerHTML = '';
        return;
    }
    
    const chat = state.chats[state.currentChatId];
    let messages = chat.messages || [];
    const isGroupChat = chat.isGroup;
    
    // Filter out expired messages
    const now = new Date();
    messages = messages.filter(msg => {
        if (!msg.expires_at) return true;
        return new Date(msg.expires_at) > now;
    });
    
    // v3.6.0: Filter out messages from blocked users
    if (typeof shouldShowMessage === 'function') {
        messages = messages.filter(shouldShowMessage);
    }
    
    // Create a map for quick message lookup (for replies)
    const messageMap = {};
    messages.forEach(msg => {
        messageMap[msg.id] = msg;
    });

    container.innerHTML = messages.map(msg => {
        // Handle call messages
        if (msg.isCallMessage || msg.message_type === 'call') {
            return renderCallMessageHTML(msg);
        }
        
        const isSent = msg.sender_id === state.user.id;
        let content = parseMarkdown(msg.text);
        
        // Highlight mentions in group chats
        if (isGroupChat && content) {
            content = highlightMentions(content);
        }
        
        if (msg.file && msg.file.file_id) {
            regFileKey(msg.file);  // КАО#090: register at-rest key for download/play/gallery
            const ext = msg.file.extension || '';
            const isVoice = msg.file.is_voice || ext === 'webm' || (msg.text && msg.text.includes('Voice'));
            const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext);
            const isAudio = ['mp3', 'wav', 'ogg', 'm4a', 'webm'].includes(ext);
            const rawFilename = msg.file.filename || 'file';
            const safeFilename = escapeHtml(rawFilename);
            const jsFilename = safeOnclickArg(rawFilename);
            
            if (isVoice || (isAudio && msg.text && msg.text.includes('Voice'))) {
                const duration = msg.file.duration || 0;
                const mins = Math.floor(duration / 60);
                const secs = duration % 60;
                const durationStr = mins + ':' + (secs < 10 ? '0' : '') + secs;
                
                content = '<div class="voice-message">' +
                    '<button class="voice-play-btn" onclick="playVoiceMessage(\'' + escapeHtml(msg.file.file_id) + '\', this)">▶</button>' +
                    '<div class="voice-waveform">' + generateWaveform() + '</div>' +
                    '<span class="voice-duration">' + durationStr + '</span>' +
                    '</div>';
            } else if (isImage) {
                content = '<div class="file-message" onclick="downloadFile(\'' + escapeHtml(msg.file.file_id) + '\', \'' + jsFilename + '\')">' +
                    '<div class="file-name">📷 ' + safeFilename + '</div>' +
                    '</div>';
            } else {
                content = '<div class="file-message" onclick="downloadFile(\'' + escapeHtml(msg.file.file_id) + '\', \'' + jsFilename + '\')">' +
                    '<div class="file-icon">📎</div>' +
                    '<div class="file-name">' + safeFilename + '</div>' +
                    '<div class="file-size">' + formatFileSize(msg.file.size) + '</div>' +
                    '</div>';
            }
        }
        
        // Wrap text content in div for link preview support (only for plain text, not files)
        if (content && !content.startsWith('<div')) {
            content = '<div class="message-text">' + content + '</div>';
        }
        
        // Build reply block if this message is a reply
        let replyBlock = '';
        if (msg.reply_to_id) {
            const replyMsg = messageMap[msg.reply_to_id];
            if (replyMsg) {
                const replySenderName = replyMsg.sender_id === state.user.id ? 'You' : escapeHtml(replyMsg.sender_name || chat.displayName || 'Unknown');
                const replyText = escapeHtml(truncateText(replyMsg.text || '[Media]', 40));
                replyBlock = '<div class="reply-block" onclick="scrollToMessage(\'' + escapeHtml(msg.reply_to_id) + '\')">' +
                    '<div class="reply-block-author">' + replySenderName + '</div>' +
                    '<div class="reply-block-text">' + replyText + '</div>' +
                    '</div>';
            } else {
                replyBlock = '<div class="reply-block reply-deleted">' +
                    '<div class="reply-block-text">Message deleted</div>' +
                    '</div>';
            }
        }
        
        // Build forwarded header if message was forwarded
        const forwardedHeader = msg.forwarded_from_name 
            ? '<div class="forwarded-header">↪️ Forwarded from ' + escapeHtml(msg.forwarded_from_name) + '</div>'
            : '';
        
        // Show sender name in group chats for received messages
        const senderNameHtml = (isGroupChat && !isSent && msg.sender_name)
            ? '<div class="message-sender">' + escapeHtml(msg.sender_name) + '</div>'
            : '';
        
        // Build pinned class
        const pinnedClass = msg.is_pinned ? ' pinned' : '';
        
        // Build reactions
        const reactionsHtml = renderReactions(msg.reactions, msg.id);
        
        // v3.8.36: Add multi-select classes if in multi-select mode
        const multiSelectClass = state.multiSelectMode ? ' multi-select-mode' : '';
        const selectedClass = state.multiSelectMode && state.selectedMessages.some(m => m.id === msg.id) ? ' selected' : '';
        
        // v3.8.37: Check if message is favorited
        const favoriteIndicator = state.favoriteMessageIds.has(msg.id) ? '<span class="message-favorite-star" title="In favorites">⭐</span>' : '';
        
        return '<div class="message ' + (isSent ? 'sent' : 'received') + pinnedClass + multiSelectClass + selectedClass + '" data-id="' + msg.id + '" data-message-id="' + msg.id + '" data-expires="' + (msg.expires_at || '') + '" data-is-sent="' + isSent + '">' +
            senderNameHtml +
            replyBlock +
            forwardedHeader +
            content +
            reactionsHtml +
            '<div class="message-meta">' +
                favoriteIndicator +
                getE2EEIndicator(msg.e2ee) +
                (msg.edited_at || msg.is_edited ? '<span class="message-edited">edited</span>' : '') +
                getDisappearingTimeDisplay(msg.expires_at, msg.created_at) +
                (isSent ? getStatusIcon(msg.status) : '') +
            '</div>' +
            '</div>';
    }).join('');

    // v3.11.5: Insert key-reset system message CHRONOLOGICALLY (not at end)
    if (!chat.isGroup && knownIdentityKeys[state.currentChatId]) {
        const known = knownIdentityKeys[state.currentChatId];
        if (known.trusted === false) {
            const dn = chat.displayName || chat.username || state.currentChatId;
            // v3.11.6: Use localStorage reset timestamp (set at actual reset event time)
            const resetTimeStr = localStorage.getItem('vibe_key_reset_time_' + state.currentChatId);
            const resetTime = resetTimeStr ? parseInt(resetTimeStr) : 0;
            const sysHTML = '<div class="system-message key-reset-message">' +
                '<div class="system-message-content">' +
                '<span class="system-message-icon">🔑</span>' +
                '<span class="system-message-text">Security code with <strong>' + escapeHtml(dn) + '</strong> changed. Your messages are secured with new encryption keys.</span>' +
                '</div></div>';
            
            if (resetTime > 0) {
                // Find first message AFTER the reset
                let firstMsgAfterReset = null;
                for (const msg of messages) {
                    if (new Date(msg.created_at).getTime() >= resetTime) {
                        firstMsgAfterReset = msg.id;
                        break;
                    }
                }
                
                if (firstMsgAfterReset) {
                    const msgEl = container.querySelector('[data-message-id="' + firstMsgAfterReset + '"]');
                    if (msgEl) {
                        msgEl.insertAdjacentHTML('beforebegin', sysHTML);
                    } else {
                        container.insertAdjacentHTML('beforeend', sysHTML);
                    }
                } else {
                    container.insertAdjacentHTML('beforeend', sysHTML);
                }
            } else {
                container.insertAdjacentHTML('beforeend', sysHTML);
            }
        }
    }

    scrollToBottom();
    
    // Load polls in messages
    loadPollsInMessages();
    
    // v3.6.0: Load link previews for messages with URLs
    loadLinkPreviewsInMessages();
    
    // Start countdown update interval if there are disappearing messages
    startDisappearingCountdown();
}

// Load polls from messages
// Poll cache to avoid repeated requests
const pollCache = {};
const pollLoadQueue = [];
let pollLoadingInProgress = false;

function loadPollsInMessages() {
    const messages = document.querySelectorAll('.message');
    messages.forEach(msgEl => {
        const textEl = msgEl.querySelector('.message-text, .md-text');
        if (!textEl) return;
        
        const text = textEl.textContent || textEl.innerText;
        const pollMatch = text.match(/\[poll:([a-fA-F0-9-]+)\]/);
        
        if (pollMatch && !msgEl.querySelector('.poll-container')) {
            const pollId = pollMatch[1];
            // КАО#230 (SER#18): capture the per-poll content key carried inside the E2E message,
            // then strip BOTH markers from the visible text.
            const keyMatch = text.match(/\[pollkey:([^\]\s]*)\]/);
            if (keyMatch && keyMatch[1] && !state.pollKeys[pollId]) state.pollKeys[pollId] = keyMatch[1];
            textEl.innerHTML = textEl.innerHTML.replace(/\[poll:[a-fA-F0-9-]+\]/g, '').replace(/\[pollkey:[^\]\s]*\]/g, '');

            // Use cached poll if available
            if (pollCache[pollId]) {
                renderPoll(pollCache[pollId], msgEl);
            } else {
                // Add to queue for sequential loading
                pollLoadQueue.push({ pollId, container: msgEl });
                processPolLoadQueue();
            }
        }
    });
}

async function processPolLoadQueue() {
    if (pollLoadingInProgress || pollLoadQueue.length === 0) return;
    
    pollLoadingInProgress = true;
    
    while (pollLoadQueue.length > 0) {
        const { pollId, container } = pollLoadQueue.shift();
        
        // Skip if already loaded
        if (container.querySelector('.poll-container')) continue;
        
        // Use cache if available
        if (pollCache[pollId]) {
            renderPoll(pollCache[pollId], container);
            continue;
        }
        
        await loadPoll(pollId, container);
        // Small delay between requests to avoid rate limiting
        await new Promise(r => setTimeout(r, 100));
    }
    
    pollLoadingInProgress = false;
}

// v3.6.0: Load link previews for messages with URLs
function loadLinkPreviewsInMessages() {
    const messages = document.querySelectorAll('.message');
    messages.forEach(msgEl => {
        // Skip if already has a preview OR the КАО#276 click-to-load button (avoid duplicates on re-render)
        if (msgEl.querySelector('.link-preview') || msgEl.querySelector('.link-preview-load-btn')) return;

        const textEl = msgEl.querySelector('.message-text, .md-text');
        if (!textEl) return;

        const text = textEl.textContent || textEl.innerText;
        addLinkPreviewsToMessage(msgEl, text);
    });
}

// Countdown update for disappearing messages
var disappearingCountdownInterval = null;

function startDisappearingCountdown() {
    // Clear existing interval
    if (disappearingCountdownInterval) {
        clearInterval(disappearingCountdownInterval);
        disappearingCountdownInterval = null;
    }
    
    // Check if there are any disappearing messages in current view
    const disappearingElements = document.querySelectorAll('.message[data-expires]:not([data-expires=""])');
    if (disappearingElements.length === 0) return;
    
    // Update countdown every second
    disappearingCountdownInterval = setInterval(() => {
        const now = new Date();
        let hasExpired = false;
        
        disappearingElements.forEach(el => {
            const expiresAt = el.getAttribute('data-expires');
            if (!expiresAt) return;
            
            const expiresDate = new Date(expiresAt);
            const remainingMs = expiresDate - now;
            
            const timeEl = el.querySelector('.disappearing-time');
            if (!timeEl) return;
            
            if (remainingMs <= 0) {
                hasExpired = true;
                return;
            }
            
            // Update countdown display
            let timeStr;
            const remainingSec = Math.floor(remainingMs / 1000);
            if (remainingSec < 60) {
                timeStr = remainingSec + 's';
            } else if (remainingSec < 3600) {
                const mins = Math.floor(remainingSec / 60);
                const secs = remainingSec % 60;
                timeStr = mins + ':' + (secs < 10 ? '0' : '') + secs;
            } else if (remainingSec < 86400) {
                const hours = Math.floor(remainingSec / 3600);
                const mins = Math.floor((remainingSec % 3600) / 60);
                timeStr = hours + 'h ' + mins + 'm';
            } else {
                const days = Math.floor(remainingSec / 86400);
                const hours = Math.floor((remainingSec % 86400) / 3600);
                timeStr = days + 'd ' + hours + 'h';
            }
            
            timeEl.textContent = '⏱️ ' + timeStr;
            timeEl.title = 'Disappears in ' + timeStr;
        });
        
        // If any message expired, trigger cleanup and rerender
        if (hasExpired) {
            clearInterval(disappearingCountdownInterval);
            disappearingCountdownInterval = null;
            cleanupExpiredMessages();
        }
    }, 1000);
}

function generateWaveform() {
    let bars = '';
    for (let i = 0; i < 20; i++) {
        const height = 5 + Math.random() * 20;
        bars += '<div class="voice-bar" style="height: ' + height + 'px"></div>';
    }
    return bars;
}

function formatFileSize(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
    return Math.round(bytes / 1024 / 1024 * 10) / 10 + ' MB';
}

// ==================== MESSAGE CONTEXT MENU ====================

var messageTouchTimer = null;
var editingMessageId = null;

function showMessageMenu(event, messageId, isSent) {
    event.preventDefault();
    
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    const message = chat.messages.find(m => m.id === messageId);
    if (!message) return;
    
    // Store current message info
    state.selectedMessage = { id: messageId, isSent: isSent, message: message };
    
    // Update menu options based on who sent the message
    const editBtn = document.getElementById('menu-edit-btn');
    const deleteForAllBtn = document.getElementById('menu-delete-all-btn');
    const pinBtn = document.getElementById('menu-pin-btn');
    const unpinBtn = document.getElementById('menu-unpin-btn');
    
    // Only sender can edit (and only text messages)
    if (editBtn) {
        if (isSent && !message.file) {
            editBtn.classList.remove('hidden');
        } else {
            editBtn.classList.add('hidden');
        }
    }
    
    // Only sender can delete for everyone
    if (deleteForAllBtn) {
        if (isSent) {
            deleteForAllBtn.classList.remove('hidden');
        } else {
            deleteForAllBtn.classList.add('hidden');
        }
    }
    
    // Pin/Unpin logic
    const isPinned = message.is_pinned || (chat.pinnedMessages && chat.pinnedMessages.some(p => p.id === messageId));
    const canPin = canUserPin(chat);
    
    if (pinBtn) {
        if (canPin && !isPinned) {
            pinBtn.classList.remove('hidden');
        } else {
            pinBtn.classList.add('hidden');
        }
    }
    
    if (unpinBtn) {
        if (canPin && isPinned) {
            unpinBtn.classList.remove('hidden');
        } else {
            unpinBtn.classList.add('hidden');
        }
    }
    
    // v3.8.38: Update favorite button text based on current state
    const favoriteBtn = document.getElementById('menu-favorite-btn');
    if (favoriteBtn) {
        const isFavorited = state.favoriteMessageIds.has(messageId);
        if (isFavorited) {
            favoriteBtn.innerHTML = '<span class="menu-icon">⭐</span> Remove from favorites';
        } else {
            favoriteBtn.innerHTML = '<span class="menu-icon">☆</span> Add to favorites';
        }
    }
    
    // v3.7.28: Position menu near the clicked message
    const menu = document.getElementById('message-menu');
    const menuWidth = 280;
    const menuHeight = 400; // approximate max height
    
    // Get click/touch position
    let clickX = event.clientX || (event.touches && event.touches[0].clientX) || window.innerWidth / 2;
    let clickY = event.clientY || (event.touches && event.touches[0].clientY) || window.innerHeight / 2;
    
    // Calculate position - try to show menu near click point
    let menuX = clickX - menuWidth / 2;
    let menuY = clickY - 20;
    
    // Adjust for screen boundaries
    const padding = 10;
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    
    // Horizontal bounds
    if (menuX < padding) {
        menuX = padding;
    } else if (menuX + menuWidth > viewportWidth - padding) {
        menuX = viewportWidth - menuWidth - padding;
    }
    
    // Vertical bounds - prefer showing below click, but above if not enough space
    if (menuY + menuHeight > viewportHeight - padding) {
        // Not enough space below - show above click point
        menuY = Math.max(padding, clickY - menuHeight - 20);
    }
    if (menuY < padding) {
        menuY = padding;
    }
    
    // Apply position
    menu.style.left = menuX + 'px';
    menu.style.top = menuY + 'px';
    menu.style.bottom = 'auto';
    menu.style.transform = 'none';
    
    // Show menu
    menu.classList.remove('hidden');
    document.getElementById('message-menu-overlay').classList.remove('hidden');
    // КАО#283 (#21): keyboard access — expose as a menu and focus the first item (Escape closes it,
    // handled by the global a11y handler).
    menu.setAttribute('role', 'menu');
    const firstItem = menu.querySelector('button, [role="menuitem"], a[href], [tabindex]:not([tabindex="-1"])');
    if (firstItem) { try { firstItem.focus({ preventScroll: true }); } catch (e) {} }
}

// Check if current user can pin messages in this chat
function canUserPin(chat) {
    if (!chat || !state.user) return false;
    
    if (chat.isGroup) {
        // Only group creator can pin
        return chat.created_by === state.user.id;
    } else {
        // Both participants can pin in direct chats
        return true;
    }
}

function hideMessageMenu() {
    document.getElementById('message-menu').classList.add('hidden');
    document.getElementById('message-menu-overlay').classList.add('hidden');
    state.selectedMessage = null;
}

function closeMessageMenu() {
    hideMessageMenu();
}

async function toggleFavoriteFromMenu() {
    if (!state.selectedMessage) return;
    
    const msg = state.selectedMessage.message;
    const messageId = state.selectedMessage.id;
    const senderId = msg.sender_id || (state.selectedMessage.isSent ? state.user?.id : state.currentChatId);
    const senderName = msg.sender_name || (state.selectedMessage.isSent ? state.user?.username : state.currentChat?.username);
    const previewText = msg.text ? msg.text.substring(0, 200) : '';
    
    await toggleFavorite(messageId, senderId, senderName, previewText);
}

// Copy message text to clipboard
async function copyMessageText() {
    if (!state.selectedMessage) return;
    
    const msg = state.selectedMessage.message;
    const text = msg.text || msg.content || "";
    
    if (!text) {
        console.log("No text to copy");
        hideMessageMenu();
        return;
    }
    
    try {
        await navigator.clipboard.writeText(text);
        console.log("Message copied to clipboard");
    } catch (e) {
        console.error("Failed to copy:", e);
        // Fallback
        const textarea = document.createElement("textarea");
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
    }
    
    hideMessageMenu();
}

async function pinSelectedMessage() {
    if (!state.selectedMessage) return;
    
    const messageId = state.selectedMessage.id;
    hideMessageMenu();
    
    await pinMessage(messageId);
}

async function unpinSelectedMessage() {
    if (!state.selectedMessage) return;
    
    const messageId = state.selectedMessage.id;
    hideMessageMenu();
    
    await unpinMessage(messageId);
}

// v3.8.27: Delegated event handlers for messages (passive for better performance)
(function initMessageEventDelegation() {
    const container = document.getElementById('messages');
    if (!container) {
        // Wait for DOM
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initMessageEventDelegation);
        }
        return;
    }
    
    // Store touch coordinates for later use (touch event becomes stale in setTimeout)
    let touchCoords = { x: 0, y: 0 };
    
    // v3.8.36: Handle click for multi-select mode
    container.addEventListener('click', (e) => {
        if (state.multiSelectMode) {
            handleMessageClickInMultiSelect(e);
        }
    });
    
    // Delegated touchstart for long-press menu
    container.addEventListener('touchstart', (e) => {
        // v3.8.36: In multi-select mode, use tap instead of long-press
        if (state.multiSelectMode) {
            return; // Let click handler deal with it
        }
        
        const messageEl = e.target.closest('.message[data-id]');
        if (messageEl && e.touches && e.touches[0]) {
            const messageId = messageEl.dataset.id;
            const isSent = messageEl.dataset.isSent === 'true';
            // Save coordinates immediately (event becomes stale in setTimeout)
            touchCoords.x = e.touches[0].clientX;
            touchCoords.y = e.touches[0].clientY;
            
            messageTouchTimer = setTimeout(() => {
                // Create synthetic event with saved coordinates
                const syntheticEvent = {
                    clientX: touchCoords.x,
                    clientY: touchCoords.y,
                    preventDefault: function() {},  // No-op for touch
                    target: messageEl
                };
                showMessageMenu(syntheticEvent, messageId, isSent);
            }, 500);
        }
    }, { passive: true });
    
    container.addEventListener('touchend', (e) => {
        if (messageTouchTimer) {
            clearTimeout(messageTouchTimer);
            messageTouchTimer = null;
        }
        
        // v3.8.36: Handle tap in multi-select mode
        if (state.multiSelectMode) {
            handleMessageClickInMultiSelect(e);
        }
    }, { passive: true });
    
    container.addEventListener('touchmove', () => {
        // Cancel long-press if user moves finger
        if (messageTouchTimer) {
            clearTimeout(messageTouchTimer);
            messageTouchTimer = null;
        }
    }, { passive: true });
    
    // Delegated contextmenu for right-click menu
    container.addEventListener('contextmenu', (e) => {
        // v3.8.36: Disable context menu in multi-select mode
        if (state.multiSelectMode) {
            e.preventDefault();
            return;
        }
        
        const messageEl = e.target.closest('.message[data-id]');
        if (messageEl) {
            e.preventDefault();
            const messageId = messageEl.dataset.id;
            const isSent = messageEl.dataset.isSent === 'true';
            showMessageMenu(e, messageId, isSent);
        }
    });
})();

// Delete message for me only
async function deleteMessageForMe() {
    if (!state.selectedMessage) return;
    
    const messageId = state.selectedMessage.id;
    hideMessageMenu();
    
    // Call messages are local-only, delete without server request
    if (messageId.startsWith('call_')) {
        removeMessageFromChat(messageId);
        return;
    }
    
    try {
        const response = await api('/messages/' + messageId + '?for_everyone=false', {
            method: 'DELETE',
        });
        
        if (response.ok || response.status === 204) {
            // Remove from local state
            removeMessageFromChat(messageId);
        } else {
            await showAlert('Failed to delete message', 'Error', '❌');
        }
    } catch (e) {
        console.error('Delete error:', e);
        await showAlert('Failed to delete message', 'Error', '❌');
    }
}

// Delete message for everyone
async function deleteMessageForAll() {
    if (!state.selectedMessage) return;

    const messageId = state.selectedMessage.id;
    hideMessageMenu();

    // КАО#123: confirm irreversible delete-for-everyone (was no confirmation; batch version has one)
    if (!await showConfirm('Delete this message for everyone? This cannot be undone.', 'Delete for everyone', 'Delete')) return;

    // Call messages are local-only, delete without server request
    if (messageId.startsWith('call_')) {
        removeMessageFromChat(messageId);
        return;
    }
    
    try {
        const response = await api('/messages/' + messageId + '?for_everyone=true', {
            method: 'DELETE',
        });
        
        if (response.ok || response.status === 204) {
            // Remove from local state
            removeMessageFromChat(messageId);
        } else {
            await showAlert('Failed to delete message', 'Error', '❌');
        }
    } catch (e) {
        console.error('Delete error:', e);
        await showAlert('Failed to delete message', 'Error', '❌');
    }
}

function removeMessageFromChat(messageId) {
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    const idx = chat.messages.findIndex(m => m.id === messageId);
    if (idx !== -1) {
        const msg = chat.messages[idx];
        
        // Clear poll cache if message contains a poll
        if (msg.text) {
            const pollMatch = msg.text.match(/\[poll:([a-fA-F0-9-]+)\]/);
            if (pollMatch && pollCache[pollMatch[1]]) {
                delete pollCache[pollMatch[1]];
            }
        }
        
        chat.messages.splice(idx, 1);
        
        // Update last message
        if (chat.messages.length > 0) {
            chat.lastMessage = chat.messages[chat.messages.length - 1];
        } else {
            chat.lastMessage = null;
        }
        
        saveChats();
        renderMessages();
        renderChatsList();
    }
}

// ==================== REACTIONS ====================

async function addReaction(emoji) {
    if (!state.selectedMessage) return;
    
    const messageId = state.selectedMessage.id;
    hideMessageMenu();
    
    try {
        const response = await api('/messages/' + messageId + '/react', {
            method: 'POST',
            body: JSON.stringify({ emoji: emoji }),
        });
        
        if (response.ok) {
            const data = await response.json();
            // Update local message reactions
            updateMessageReactions(messageId, data.reactions);
        } else {
            const error = await response.json();
            console.error('Failed to add reaction:', error.detail);
        }
    } catch (e) {
        console.error('Reaction error:', e);
    }
}

async function removeReaction(messageId) {
    try {
        const response = await api('/messages/' + messageId + '/react', {
            method: 'DELETE',
        });
        
        if (response.ok) {
            updateMessageReactions(messageId, []);
        }
    } catch (e) {
        console.error('Remove reaction error:', e);
    }
}

function handleMessageReaction(payload) {
    console.log('Reaction update:', payload);
    
    // Find which chat this message belongs to
    let chatId = payload.group_id || payload.chat_id;
    
    // If chat_id is the other user's ID, we need to find the right chat
    if (!chatId) {
        // Try to find message in current chat or any chat
        for (const cid in state.chats) {
            const chat = state.chats[cid];
            if (chat.messages && chat.messages.some(m => m.id === payload.message_id)) {
                chatId = cid;
                break;
            }
        }
    }
    
    // КАО#290: do NOT gate on state.chats[chatId]. The server broadcasts RAW column values, so for a
    // group `payload.group_id` is the BARE uuid while the local chat key is 'group_'+id, and for a 1:1
    // `payload.chat_id` can be the recipient's own id — in both cases the keyed lookup misses and the
    // live reaction was silently dropped (it only appeared after a reload). updateMessageReactions()
    // already locates the message by id across ALL chats and re-renders, so call it unconditionally.
    updateMessageReactions(payload.message_id, payload.reactions);
}

/**
 * Handle poll update from WebSocket
 */
async function handlePollUpdate(payload) {
    console.log('Poll update:', payload);

    const pollId = payload.poll_id;
    const poll = payload.poll;

    if (!pollId || !poll) return;

    await decryptPollFields(poll);  // КАО#230 (SER#18)
    // Update cache
    pollCache[pollId] = poll;

    // Find and update poll container in current view
    const pollContainer = document.querySelector(`.poll-container[data-poll-id="${pollId}"]`);
    if (pollContainer) {
        renderPoll(poll, pollContainer.parentElement);
        pollContainer.remove();
    }
}

function updateMessageReactions(messageId, reactions) {
    // Find message in any chat and update
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (chat.messages) {
            const message = chat.messages.find(m => m.id === messageId);
            if (message) {
                message.reactions = reactions;
                saveChats();
                
                // Re-render if this is current chat
                if (chatId === state.currentChatId) {
                    renderMessages();
                }
                break;
            }
        }
    }
}

function renderReactions(reactions, messageId) {
    if (!reactions || reactions.length === 0) return '';
    
    let html = '<div class="message-reactions">';
    
    reactions.forEach(r => {
        const isMyReaction = r.users && r.users.some(u => u.user_id === state.user.id);
        const myClass = isMyReaction ? ' my-reaction' : '';
        // v3.7.32: Click removes if my reaction, shows users otherwise
        html += '<button class="reaction-badge' + myClass + '" onclick="event.stopPropagation(); handleReactionBadgeClick(\'' + escapeHtml(messageId) + '\', \'' + escapeHtml(r.emoji) + '\', ' + isMyReaction + ')">';
        html += '<span class="reaction-emoji-badge">' + escapeHtml(r.emoji) + '</span>';
        html += '<span class="reaction-count">' + r.count + '</span>';
        html += '</button>';
    });
    
    html += '</div>';
    return html;
}

async function showReactionUsers(messageId, emoji) {
    try {
        const response = await api('/messages/' + messageId + '/reactions');
        
        if (response.ok) {
            const data = await response.json();
            
            // Find the specific emoji group
            const reactionGroup = data.reactions.find(r => r.emoji === emoji);
            
            if (reactionGroup && reactionGroup.users) {
                document.getElementById('reaction-users-title').textContent = emoji + ' ' + reactionGroup.count;
                
                const listEl = document.getElementById('reaction-users-list');
                listEl.innerHTML = reactionGroup.users.map(u => {
                    const isMe = u.user_id === state.user.id;
                    return '<div class="reaction-user-item">' +
                        '<span class="reaction-user-name">' + escapeHtml(u.display_name) + (isMe ? ' (you)' : '') + '</span>' +
                        '</div>';
                }).join('');
                
                document.getElementById('reaction-users-modal').classList.remove('hidden');
            }
        }
    } catch (e) {
        console.error('Failed to load reaction users:', e);
    }
}

// v3.7.32: Handle click on reaction badge - remove if mine, show users if not
async function handleReactionBadgeClick(messageId, emoji, isMyReaction) {
    if (isMyReaction) {
        // Remove my reaction
        try {
            const response = await api('/messages/' + messageId + '/react', {
                method: 'DELETE',
            });
            
            if (response.ok) {
                // Update will come via WebSocket
                console.log('Reaction removed');
            }
        } catch (e) {
            console.error('Remove reaction error:', e);
        }
    } else {
        // Show who reacted
        showReactionUsers(messageId, emoji);
    }
}

function hideReactionUsersModal() {
    document.getElementById('reaction-users-modal').classList.add('hidden');
}

// ==================== MENTIONS ====================

var mentionsPopupVisible = false;
var mentionStartIndex = -1;
var currentMentionQuery = '';

var mentionsInitialized = false;

function initMentions() {
    const input = document.getElementById('message-text');
    if (!input) return;
    
    // Prevent duplicate listeners
    if (mentionsInitialized) return;
    mentionsInitialized = true;
    
    input.addEventListener('input', handleMentionInput);
    input.addEventListener('keydown', handleMentionKeydown);
    
    // Close popup on click outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.mentions-popup') && !e.target.closest('#message-text')) {
            hideMentionsPopup();
        }
    });
}

function handleMentionInput(e) {
    const input = e.target;
    const text = input.value;
    const cursorPos = input.selectionStart;
    
    // Check if we're in a group chat
    const chat = state.chats[state.currentChatId];
    if (!chat || !chat.isGroup) {
        hideMentionsPopup();
        return;
    }
    
    // Find @ before cursor
    const textBeforeCursor = text.substring(0, cursorPos);
    const lastAtIndex = textBeforeCursor.lastIndexOf('@');
    
    if (lastAtIndex >= 0) {
        // Check if @ is at start or after space
        if (lastAtIndex === 0 || textBeforeCursor[lastAtIndex - 1] === ' ') {
            const query = textBeforeCursor.substring(lastAtIndex + 1);
            
            // Check if query contains space (mention ended)
            if (!query.includes(' ')) {
                mentionStartIndex = lastAtIndex;
                currentMentionQuery = query.toLowerCase();
                showMentionsPopup(chat, currentMentionQuery);
                return;
            }
        }
    }
    
    hideMentionsPopup();
}

function handleMentionKeydown(e) {
    if (!mentionsPopupVisible) return;
    
    const popup = document.getElementById('mentions-popup');
    const items = popup.querySelectorAll('.mention-item');
    const selected = popup.querySelector('.mention-item.selected');
    
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (selected) {
            const next = selected.nextElementSibling;
            if (next) {
                selected.classList.remove('selected');
                next.classList.add('selected');
                next.scrollIntoView({ block: 'nearest' });
            }
        } else if (items.length > 0) {
            items[0].classList.add('selected');
        }
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (selected) {
            const prev = selected.previousElementSibling;
            if (prev) {
                selected.classList.remove('selected');
                prev.classList.add('selected');
                prev.scrollIntoView({ block: 'nearest' });
            }
        }
    } else if (e.key === 'Enter' && selected) {
        e.preventDefault();
        const userId = selected.dataset.userId;
        const displayName = selected.dataset.displayName;
        insertMention(userId, displayName);
    } else if (e.key === 'Escape') {
        hideMentionsPopup();
    }
}

async function showMentionsPopup(chat, query) {
    // Load members if not cached
    if (!chat.membersCache) {
        try {
            const response = await api('/groups/' + chat.id + '/members');
            if (response.ok) {
                chat.membersCache = await response.json();
            }
        } catch (e) {
            console.error('Failed to load members:', e);
            return;
        }
    }
    
    const members = chat.membersCache || [];
    
    // Filter by query and exclude self
    let filtered = members.filter(m => 
        m.user_id !== state.user.id &&
        m.display_name.toLowerCase().includes(query)
    );
    
    // Add @all option
    const allOption = { user_id: '@all', display_name: 'All participants' };
    if ('all'.includes(query) || 'everyone'.includes(query) || query === '') {
        filtered = [allOption, ...filtered];
    }
    
    if (filtered.length === 0) {
        hideMentionsPopup();
        return;
    }
    
    // Render popup
    const list = document.getElementById('mentions-list');
    list.innerHTML = filtered.slice(0, 8).map((m, idx) => {
        const isAll = m.user_id === '@all';
        return '<div class="mention-item' + (idx === 0 ? ' selected' : '') + '" ' +
            'data-user-id="' + escapeHtml(m.user_id) + '" ' +
            'data-display-name="' + escapeHtml(m.display_name) + '" ' +
            'onclick="insertMention(\'' + escapeHtml(m.user_id) + '\', \'' + escapeJsString(m.display_name) + '\')">' +
            '<span class="mention-icon">' + (isAll ? '👥' : '👤') + '</span>' +
            '<span class="mention-name">' + escapeHtml(m.display_name) + '</span>' +
            '</div>';
    }).join('');
    
    document.getElementById('mentions-popup').classList.remove('hidden');
    mentionsPopupVisible = true;
}

function hideMentionsPopup() {
    document.getElementById('mentions-popup').classList.add('hidden');
    mentionsPopupVisible = false;
    mentionStartIndex = -1;
    currentMentionQuery = '';
}

function insertMention(userId, displayName) {
    const input = document.getElementById('message-text');
    const text = input.value;
    const cursorPos = input.selectionStart;
    
    // Replace @query with @displayName
    const beforeMention = text.substring(0, mentionStartIndex);
    const afterCursor = text.substring(cursorPos);
    
    const mentionText = '@' + displayName + ' ';
    input.value = beforeMention + mentionText + afterCursor;
    
    // Move cursor after mention
    const newCursorPos = mentionStartIndex + mentionText.length;
    input.setSelectionRange(newCursorPos, newCursorPos);
    input.focus();
    
    hideMentionsPopup();
}

function extractMentions(text, chat) {
    if (!chat.membersCache) return [];
    
    const mentions = [];
    const members = chat.membersCache;
    
    // Check for @all
    if (text.includes('@All participants') || text.match(/@all\b/i)) {
        return ['@all'];
    }
    
    // Find @displayName mentions
    for (const member of members) {
        if (member.user_id === state.user.id) continue;
        
        const mentionPattern = '@' + member.display_name;
        if (text.includes(mentionPattern)) {
            mentions.push(member.user_id);
        }
    }
    
    return mentions;
}

function highlightMentions(text) {
    if (!text) return text;
    
    // Highlight @all
    text = text.replace(/@All participants/g, '<span class="mention-highlight">@All participants</span>');
    
    // Highlight @username patterns (text is already escaped)
    text = text.replace(/@([^\s<]+)/g, function(match, name) {
        // Don't re-highlight already highlighted
        if (match.includes('class=')) return match;
        return '<span class="mention-highlight">' + match + '</span>';
    });
    
    return text;
}

// ==================== REPLY FUNCTIONS ====================

function startReplyMessage() {
    if (!state.selectedMessage) return;
    
    const message = state.selectedMessage.message;
    const senderId = message.sender_id;
    
    // Get sender name
    let senderName = 'Unknown';
    if (senderId === state.user.id) {
        senderName = 'You';
    } else {
        const chat = state.chats[state.currentChatId];
        if (chat) {
            if (chat.isGroup) {
                senderName = message.sender_name || 'Unknown';
            } else {
                senderName = chat.displayName || chat.username || 'Unknown';
            }
        }
    }
    
    // Set reply state
    state.replyToMessage = {
        id: message.id,
        sender_id: senderId,
        sender_name: senderName,
        text: message.text || '[Media]',
    };
    
    // Show reply preview
    const replyPreview = document.getElementById('reply-preview');
    const replyAuthor = document.getElementById('reply-author');
    const replyText = document.getElementById('reply-text');
    
    replyAuthor.textContent = senderName;
    replyText.textContent = truncateText(state.replyToMessage.text, 50);
    replyPreview.classList.remove('hidden');
    
    hideMessageMenu();
    
    // Focus input
    document.getElementById('message-text').focus();
}

function cancelReply() {
    state.replyToMessage = null;
    document.getElementById('reply-preview').classList.add('hidden');
}

function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Start editing a message
function startEditMessage() {
    if (!state.selectedMessage) return;
    
    const message = state.selectedMessage.message;
    editingMessageId = state.selectedMessage.id;
    
    hideMessageMenu();
    
    // Show edit UI
    const input = document.getElementById('message-text');
    input.value = message.text;
    input.focus();
    
    // Change send button to save
    document.getElementById('send-btn').classList.add('hidden');
    document.getElementById('edit-actions').classList.remove('hidden');
}

// Save edited message
async function saveEditMessage() {
    if (!editingMessageId) return;
    
    const input = document.getElementById('message-text');
    const newText = input.value.trim();
    
    if (!newText) {
        await showAlert('Message cannot be empty', 'Error', '⚠️');
        return;
    }
    
    try {
        const chat = state.chats[state.currentChatId];
        const isGroup = chat && chat.isGroup;
        
        // E2EE: Encrypt the edited message
        let encryptedPayload;
        let encryptedForSelf = null;
        
        if (state.e2eeReady) {
            try {
                if (isGroup) {
                    // Group message - encrypt with sender key
                    const result = await VibeCrypto.encryptGroupMessage(chat.id, newText);
                    encryptedPayload = result.payload;
                } else {
                    // Direct message - encrypt with Double Ratchet
                    encryptedPayload = await VibeCrypto.encryptMessage(state.currentChatId, newText);
                }
                // Encrypt for self (multi-device sync)
                encryptedForSelf = await VibeCrypto.encryptForSelf(newText);
                console.log('[E2EE] Edit message encrypted');
            } catch (e) {
                console.warn('[E2EE] Edit encryption failed:', e);
                showEncryptionFailedError('Edit encryption failed. Changes were NOT saved.');
                return;
            }
        } else {
            // v3.11.9: Fail-closed — E2EE not ready
            showEncryptionFailedError('Cannot edit: encryption not initialized.');
            return;
        }
        
        const payload = {
            encrypted_payload: encryptedPayload,
        };
        if (encryptedForSelf) {
            payload.encrypted_for_self = encryptedForSelf;
        }
        
        const response = await api('/messages/' + editingMessageId, {
            method: 'PUT',
            body: JSON.stringify(payload),
        });
        
        if (response.ok) {
            // Update local message
            if (chat) {
                const message = chat.messages.find(m => m.id === editingMessageId);
                if (message) {
                    message.text = newText;
                    message.is_edited = true;
                    message.edited_at = new Date().toISOString();
                    saveChats();
                    renderMessages();
                    // v3.11.10: Ensure markdown preview is cleared after edit save
                    clearMarkdownPreview();
                    
                    // Update decrypted cache for E2EE
                    if (state.e2eeReady) {
                        offlineDB.saveDecryptedMessage(editingMessageId, state.currentChatId, newText, null);
                    }
                }
            }
            
            cancelEditMessage();
        } else {
            const data = await response.json();
            await showAlert(data.detail || 'Failed to edit message', 'Error', '❌');
        }
    } catch (e) {
        console.error('Edit error:', e);
        await showAlert('Failed to edit message', 'Error', '❌');
    }
}

// Cancel editing
function cancelEditMessage() {
    editingMessageId = null;
    document.getElementById('message-text').value = '';
    document.getElementById('send-btn').classList.remove('hidden');
    document.getElementById('edit-actions').classList.add('hidden');
    // v3.11.10: Clear markdown preview after edit
    clearMarkdownPreview();
}

// ==================== FORWARD MESSAGE ====================

function showForwardModal() {
    // Hide menu but keep selectedMessage
    document.getElementById('message-menu').classList.add('hidden');
    document.getElementById('message-menu-overlay').classList.add('hidden');
    
    // Build list of chats to forward to
    const listEl = document.getElementById('forward-chat-list');
    const chatIds = Object.keys(state.chats).filter(id => id !== state.currentChatId);
    
    if (chatIds.length === 0) {
        listEl.innerHTML = '<p class="empty-forward">No other chats available</p>';
    } else {
        listEl.innerHTML = chatIds.map(chatId => {
            const chat = state.chats[chatId];
            const name = escapeHtml(chat.displayName || chat.username || chatId);
            const initial = escapeHtml((chat.displayName || chat.username || chatId)[0].toUpperCase());
            return '<div class="forward-chat-item" onclick="forwardMessageTo(\'' + escapeHtml(chatId) + '\')">' +
                '<div class="chat-avatar">' + initial + '</div>' +
                '<span class="forward-chat-name">' + name + '</span>' +
                '<span class="forward-send-icon">➤</span>' +
                '</div>';
        }).join('');
    }
    
    document.getElementById('forward-modal').classList.remove('hidden');
}

function hideForwardModal() {
    document.getElementById('forward-modal').classList.add('hidden');
    state.selectedMessage = null;
}

async function forwardMessageTo(recipientId) {
    if (!state.selectedMessage) return;
    
    const originalMessage = state.selectedMessage.message;
    const messageId = 'msg_' + Date.now();
    
    // Determine original sender name
    let forwardedFromName;
    let forwardedFromId;
    
    if (originalMessage.forwarded_from_id) {
        // Already forwarded - keep original sender
        forwardedFromId = originalMessage.forwarded_from_id;
        forwardedFromName = originalMessage.forwarded_from_name;
    } else {
        // First forward - use original message sender
        if (originalMessage.sender_id === state.user.id) {
            forwardedFromId = state.user.id;
            forwardedFromName = state.user.display_name || state.user.username;
        } else {
            // Get sender info. КАО#272 (#29): a message forwarded FROM a group has a group-member
            // sender (no DM chat keyed by their id) — fall back to the group's membersCache and the
            // message's own sender_name before showing 'Unknown'.
            forwardedFromId = originalMessage.sender_id;
            const senderChat = state.chats[originalMessage.sender_id];
            let nm = senderChat ? (senderChat.displayName || senderChat.username) : null;
            if (!nm && state.currentChat && state.currentChat.isGroup && Array.isArray(state.currentChat.membersCache)) {
                const mem = state.currentChat.membersCache.find(m => m.user_id === originalMessage.sender_id);
                if (mem) nm = mem.display_name || mem.username;
            }
            forwardedFromName = nm || originalMessage.sender_name || 'Unknown';
        }
    }
    
    hideForwardModal();
    
    // Create local message for UI
    const message = {
        id: messageId,
        text: originalMessage.text,
        file: originalMessage.file,
        sender_id: state.user.id,
        created_at: new Date().toISOString(),
        status: 'sending',
        forwarded_from_id: forwardedFromId,
        forwarded_from_name: forwardedFromName,
        // v3.11.10: Set E2EE flag for forwarded messages
        e2ee: state.e2eeReady,
    };
    
    // Add to recipient's chat
    if (!state.chats[recipientId]) {
        // Need to create chat first
        try {
            const response = await api('/auth/user/id/' + recipientId);
            if (response.ok) {
                const userData = await response.json();
                state.chats[recipientId] = { 
                    id: recipientId, 
                    username: userData.username, 
                    displayName: userData.display_name || userData.username, 
                    messages: [], 
                    unreadCount: 0, 
                    missedCalls: 0 
                };
            }
        } catch (e) {
            console.error('Failed to get user info:', e);
        }
    }
    
    if (state.chats[recipientId]) {
        state.chats[recipientId].messages.push(message);
        state.chats[recipientId].lastMessage = message;
        saveChats();
        renderChatsList();
    }
    
    // Send to server
    try {
        // Determine if target is a group chat
        const isGroupTarget = recipientId.startsWith('group_');
        const fwdText = originalMessage.file ? JSON.stringify(originalMessage.file) : originalMessage.text;

        if (!state.e2eeReady) {
            showEncryptionFailedError('End-to-end encryption is not initialized. Message was NOT forwarded.');
            updateMessageStatus(messageId, 'failed');
            return;
        }

        // КАО#272 (#9): capture the group sender-key distribution (was discarded — only .payload was used),
        // so members lacking the forwarder's current sender key can still decrypt the forwarded message.
        let encryptedPayload;
        let groupDistribution = null;
        if (isGroupTarget) {
            const gid = recipientId.replace('group_', '');
            const r = await VibeCrypto.encryptGroupMessage(gid, fwdText);
            encryptedPayload = r.payload;
            groupDistribution = r.distribution;
        } else {
            try { encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fwdText); }
            catch (e2) {
                const kb = await fetchKeyBundle(recipientId);
                if (kb) {
                    encryptedPayload = await VibeCrypto.encryptMessage(recipientId, fwdText, kb);
                } else {
                    const ok = await showUnencryptedConfirmDialog(recipientId);
                    if (!ok) { updateMessageStatus(messageId, 'failed'); return; }
                    encryptedPayload = btoa(unescape(encodeURIComponent(fwdText)));
                }
            }
        }

        const payload = {
            encrypted_payload: encryptedPayload,
            client_message_id: messageId,
            forwarded_from_id: forwardedFromId,
            forwarded_from_name: forwardedFromName,
        };

        if (isGroupTarget) {
            payload.group_id = recipientId.replace('group_', '');
            if (groupDistribution) payload.sender_key_distribution = await encryptDistributionForMembers(payload.group_id, groupDistribution);  // КАО#272 (#9 + #100)
        } else {
            payload.recipient_id = recipientId;
        }
        
        // Add file info if it's a file message
        if (originalMessage.file && originalMessage.file.file_id) {
            payload.message_type = originalMessage.file.is_voice ? 'voice' : 'file';
            payload.file_id = originalMessage.file.file_id;
        }

        // КАО#161: self-copy so the sender can re-decrypt the forwarded message after reload
        if (state.e2eeReady) {
            try {
                const fwdSelfText = originalMessage.file ? JSON.stringify(originalMessage.file) : originalMessage.text;
                payload.encrypted_for_self = await VibeCrypto.encryptForSelf(fwdSelfText);
            } catch (e) { console.warn('[forward] encryptForSelf failed', e); }
        }

        const response = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify(payload),
        });

        if (response.ok) {
            const data = await response.json();
            updateMessageWithServerId(messageId, data.id, data.status);
        } else {
            updateMessageStatus(messageId, 'failed');
            await showAlert('Failed to forward message', 'Error', '❌');
        }
    } catch (e) {
        console.error('Forward error:', e);
        updateMessageStatus(messageId, 'failed');
        await showAlert('Failed to forward message', 'Error', '❌');
    }
}

// ==================== MESSAGE SEARCH ====================

var searchResults = [];
var currentSearchIndex = -1;

function openSearch() {
    document.getElementById('search-bar').classList.remove('hidden');
    document.getElementById('search-input').focus();
    searchResults = [];
    currentSearchIndex = -1;
    updateSearchUI();
}

function closeSearch() {
    document.getElementById('search-bar').classList.add('hidden');
    document.getElementById('search-input').value = '';
    clearSearchHighlights();
    searchResults = [];
    currentSearchIndex = -1;
}

function performSearch() {
    const query = document.getElementById('search-input').value.trim().toLowerCase();
    const exactMatch = document.getElementById('search-exact').checked;
    
    clearSearchHighlights();
    searchResults = [];
    currentSearchIndex = -1;
    
    if (!query || !state.currentChatId || !state.chats[state.currentChatId]) {
        // v3.7.2: Re-render without highlights when query is empty
        if (!query && state.currentChatId && state.chats[state.currentChatId]) {
            renderMessagesWithHighlight('');
        }
        updateSearchUI();
        return;
    }
    
    const chat = state.chats[state.currentChatId];
    
    // v3.7.1: Client-side search only (works with E2EE decrypted messages)
    const messages = chat.messages || [];
    messages.forEach(function(msg, index) {
        if (msg.text) {
            const textLower = msg.text.toLowerCase();
            const matches = exactMatch ? (textLower === query) : textLower.includes(query);
            if (matches) {
                searchResults.push({ index: index, id: msg.id });
            }
        }
    });
    
    // Sort by index (chronological)
    searchResults.sort(function(a, b) { return a.index - b.index; });
    
    // Re-render with highlights
    renderMessagesWithHighlight(query);
    
    if (searchResults.length > 0) {
        currentSearchIndex = searchResults.length - 1; // Start from newest
        scrollToSearchResult();
    }
    
    updateSearchUI();
}

function renderMessagesWithHighlight(query) {
    const container = document.getElementById('messages');
    if (!state.currentChatId || !state.chats[state.currentChatId]) {
        container.innerHTML = '';
        return;
    }
    
    const messages = state.chats[state.currentChatId].messages || [];

    container.innerHTML = messages.map(msg => {
        // Handle call messages
        if (msg.isCallMessage || msg.message_type === 'call') {
            return renderCallMessageHTML(msg);
        }
        
        const isSent = msg.sender_id === state.user.id;
        let content = parseMarkdown(msg.text);
        
        // Highlight search query in text (after escaping)
        if (query && content) {
            const safeQuery = escapeHtml(query);
            if (content.toLowerCase().includes(safeQuery.toLowerCase())) {
                const regex = new RegExp('(' + escapeRegex(safeQuery) + ')', 'gi');
                content = content.replace(regex, '<span class="highlight-text">$1</span>');
            }
        }
        
        if (msg.file && msg.file.file_id) {
            regFileKey(msg.file);  // КАО#090: register at-rest key for download/play/gallery
            const ext = msg.file.extension || '';
            const isVoice = msg.file.is_voice || ext === 'webm' || (msg.text && msg.text.includes('Voice'));
            const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext);
            const isAudio = ['mp3', 'wav', 'ogg', 'm4a', 'webm'].includes(ext);
            const rawFilename = msg.file.filename || 'file';
            const safeFilename = escapeHtml(rawFilename);
            const jsFilename = safeOnclickArg(rawFilename);
            
            if (isVoice || (isAudio && msg.text && msg.text.includes('Voice'))) {
                const duration = msg.file.duration || 0;
                const mins = Math.floor(duration / 60);
                const secs = duration % 60;
                const durationStr = mins + ':' + (secs < 10 ? '0' : '') + secs;
                
                content = '<div class="voice-message">' +
                    '<button class="voice-play-btn" onclick="playVoiceMessage(\'' + escapeHtml(msg.file.file_id) + '\', this)">▶</button>' +
                    '<div class="voice-waveform">' + generateWaveform() + '</div>' +
                    '<span class="voice-duration">' + durationStr + '</span>' +
                    '</div>';
            } else if (isImage) {
                content = '<div class="file-message" onclick="downloadFile(\'' + escapeHtml(msg.file.file_id) + '\', \'' + jsFilename + '\')">' +
                    '<div class="file-name">📷 ' + safeFilename + '</div>' +
                    '</div>';
            } else {
                content = '<div class="file-message" onclick="downloadFile(\'' + escapeHtml(msg.file.file_id) + '\', \'' + jsFilename + '\')">' +
                    '<div class="file-icon">📎</div>' +
                    '<div class="file-name">' + safeFilename + '</div>' +
                    '<div class="file-size">' + formatFileSize(msg.file.size) + '</div>' +
                    '</div>';
            }
        }
        
        // Wrap text content in div for link preview support (only for plain text, not files)
        if (content && !content.startsWith('<div')) {
            content = '<div class="message-text">' + content + '</div>';
        }
        
        // Build forwarded header if message was forwarded
        const forwardedHeader = msg.forwarded_from_name 
            ? '<div class="forwarded-header">↪️ Forwarded from ' + escapeHtml(msg.forwarded_from_name) + '</div>'
            : '';
        
        // Build reactions
        const reactionsHtml = renderReactions(msg.reactions, msg.id);
        
        return '<div class="message ' + (isSent ? 'sent' : 'received') + '" data-id="' + escapeHtml(msg.id) + '" data-is-sent="' + isSent + '">' +
            forwardedHeader +
            content +
            reactionsHtml +
            '<div class="message-meta">' +
                getE2EEIndicator(msg.e2ee) +
                (msg.edited_at || msg.is_edited ? '<span class="message-edited">edited</span>' : '') +
                '<span class="message-time">' + formatTime(msg.created_at) + '</span>' +
                (isSent ? getStatusIcon(msg.status) : '') +
            '</div>' +
            '</div>';
    }).join('');
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function clearSearchHighlights() {
    document.querySelectorAll('.message.search-highlight').forEach(el => {
        el.classList.remove('search-highlight');
    });
}

function scrollToSearchResult() {
    if (searchResults.length === 0 || currentSearchIndex < 0) return;
    
    clearSearchHighlights();
    
    const result = searchResults[currentSearchIndex];
    const messageEl = document.querySelector('.message[data-id="' + result.id + '"]');
    
    if (messageEl) {
        messageEl.classList.add('search-highlight');
        messageEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    
    updateSearchUI();
}

function searchPrev() {
    if (searchResults.length === 0) return;
    currentSearchIndex = (currentSearchIndex - 1 + searchResults.length) % searchResults.length;
    scrollToSearchResult();
}

function searchNext() {
    if (searchResults.length === 0) return;
    currentSearchIndex = (currentSearchIndex + 1) % searchResults.length;
    scrollToSearchResult();
}

function updateSearchUI() {
    const countEl = document.getElementById('search-results-count');
    const prevBtn = document.getElementById('search-prev');
    const nextBtn = document.getElementById('search-next');
    
    if (searchResults.length === 0) {
        const query = document.getElementById('search-input').value.trim();
        countEl.textContent = query ? 'No results' : '';
        prevBtn.disabled = true;
        nextBtn.disabled = true;
    } else {
        countEl.textContent = (currentSearchIndex + 1) + ' / ' + searchResults.length;
        prevBtn.disabled = false;
        nextBtn.disabled = false;
    }
}

// ==================== GLOBAL SEARCH ====================

var globalSearchTimeout = null;
var globalSearchActive = false;

function toggleGlobalSearch() {
    const searchBar = document.getElementById('global-search-bar');
    const searchResults = document.getElementById('global-search-results');
    const chatsContainer = document.getElementById('chats-container');
    
    if (searchBar.classList.contains('hidden')) {
        // Open search
        searchBar.classList.remove('hidden');
        document.getElementById('global-search-input').focus();
        globalSearchActive = true;
    } else {
        // Close search
        clearGlobalSearch();
    }
}

function clearGlobalSearch() {
    document.getElementById('global-search-bar').classList.add('hidden');
    document.getElementById('global-search-results').classList.add('hidden');
    document.getElementById('global-search-input').value = '';
    document.getElementById('chats-container').classList.remove('hidden');
    globalSearchActive = false;
}

function handleGlobalSearchInput(event) {
    const query = event.target.value.trim();
    
    // Debounce
    if (globalSearchTimeout) {
        clearTimeout(globalSearchTimeout);
    }
    
    if (query.length < 2) {
        document.getElementById('global-search-results').classList.add('hidden');
        document.getElementById('chats-container').classList.remove('hidden');
        return;
    }
    
    globalSearchTimeout = setTimeout(function() {
        performGlobalSearch(query);
    }, 300);
}

async function performGlobalSearch(query) {
    const resultsEl = document.getElementById('global-search-results');
    const chatsContainer = document.getElementById('chats-container');
    const exactMatch = document.getElementById('global-search-exact').checked;
    
    resultsEl.innerHTML = '<div class="search-loading">Searching...</div>';
    resultsEl.classList.remove('hidden');
    chatsContainer.classList.add('hidden');
    
    try {
        let url = '/messages/search?q=' + encodeURIComponent(query);
        if (exactMatch) {
            url += '&exact=true';
        }
        const response = await api(url);
        
        if (response.ok) {
            const data = await response.json();
            renderGlobalSearchResults(data.chats || [], query);
        } else {
            resultsEl.innerHTML = '<div class="search-error">Search failed</div>';
        }
    } catch (e) {
        console.error('Global search error:', e);
        resultsEl.innerHTML = '<div class="search-error">Search failed</div>';
    }
}

function renderGlobalSearchResults(chats, query) {
    const resultsEl = document.getElementById('global-search-results');
    
    if (chats.length === 0) {
        resultsEl.innerHTML = '<div class="search-empty">No results for "' + escapeHtml(query) + '"</div>';
        return;
    }
    
    resultsEl.innerHTML = chats.map(function(chat) {
        const isGroup = chat.type === 'group';
        const icon = isGroup ? (chat.isChannel ? '📢' : '👥') : '👤';
        const chatKey = isGroup ? 'group_' + chat.chat_id : chat.chat_id;
        
        // Highlight query in preview
        let preview = escapeHtml(chat.last_match_preview || '');
        if (preview && query) {
            const regex = new RegExp('(' + escapeRegex(escapeHtml(query)) + ')', 'gi');
            preview = preview.replace(regex, '<mark>$1</mark>');
        }
        
        return '<div class="global-search-item" onclick="openSearchResult(\'' + escapeHtml(chatKey) + '\', \'' + escapeHtml(query) + '\')">' +
            '<div class="global-search-icon">' + icon + '</div>' +
            '<div class="global-search-info">' +
                '<div class="global-search-name">' + escapeHtml(chat.name) + '</div>' +
                '<div class="global-search-preview">' + preview + '</div>' +
                '<div class="global-search-count">' + chat.match_count + ' match' + (chat.match_count > 1 ? 'es' : '') + '</div>' +
            '</div>' +
        '</div>';
    }).join('');
}

function openSearchResult(chatKey, query) {
    clearGlobalSearch();
    
    // Open the chat
    if (chatKey.startsWith('group_')) {
        const groupId = chatKey.replace('group_', '');
        openGroupChat(groupId);
    } else {
        openChat(chatKey);
    }
    
    // After chat opens, trigger local search with the query
    setTimeout(function() {
        openSearch();
        document.getElementById('search-input').value = query;
        performSearch();
    }, 500);
}

function addMessageToUI(message) {
    if (!state.currentChatId || !state.chats[state.currentChatId]) return;
    const chat = state.chats[state.currentChatId];
    if (chat.messages.find(m => m.id === message.id)) return;
    chat.messages.push(message);
    chat.lastMessage = message;
    saveChats();
    renderMessages();
}

function updateMessageStatus(messageId, status) {
    // Search in all chats for the message (by id or client_message_id)
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        
        const message = chat.messages.find(m => m.id === messageId || m.client_message_id === messageId);
        if (message) {
            message.status = status;
            saveChats();
            if (state.currentChatId === chatId) {
                renderMessages();
            }
            return;
        }
    }
}

// v3.7.1: Find message by client_message_id
function findMessageByClientId(clientMessageId) {
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        const msg = chat.messages.find(m => m.id === clientMessageId || m.client_message_id === clientMessageId);
        if (msg) return msg;
    }
    return null;
}

// v3.7.1: Handle own message received from another device
async function handleOwnMessageFromOtherDevice(msgData) {
    console.log('[Multi-device] === handleOwnMessageFromOtherDevice START ===');
    console.log('[Multi-device] Message ID:', msgData.id);
    console.log('[Multi-device] Recipient ID:', msgData.recipient_id);
    console.log('[Multi-device] Group ID:', msgData.group_id);
    console.log('[Multi-device] Has encrypted_for_self:', !!msgData.encrypted_for_self);
    console.log('[Multi-device] E2EE ready:', state.e2eeReady);
    
    // Determine chat ID
    let chatId = msgData.group_id ? 'group_' + msgData.group_id : msgData.recipient_id;
    console.log('[Multi-device] Resolved chatId:', chatId);
    
    // v3.7.3: Create chat if it doesn't exist on this device
    let chat = state.chats[chatId];
    if (!chat) {
        console.log('[Multi-device] Chat not found, creating:', chatId);
        // Create minimal chat entry - will be populated when user opens it
        if (msgData.group_id) {
            // For group chats, create with group flag
            state.chats[chatId] = {
                id: msgData.group_id,
                isGroup: true,
                displayName: 'Group Chat',
                messages: [],
                unreadCount: 0
            };
        } else {
            // For direct chats, create with recipient ID
            state.chats[chatId] = {
                id: msgData.recipient_id,
                username: msgData.recipient_id,
                displayName: msgData.recipient_id,
                messages: [],
                unreadCount: 0
            };
            // Fetch recipient info in background
            fetchUserInfoAsync(msgData.recipient_id);
        }
        chat = state.chats[chatId];
        console.log('[Multi-device] Chat created successfully');
    } else {
        console.log('[Multi-device] Chat already exists');
    }
    
    // Check if message already exists
    if (chat.messages && chat.messages.find(m => m.id === msgData.id)) {
        console.log('[Multi-device] Message already exists, skipping:', msgData.id);
        return;
    }
    
    // Decrypt encrypted_for_self
    let text = '🔒 Encrypted message (key expired)';
    let fileInfo = null;
    
    if (msgData.encrypted_for_self && state.e2eeReady) {
        console.log('[Multi-device] Attempting decryptForSelf...');
        try {
            const decrypted = await VibeCrypto.decryptForSelf(msgData.encrypted_for_self);
            console.log('[Multi-device] decryptForSelf result:', decrypted ? 'success' : 'null');
            if (decrypted) {
                // Check if it's file info
                if (msgData.message_type === 'file' || msgData.message_type === 'FILE' ||
                    msgData.message_type === 'voice' || msgData.message_type === 'VOICE') {
                    try {
                        fileInfo = JSON.parse(decrypted);
                        text = msgData.message_type === 'voice' || msgData.message_type === 'VOICE' 
                            ? '🎤 Voice message' 
                            : '📎 ' + (fileInfo.filename || 'File');
                    } catch {
                        text = decrypted;
                    }
                } else {
                    text = decrypted;
                }
                // Cache decrypted message
                await offlineDB.saveDecryptedMessage(msgData.id, chatId, text, fileInfo);
                console.log('[Multi-device] Message decrypted and cached');
            }
        } catch (e) {
            console.warn('[Multi-device] Failed to decrypt:', e);
            console.warn('[Multi-device] This likely means different identity keys on devices');
        }
    } else {
        console.log('[Multi-device] Skipping decryption - encrypted_for_self:', !!msgData.encrypted_for_self, 'e2eeReady:', state.e2eeReady);
    }
    
    // Add message to UI
    const message = {
        id: msgData.id,
        text: text,
        file: fileInfo,
        sender_id: msgData.sender_id,
        recipient_id: msgData.recipient_id,
        group_id: msgData.group_id,
        created_at: msgData.created_at,
        status: msgData.status,
        message_type: msgData.message_type,
        is_pinned: msgData.is_pinned,
        reply_to_id: msgData.reply_to_id,
        mentions: msgData.mentions,
        expires_at: msgData.expires_at,  // КАО#291: was dropped here, so a disappearing message synced to the sender's OTHER device never expired locally (cleanupExpiredMessages/render filter key off expires_at). Mirrors handleNewMessage.
        // КАО#313: forward attribution was dropped too — on the sender's other device a forwarded message
        // rendered as an ordinary one, losing the "Forwarded from X" header that handleNewMessage sets.
        forwarded_from_id: msgData.forwarded_from_id,
        forwarded_from_name: msgData.forwarded_from_name,
    };

    if (!chat.messages) chat.messages = [];
    chat.messages.push(message);
    console.log('[Multi-device] Message added to chat. Total messages:', chat.messages.length);
    
    // Update UI if this chat is active
    if (state.currentChatId === chatId) {
        console.log('[Multi-device] This is the active chat, rendering messages');
        renderMessages();
        scrollToBottom();
    } else {
        console.log('[Multi-device] Not the active chat. Current:', state.currentChatId, 'Message chat:', chatId);
    }
    
    // Update chat list and save
    renderChatsList();
    saveChats();
    console.log('[Multi-device] === handleOwnMessageFromOtherDevice END ===');
}

// v3.7.3: Fetch user info in background and update chat
async function fetchUserInfoAsync(userId) {
    try {
        const response = await api('/auth/user/id/' + userId);
        if (response.ok) {
            const userData = await response.json();
            if (state.chats[userId]) {
                state.chats[userId].username = userData.username;
                state.chats[userId].displayName = userData.display_name || userData.username;
                state.chats[userId].avatar_url = userData.avatar_url || null;
                // Update UI if this chat is currently visible
                if (state.currentChatId === userId) {
                    const chatNameEl = document.getElementById('chat-name');
                    if (chatNameEl) {
                        chatNameEl.textContent = state.chats[userId].displayName;
                    }
                    updateChatHeaderAvatar(state.chats[userId]);
                }
                renderChatsList();
                saveChats();
            }
        }
    } catch (e) {
        console.log('[Multi-device] Failed to fetch user info:', e);
    }
}

// Update message with server ID after successful send
function updateMessageWithServerId(clientMessageId, serverId, status, expiresAt) {
    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;
        
        const message = chat.messages.find(m => m.id === clientMessageId || m.client_message_id === clientMessageId);
        if (message) {
            // Save client_message_id and update id to server id
            message.client_message_id = clientMessageId;
            message.id = serverId;
            message.status = status;
            if (expiresAt) {
                message.expires_at = expiresAt;
            }
            
            // Check for pending status updates
            if (state.pendingStatusUpdates[serverId]) {
                const pending = state.pendingStatusUpdates[serverId];
                const statusPriority = { pending: 0, sent: 1, delivered: 2, read: 3 };
                if (statusPriority[pending.status] > statusPriority[message.status]) {
                    console.log('Applying pending status update:', serverId, '->', pending.status);
                    message.status = pending.status;
                }
                delete state.pendingStatusUpdates[serverId];
            }
            
            saveChats();
            if (state.currentChatId === chatId) {
                renderMessages();
            }
            return;
        }
    }
}

// ==================== NEW CHAT/GROUP MENU ====================

function showNewMenu() {
    const menu = document.getElementById('new-menu');
    menu.classList.remove('hidden');
    
    // Add overlay to close menu when clicking outside
    const overlay = document.createElement('div');
    overlay.className = 'dropdown-overlay';
    overlay.onclick = hideNewMenu;
    overlay.id = 'new-menu-overlay';
    document.body.appendChild(overlay);
}

function hideNewMenu() {
    document.getElementById('new-menu').classList.add('hidden');
    const overlay = document.getElementById('new-menu-overlay');
    if (overlay) overlay.remove();
}

function showNewChatModal() {
    hideNewMenu();
    document.getElementById('new-chat-modal').classList.remove('hidden');
    document.getElementById('new-chat-username').value = '';
    document.getElementById('new-chat-username').focus();
}

function hideNewChatModal() {
    document.getElementById('new-chat-modal').classList.add('hidden');
    document.getElementById('new-chat-username').value = '';
}

function showNewGroupModal() {
    hideNewMenu();
    document.getElementById('new-group-modal').classList.remove('hidden');
    document.getElementById('new-group-name').value = '';
    loadContactsForGroup();
    document.getElementById('new-group-name').focus();
}

// ==================== CHANNELS (v3.11.10) ====================

function isPostingRole(role) {
    return role === 'owner' || role === 'admin';
}

function showNewChannelModal() {
    document.getElementById('new-channel-modal').classList.remove('hidden');
    document.getElementById('new-channel-name').value = '';
    document.getElementById('new-channel-desc').value = '';
    document.getElementById('new-channel-name').focus();
    // Close the new-menu dropdown
    const newMenu = document.getElementById('new-menu');
    if (newMenu) newMenu.classList.add('hidden');
}

function hideNewChannelModal() {
    document.getElementById('new-channel-modal').classList.add('hidden');
}

async function createChannel() {
    const nameInput = document.getElementById('new-channel-name');
    const descInput = document.getElementById('new-channel-desc');
    const name = nameInput.value.trim();
    const description = descInput.value.trim() || null;

    if (!name) {
        alert('Please enter a channel name');
        return;
    }

    try {
        const response = await api('/groups', {
            method: 'POST',
            body: JSON.stringify({
                name: name,
                description: description,
                member_ids: [],
                is_channel: true
            })
        });

        if (response.ok) {
            const channel = await response.json();
            const chatId = 'group_' + channel.id;
            state.chats[chatId] = {
                id: channel.id,
                isGroup: true,
                isChannel: true,
                name: channel.name,
                displayName: channel.name,
                description: channel.description,
                created_by: channel.created_by,
                myRole: 'owner',
                members: channel.members || [],
                messages: [],
                unreadCount: 0,
                missedCalls: 0,
                avatar_url: channel.avatar_url
            };
            saveChats();
            hideNewChannelModal();
            openGroupChat(channel.id);
            renderChatsList();
        } else {
            const err = await response.json();
            alert(err.detail || 'Failed to create channel');
        }
    } catch (e) {
        console.error('Create channel error:', e);
        alert('Failed to create channel');
    }
}

function hideNewGroupModal() {
    document.getElementById('new-group-modal').classList.add('hidden');
    document.getElementById('new-group-name').value = '';
}

// ==================== UNIVERSAL DIALOGS ====================

/**
 * Show custom confirm dialog (replaces browser confirm)
 * @param {string} message - Message to display
 * @param {string} title - Dialog title (optional)
 * @param {string} okText - OK button text (default: "OK")
 * @param {string} cancelText - Cancel button text (default: "Cancel")
 * @returns {Promise<boolean>} - Resolves to true if OK clicked, false if Cancel
 */
function showConfirm(message, title = 'Confirm', okText = 'OK', cancelText = 'Cancel') {
    return new Promise((resolve) => {
        const modal = document.getElementById('universal-confirm-modal');
        const titleEl = document.getElementById('confirm-title');
        const messageEl = document.getElementById('confirm-message');
        const okBtn = document.getElementById('confirm-ok-btn');
        const cancelBtn = document.getElementById('confirm-cancel-btn');
        
        // Set content
        titleEl.textContent = title;
        messageEl.textContent = message;
        okBtn.textContent = okText;
        cancelBtn.textContent = cancelText;
        
        // Show modal
        modal.classList.remove('hidden');
        
        // Event handlers
        const handleOk = () => {
            cleanup();
            resolve(true);
        };
        
        const handleCancel = () => {
            cleanup();
            resolve(false);
        };
        
        const cleanup = () => {
            modal.classList.add('hidden');
            okBtn.removeEventListener('click', handleOk);
            cancelBtn.removeEventListener('click', handleCancel);
        };
        
        // Attach listeners
        okBtn.addEventListener('click', handleOk);
        cancelBtn.addEventListener('click', handleCancel);
        
        // Focus OK button
        setTimeout(() => cancelBtn.focus(), 100);
    });
}

/**
 * Show custom alert dialog (replaces browser alert)
 * @param {string} message - Message to display
 * @param {string} title - Dialog title (optional)
 * @param {string} icon - Icon to display (optional, default: ℹ️)
 * @returns {Promise<void>} - Resolves when OK clicked
 */
function showAlert(message, title = 'Notice', icon = 'ℹ️') {
    return new Promise((resolve) => {
        const modal = document.getElementById('universal-alert-modal');
        const titleEl = document.getElementById('alert-title');
        const messageEl = document.getElementById('alert-message');
        const iconEl = document.getElementById('alert-icon');
        const okBtn = document.getElementById('alert-ok-btn');
        
        // Set content
        titleEl.textContent = title;
        messageEl.textContent = message;
        iconEl.textContent = icon;
        
        // Show modal
        modal.classList.remove('hidden');
        
        // Event handler
        const handleOk = () => {
            cleanup();
            resolve();
        };
        
        const cleanup = () => {
            modal.classList.add('hidden');
            okBtn.removeEventListener('click', handleOk);
        };
        
        // Attach listener
        okBtn.addEventListener('click', handleOk);
        
        // Focus OK button
        setTimeout(() => okBtn.focus(), 100);
    });
}

// ==================== END UNIVERSAL DIALOGS ====================


function loadContactsForGroup() {
    const listEl = document.getElementById('group-members-list');
    const contacts = Object.keys(state.chats).filter(id => !state.chats[id].isGroup);
    
    if (contacts.length === 0) {
        listEl.innerHTML = '<p style="padding: 12px; color: #666;">No contacts yet</p>';
        return;
    }
    
    listEl.innerHTML = contacts.map(id => {
        const chat = state.chats[id];
        const name = escapeHtml(chat.displayName || chat.username || id);
        return '<div class="group-member-item" data-name="' + name.toLowerCase() + '" style="display: flex; flex-direction: row; align-items: center; padding: 10px 12px; cursor: pointer; gap: 12px;" onclick="this.querySelector(\'input\').checked = !this.querySelector(\'input\').checked">' +
            '<input type="checkbox" style="width: 20px; height: 20px; margin: 0; flex-shrink: 0;" class="member-checkbox" value="' + escapeHtml(id) + '" onclick="event.stopPropagation()">' +
            '<span style="flex: 1; color: #333; font-size: 16px;">' + name + '</span>' +
            '</div>';
    }).join('');
}

// v3.7.28: Filter group members list by search input
function filterGroupMembersList() {
    const searchInput = document.getElementById('group-members-search');
    const filter = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const items = document.querySelectorAll('#group-members-list .group-member-item');
    
    items.forEach(item => {
        const name = item.getAttribute('data-name') || '';
        if (filter === '' || name.includes(filter)) {
            item.style.display = 'flex';
        } else {
            item.style.display = 'none';
        }
    });
}

async function createGroup() {
    const name = document.getElementById('new-group-name').value.trim();
    if (!name) {
        await showAlert('Please enter a group name', 'Error', '⚠️');
        return;
    }
    
    const checkboxes = document.querySelectorAll('#group-members-list .member-checkbox:checked');
    const memberIds = Array.from(checkboxes).map(cb => cb.value);
    
    if (memberIds.length === 0) {
        await showAlert('Please select at least one member', 'Error', '⚠️');
        return;
    }

    // КАО#125: prevent double-submit (duplicate group creation on rapid clicks)
    if (state._creatingGroup) return;
    state._creatingGroup = true;
    try {
        const response = await api('/groups', {
            method: 'POST',
            body: JSON.stringify({
                name: name,
                member_ids: memberIds,
            }),
        });
        
        if (response.ok) {
            const group = await response.json();
            
            // Add group to chats
            state.chats['group_' + group.id] = {
                id: group.id,
                isGroup: true,
                name: group.name,
                displayName: group.name,
                created_by: group.created_by,
                members: group.members,
                messages: [],
                unreadCount: 0,
            };
            
            saveChats();
            renderChatsList();
            hideNewGroupModal();
            
            // Open the group
            openGroupChat(group.id);
        } else {
            const data = await response.json();
            await showAlert(data.detail || 'Failed to create group', 'Error', '❌');
        }
    } catch (e) {
        console.error('Create group error:', e);
        await showAlert('Failed to create group', 'Error', '❌');
    } finally {
        state._creatingGroup = false;  // КАО#125
    }
}

async function openGroupChat(groupId) {
    // v3.8.57: Hide identity key changed banner from previous chat
    hideIdentityKeyChangedBanner();
    
    // Load group info if not cached
    const chatKey = 'group_' + groupId;
    
    if (!state.chats[chatKey]) {
        try {
            const response = await api('/groups/' + groupId);
            if (response.ok) {
                const group = await response.json();
                state.chats[chatKey] = {
                    id: group.id,
                    isGroup: true,
                    name: group.name,
                    displayName: group.name,
                    avatar_url: group.avatar_url || null,
                    created_by: group.created_by,
                    members: group.members,
                    messages: [],
                    unreadCount: 0,
                };
            }
        } catch (e) {
            console.error('Failed to load group:', e);
            return;
        }
    }
    
    state.currentChatId = chatKey;
    state.currentChat = state.chats[chatKey];
    
    // Update UI
    document.getElementById('chat-name').textContent = state.currentChat.name;
    // Member count will be updated by loadGroupMembers
    document.getElementById('chat-status').textContent = 'Loading...';
    
    // Update avatar in header
    updateChatHeaderAvatar(state.currentChat);
    
    // Update E2EE indicator
    updateE2EEIndicator();
    
    // Reset unread
    state.chats[chatKey].unreadCount = 0;
    saveChats();
    
    // Load messages
    await loadGroupMessages(groupId);
    
    showScreen('chat');
    // КАО#343: refresh the pinned bar for THIS chat. openChat() does it, openGroupChat() did not, so the
    // bar kept rendering the pinned message of the previously-open 1:1 chat while a group was on screen.
    if (typeof renderPinnedMessages === 'function') renderPinnedMessages();
    if (typeof loadPinnedMessages === 'function') loadPinnedMessages();
    loadGroupMembers(groupId);
    renderMessages();
    renderChatsList();
    // v3.11.10: Update UI for channel-specific behavior
    updateChannelUI(state.chats[state.currentChatId]);
    setupGroupMenuForChat();
    
    // Re-init mentions for group chat
    initMentions();
    
    // Init pull to refresh for messages
    setTimeout(() => {
        initMessagesPullToRefresh();
        scrollToBottom();
    }, 100);
}

async function loadGroupMessages(groupId) {
    try {
        const response = await api('/groups/' + groupId + '/messages?limit=50');
        if (response.ok) {
            const messages = await response.json();
            const chatKey = 'group_' + groupId;
            
            if (!state.chats[chatKey]) return;
            
            // v3.7.2: Batch load cached messages for performance
            const messageIds = messages.map(m => m.id);
            const cachedMessages = await offlineDB.getDecryptedMessages(messageIds);
            
            const decryptedMessages = [];
            for (const msg of messages) {
                let text;
                let fileInfo = null;
                let decrypted = null;
                let fromCache = false;
                
                // Check decrypted messages cache first (from batch load)
                const cached = cachedMessages.get(msg.id);
                if (cached) {
                    text = cached.text;
                    fileInfo = cached.file_info;
                    fromCache = true;
                }
                
                // Try E2EE decryption if not cached
                // v3.7.1: For our own group messages, try to decrypt encrypted_for_self
                const isOurMessage = String(msg.sender_id) === String(state.user.id);
                if (!fromCache && isOurMessage && state.e2eeReady && msg.encrypted_for_self) {
                    try {
                        decrypted = await VibeCrypto.decryptForSelf(msg.encrypted_for_self);
                        if (decrypted) {
                            // КАО#090 Round-2: own file/voice store fileInfo JSON in encrypted_for_self —
                            // parse it back so the attachment (+ at-rest fileKey) isn't lost on reload.
                            let selfFileInfo = null;
                            if ((msg.message_type === 'file' || msg.message_type === 'voice' || msg.file_id) && decrypted.startsWith('{')) {
                                try {
                                    const fi = JSON.parse(decrypted);
                                    if (fi && fi.file_id) { selfFileInfo = fi; regFileKey(fi); decrypted = fi.is_voice ? '🎤 Voice message' : ('📎 ' + (fi.filename || 'File')); }
                                } catch (e) {}
                            }
                            offlineDB.saveDecryptedMessage(msg.id, "group_" + groupId, decrypted, selfFileInfo);
                            if (selfFileInfo) msg.file = selfFileInfo;
                            // КАО#364: assign the LOCALS too. This branch wrote the plaintext to the cache and
                            // set fromCache = true, which then skips the `if (!fromCache)` block below that is
                            // the only other place `text` is assigned — so the message was pushed with
                            // `text: undefined, file: null` and rendered as an empty bubble with no attachment,
                            // even though decryption had SUCCEEDED. `msg.file` at the line above mutates the raw
                            // server object, which is never used to build the pushed message. Worse, undefined
                            // is not the failure placeholder, so the merge guard did not catch it and the
                            // undefined overwrote a readable local copy, which saveChats() then persisted.
                            text = decrypted;
                            if (selfFileInfo) fileInfo = selfFileInfo;
                            fromCache = true;
                        }
                    } catch (e) {
                        console.warn("[E2EE] Failed to decrypt own group message:", e);
                    }
                }

                if (!fromCache && state.e2eeReady && msg.encrypted_payload) {
                    try {
                        const firstBytes = atob(msg.encrypted_payload.slice(0, 20));
                        if (firstBytes.startsWith('{"v":')) {
                            decrypted = await VibeCrypto.decryptGroupMessage(groupId, msg.sender_id, msg.encrypted_payload);
                            // Cache the decrypted message
                            if (decrypted) {
                                let cacheText = decrypted;
                                let cacheFileInfo = null;
                                if (msg.message_type === 'FILE' || msg.message_type === 'file' || 
                                    msg.message_type === 'voice' || msg.message_type === 'VOICE' ||
                                    (decrypted.startsWith('{') && !decrypted.startsWith('{"v":'))) {
                                    try {
                                        cacheFileInfo = JSON.parse(decrypted);
                                        if (msg.message_type === 'voice' || msg.message_type === 'VOICE' || cacheFileInfo.is_voice) {
                                            cacheText = '🎤 Voice message';
                                        } else {
                                            cacheText = '📎 ' + (cacheFileInfo.filename || 'File');
                                        }
                                    } catch {}
                                }
                                offlineDB.saveDecryptedMessage(msg.id, chatKey, cacheText, cacheFileInfo);
                            }
                        }
                    } catch (e) {
                        console.log('[E2EE] Group history decryption failed for msg', msg.id);
                    }
                }
                
                // Legacy decoding fallback (only if not from cache)
                if (!fromCache) {
                    try {
                        if (!decrypted) {
                            decrypted = decodeURIComponent(escape(atob(msg.encrypted_payload)));
                            // Check if this is an undecrypted E2EE payload
                            if (decrypted.startsWith('{"v":')) {
                                decrypted = null; // Mark as failed E2EE
                            }
                        }
                        
                        // Handle decryption failure
                        if (!decrypted) {
                            text = '🔒 Encrypted message (key expired)';
                        }
                        // Parse file info if applicable
                        else if (msg.message_type === 'FILE' || msg.message_type === 'file' || 
                            msg.message_type === 'voice' || msg.message_type === 'VOICE' ||
                            (typeof decrypted === 'string' && decrypted.startsWith('{') && !decrypted.startsWith('{"v":'))) {
                            try {
                                fileInfo = JSON.parse(decrypted);
                                if (msg.message_type === 'voice' || msg.message_type === 'VOICE' || fileInfo.is_voice) {
                                    text = '🎤 Voice message';
                                    fileInfo.is_voice = true;
                                } else {
                                    text = '📎 ' + (fileInfo.filename || 'File');
                                }
                            } catch {
                                text = decrypted;
                            }
                        } else {
                            text = decrypted;
                        }
                    } catch (e) {
                        try {
                            text = atob(msg.encrypted_payload);
                        } catch {
                            text = '[Unable to decrypt]';
                        }
                    }
                }
                
                decryptedMessages.push({
                    id: msg.id,
                    // КАО#365: the server returns this (groups.py) but the loader dropped it, so an
                    // optimistic message still carrying its 'msg_<ts>' id could never be collapsed.
                    client_message_id: msg.client_message_id,
                    text: text,
                    file: fileInfo,
                    sender_id: msg.sender_id,
                    sender_name: msg.sender_name,
                    created_at: msg.created_at,
                    status: msg.status,
                    group_id: msg.group_id,
                    reply_to_id: msg.reply_to_id,
                    forwarded_from_id: msg.forwarded_from_id,
                    forwarded_from_name: msg.forwarded_from_name,
                    reactions: msg.reactions || [],
                    mentions: msg.mentions || [],
                    // КАО#312: expires_at was dropped here while this loader REPLACES chat.messages
                    // wholesale and saveChats() persists the result — so opening a group chat erased the
                    // expiry of every disappearing message (set correctly by handleNewMessage /
                    // handleOwnMessageFromOtherDevice), and cleanupExpiredMessages then skipped them
                    // forever (`if (!msg.expires_at) return true`). The plaintext survived in
                    // localStorage + IndexedDB indefinitely. Carry the same fields loadChatHistory keeps.
                    expires_at: msg.expires_at,
                    is_pinned: msg.is_pinned,
                    edited_at: msg.edited_at,
                    is_edited: !!msg.edited_at,
                    // v3.11.10: Set E2EE flag for group messages
                    e2ee: fromCache || (decrypted !== null),
                });
            }
            
            // КАО#341: MERGE, never replace. This endpoint returns only the newest page (limit 50), and
            // assigning it over chat.messages destroyed every older group message this device still held
            // locally — permanently, because saveChats() then wrote the truncated array to localStorage and
            // the server cannot re-supply what the client decrypted once (decrypt-once ratchet).
            // КАО#363 (critical): the merge used to be a bare `{ ...prev, ...m }`, so EVERY field of the
            // freshly-fetched object won — including a `text` that is the decrypt-FAILURE placeholder and a
            // `file` of null. A group sender key is a decrypt-once ratchet and own messages have no entry in
            // memberKeys at all, so re-opening a group after the IndexedDB plaintext cache expired produced
            // '🔒 Encrypted message (key expired)' / '[Unable to decrypt]' and that overwrote text this device
            // still held in readable form — then saveChats() persisted the loss and nothing can re-supply it.
            // Nulling `file` was worse: fileInfo.fileKey is the ONLY copy of the at-rest AES key, so the
            // attachment became permanently undecryptable here. loadChatHistory has guarded against exactly
            // this since v3.9.2 (app.js:7479-7494); the group path never did.
            // КАО#365 (minor): key the lookup on client_message_id too. An optimistic send whose response was
            // never processed keeps its 'msg_<ts>' id, so the server row was appended as a SECOND copy and the
            // stuck ⏳ duplicate survived every later open. Must land WITH #363, never before it — collapsing
            // an optimistic (readable) message onto an undecryptable server row without the guard above would
            // destroy the very text this is meant to protect.
            {
                const existing = state.chats[chatKey].messages || [];
                const byId = new Map(existing.map(m => [m.id, m]));
                const isFailureText = (t) => t === '🔒 Encrypted message (key expired)' ||
                                             (typeof t === 'string' && t.startsWith('[Unable to decrypt'));
                const isReadableText = (t) => !!t && !t.startsWith('🔒') && !t.startsWith('[Unable to decrypt');
                for (const m of decryptedMessages) {
                    const prev = byId.get(m.id) ||
                                 (m.client_message_id ? byId.get(m.client_message_id) : undefined);
                    if (!prev) { byId.set(m.id, m); continue; }
                    if (prev.id !== m.id) byId.delete(prev.id);   // drop the stale optimistic key (#365)
                    const merged = { ...prev, ...m };
                    if (isFailureText(m.text) && isReadableText(prev.text)) {
                        merged.text = prev.text;
                        merged.e2ee = prev.e2ee;
                    }
                    if (!m.file && prev.file) merged.file = prev.file;   // never null out an attachment
                    byId.set(m.id, merged);
                }
                // КАО#376: reconcile deletions inside the window the server just described.
                // The КАО#341 merge is purely additive, and the wholesale assignment it replaced had been
                // acting as the de-facto reconciliation for the newest page. `send_to_user` DROPS the
                // message_deleted event when the member has no open socket and nothing replays it on
                // reconnect (/pending returns messages only), so a "delete for everyone" that happened while
                // this device was offline was never learned about: the server omits the row, the additive
                // merge keeps the local copy, and saveChats() re-persists it — the retracted message stays
                // visible on that device for ever.
                // Scope is everything here. Prune ONLY at or after the oldest message the server returned:
                // that is the region it spoke about authoritatively. Anything older is the very history
                // КАО#341 exists to protect, and an empty page carries no window at all.
                if (decryptedMessages.length) {
                    const serverIds = new Set(decryptedMessages.map(m => m.id));
                    const times = decryptedMessages
                        .map(m => new Date(m.created_at || 0).getTime())
                        .filter(t => Number.isFinite(t));
                    const windowStart = times.length ? Math.min.apply(null, times) : null;
                    if (windowStart !== null) {
                        for (const [id, m] of Array.from(byId)) {
                            if (serverIds.has(id)) continue;
                            if (String(id).startsWith('msg_') || String(id).startsWith('call_')) continue;  // never reached the server yet
                            if (m.status === 'sending' || m.status === 'queued' || m.status === 'failed') continue;
                            if (new Date(m.created_at || 0).getTime() >= windowStart) byId.delete(id);
                        }
                    }
                }

                state.chats[chatKey].messages = Array.from(byId.values())
                    .sort((x, y) => new Date(x.created_at || 0) - new Date(y.created_at || 0));
            }
            
            saveChats();
            if (state.currentChatId === chatKey) {
                renderMessages();
            }
        }
    } catch (e) {
        console.error('Failed to load group messages:', e);
    }
}

async function loadMyGroups() {
    try {
        const response = await api('/groups');
        if (response.ok) {
            const groups = await response.json();
            
            // Get deleted chats list
            const deletedKey = state.user ? 'deletedChats_' + state.user.id : 'deletedChats';
            const deletedChats = JSON.parse(localStorage.getItem(deletedKey) || '{}');
            
            for (const group of groups) {
                const chatKey = 'group_' + group.id;
                
                // Skip if locally deleted
                if (deletedChats[chatKey]) {
                    continue;
                }
                
                if (!state.chats[chatKey]) {
                    state.chats[chatKey] = {
                        id: group.id,
                        isGroup: true,
                        name: group.name,
                        displayName: group.name,
                        avatar_url: group.avatar_url || null,
                        messages: [],
                        unreadCount: group.unread_count || 0,
                    };
                } else {
                    state.chats[chatKey].unreadCount = group.unread_count || 0;
                    state.chats[chatKey].name = group.name;
                    state.chats[chatKey].displayName = group.name;
                    // Update avatar_url only if server returned a value
                    if (group.avatar_url) {
                        state.chats[chatKey].avatar_url = group.avatar_url;
                    }
                }
            }
            
            saveChats();
            renderChatsList();
        }
    } catch (e) {
        console.error('Failed to load groups:', e);
    }
}

// ==================== GROUP INVITES ====================

var pendingInvites = [];

async function loadPendingInvites() {
    try {
        const response = await api('/groups/invites/pending');
        if (response.ok) {
            pendingInvites = await response.json();
        } else {
            pendingInvites = [];
        }
    } catch (e) {
        console.error('Failed to load invites:', e);
        pendingInvites = [];
    }
    updateInvitesBadge();
}

function updateInvitesBadge() {
    const badge = document.getElementById('invites-badge');
    const icon = document.getElementById('invites-icon');
    console.log('updateInvitesBadge called, pendingInvites:', pendingInvites.length);
    if (!badge) {
        console.log('Badge element not found');
        return;
    }
    
    if (pendingInvites.length > 0) {
        badge.textContent = pendingInvites.length;
        badge.classList.remove('hidden');
        if (icon) icon.textContent = '📬';  // Mailbox with mail (has invites)
        console.log('Badge shown, icon set to mailbox with mail');
    } else {
        badge.textContent = '';
        badge.classList.add('hidden');
        if (icon) icon.textContent = '📭';  // Empty mailbox (no invites)
        console.log('Badge hidden, icon set to empty mailbox');
    }
}

function showInvitesModal() {
    renderInvitesList();
    document.getElementById('invites-modal').classList.remove('hidden');
}

function hideInvitesModal() {
    document.getElementById('invites-modal').classList.add('hidden');
}

function renderInvitesList() {
    const listEl = document.getElementById('invites-list');
    
    console.log('Rendering invites list:', pendingInvites);
    
    if (pendingInvites.length === 0) {
        listEl.innerHTML = '<p class="empty-invites">No pending invitations</p>';
        return;
    }
    
    listEl.innerHTML = pendingInvites.map(invite => {
        console.log('Invite item:', invite);
        return '<div class="invite-item">' +
            '<div class="invite-info">' +
                '<div class="invite-group-name">' + escapeHtml(invite.group_name) + '</div>' +
                '<div class="invite-from">Invited by ' + escapeHtml(invite.inviter_name) + '</div>' +
            '</div>' +
            '<div class="invite-actions">' +
                '<button class="btn decline" onclick="respondToInvite(\'' + escapeHtml(invite.id) + '\', \'decline\')">Decline</button>' +
                '<button class="btn accept" onclick="respondToInvite(\'' + escapeHtml(invite.id) + '\', \'accept\')">Accept</button>' +
            '</div>' +
        '</div>';
    }).join('');
}

async function respondToInvite(inviteId, action) {
    console.log('Responding to invite:', inviteId, action);
    try {
        const response = await api('/groups/invites/' + inviteId + '/respond', {
            method: 'POST',
            body: JSON.stringify({ action: action }),
        });
        
        console.log('Response status:', response.status);
        
        if (response.ok) {
            const result = await response.json();
            console.log('Response result:', result);
            
            // Remove from pending list
            pendingInvites = pendingInvites.filter(inv => inv.id !== inviteId);
            updateInvitesBadge();
            renderInvitesList();
            
            if (action === 'accept' && result.group_id) {
                // Load the group and open it
                hideInvitesModal();
                await loadMyGroups();
                openGroupChat(result.group_id);
            }
        } else {
            let errorMsg = 'Failed to respond to invite';
            try {
                const data = await response.json();
                console.error('Error response:', data);
                errorMsg = data.detail || errorMsg;
            } catch (e) {
                console.error('Could not parse error response');
            }
            alert(errorMsg + ' (status: ' + response.status + ')');
        }
    } catch (e) {
        console.error('Respond to invite error:', e);
        alert('Failed to respond to invite: ' + e.message);
    }
}

function handleGroupInvite(payload) {
    console.log('Received group invite:', payload);
    // Add to pending invites
    pendingInvites.push({
        id: payload.invite_id,
        group_id: payload.group_id,
        group_name: payload.group_name,
        inviter_id: payload.inviter_id,
        inviter_name: payload.inviter_name,
        status: 'pending',
        created_at: new Date().toISOString(),
    });
    console.log('Pending invites now:', pendingInvites);
    updateInvitesBadge();
    
    // Show notification
    if (Notification.permission === 'granted') {
        new Notification('Group Invitation', {
            body: payload.inviter_name + ' invited you to ' + payload.group_name,
            icon: '/icon-192.png',
        });
    }
}

function startNewChat() {
    const username = document.getElementById('new-chat-username').value.trim();
    if (!username) return;
    hideNewChatModal();
    openChat(username);
}

async function loadChats() {
    console.log('Loading chats for user:', state.user?.id);
    
    // First load from localStorage
    if (state.user && state.user.id) {
        const saved = localStorage.getItem('chats_' + state.user.id);
        if (saved) {
            try {
                state.chats = JSON.parse(saved);
                console.log('Loaded chats from localStorage:', Object.keys(state.chats).length);
                
                // Immediately cleanup expired messages from localStorage
                cleanupExpiredMessages();
            } catch (e) {
                console.error('Failed to parse saved chats:', e);
                state.chats = {};
            }
        }
    }
    
    // Render immediately with cached data
    renderChatsList();
    
    // Then load from server in background
    try {
        await Promise.all([
            loadConversations(),
            loadPendingMessages(),
            loadMyGroups(),
            loadPendingInvites()
        ]);
    } catch (e) {
        console.error('Error loading remote data:', e);
    }
}

async function loadConversations() {
    // Load all conversations from server to sync across devices
    try {
        const response = await api('/messages/conversations?days=90');
        if (response.ok) {
            const conversations = await response.json();
            console.log('Loaded conversations from server:', conversations.length);
            
            for (const conv of conversations) {
                const chatKey = conv.contact_id;
                
                // Only add if chat doesn't exist locally
                if (!state.chats[chatKey]) {
                    state.chats[chatKey] = {
                        id: chatKey,
                        username: conv.username,
                        displayName: conv.display_name,
                        avatar_url: conv.avatar_url || null,
                        messages: [],
                        unreadCount: 0,
                        missedCalls: 0,
                    };
                    
                    // Add last message if available
                    if (conv.last_message) {
                        const msg = conv.last_message;
                        let text;
                        try {
                            text = decodeURIComponent(escape(atob(msg.encrypted_payload)));
                            // КАО#342: an E2EE payload also decodes to JSON ({"v":2,...}). It was parsed as
                            // fileInfo, whose `filename` is undefined, so on a device without the plaintext
                            // cache EVERY encrypted text message showed up in the chat list as "📎 File".
                            if (text.startsWith('{"v":')) {
                                text = '';
                            } else if (text.startsWith('{')) {
                                const fileInfo = JSON.parse(text);
                                text = fileInfo.is_voice ? '🎤 Voice message' : '📎 ' + (fileInfo.filename || 'File');
                            }
                        } catch {
                            text = msg.encrypted_payload ? atob(msg.encrypted_payload) : '';
                        }
                        
                        state.chats[chatKey].lastMessage = {
                            id: msg.id,
                            text: text,
                            sender_id: msg.sender_id,
                            created_at: msg.created_at,
                        };
                    }
                } else {
                    // Update display name if changed
                    if (conv.display_name && state.chats[chatKey].displayName !== conv.display_name) {
                        state.chats[chatKey].displayName = conv.display_name;
                    }
                    // Update avatar_url only if server returned a value (don't overwrite with null)
                    if (conv.avatar_url) {
                        state.chats[chatKey].avatar_url = conv.avatar_url;
                    }
                    // КАО#293 (completes КАО#292): the server now omits soft-deleted messages from
                    // last_message, so an explicit null means "nothing visible left in this conversation".
                    // КАО#288 only cleared chats MISSING from the list, so a retracted-message preview
                    // would otherwise survive here. Same guard as #288: never clear a chat that still has
                    // locally-cached messages (those are the real, still-displayable history).
                    const existing = state.chats[chatKey];
                    if (!conv.last_message && existing.lastMessage &&
                        !(Array.isArray(existing.messages) && existing.messages.length > 0)) {
                        existing.lastMessage = null;
                        existing.lastMessageTime = null;
                    }
                }
            }
            
            // КАО#288: clear STALE previews. A 1:1 chat the server no longer lists as a conversation
            // (no server-side last message in the window) AND with no locally-cached messages has no
            // real last message anywhere — null its lastMessage so the list shows "No messages" instead
            // of a snapshot of a message that no longer exists. Guarded on a non-empty server list so a
            // transient empty/partial response cannot wipe every preview. Groups are reconciled elsewhere.
            if (conversations.length > 0) {
                const serverContactIds = new Set(conversations.map(c => c.contact_id));
                for (const key in state.chats) {
                    const c = state.chats[key];
                    if (!c || c.isGroup) continue;
                    const hasLocalMsgs = Array.isArray(c.messages) && c.messages.length > 0;
                    if (c.lastMessage && !hasLocalMsgs && !serverContactIds.has(c.id)) {
                        c.lastMessage = null;
                        c.lastMessageTime = null;
                    }
                }
            }

            saveChats();
            renderChatsList();
        }
    } catch (e) {
        console.error('Failed to load conversations:', e);
    }
}

function saveChats() {
    if (state.user && state.user.id) {
        localStorage.setItem('chats_' + state.user.id, JSON.stringify(state.chats));
    }
}

let _loadingPending = false;
let _pendingQueued = false;
async function loadPendingMessages() {
    // КАО#270 Round-3: serialize (no concurrent double-decrypt of the stateful ratchet) but DON'T drop a
    // request made while one is in flight — queue a single trailing run so a reconnect's recovery isn't
    // lost (Round-2's hard guard silently dropped it). A timeout prevents a black-holed connection from
    // leaving the flag stuck true and permanently suppressing recovery.
    if (_loadingPending) { _pendingQueued = true; return; }
    _loadingPending = true;
    try {
        do {
            _pendingQueued = false;
            const ctrl = new AbortController();
            const to = setTimeout(() => ctrl.abort(), 15000);
            try {
                const response = await api('/messages/pending', { signal: ctrl.signal });
                if (response.ok) {
                    const messages = await response.json();
                    for (const msg of messages) { await handleNewMessage(msg); }
                }
            } finally { clearTimeout(to); }
        } while (_pendingQueued);
    } catch (e) { console.error('Failed to load pending:', e); }
    finally { _loadingPending = false; }
}

function formatTime(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Event Listeners
document.getElementById('login-btn').onclick = login;
document.getElementById('register-btn').onclick = register;
document.getElementById('logout-btn').onclick = logout;
document.getElementById('send-btn').onclick = sendMessage;
document.getElementById('settings-btn').onclick = showSettings;
document.getElementById('settings-back-btn').onclick = () => showScreen('chats');
document.getElementById('change-password-btn').onclick = changePassword;

// v3.10.0: Update biometric login button when username changes
(function() {
    let biometricDebounce = null;
    const usernameInput = document.getElementById('login-username');
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            if (biometricDebounce) clearTimeout(biometricDebounce);
            biometricDebounce = setTimeout(() => {
                if (typeof BiometricAuth !== 'undefined') {
                    BiometricAuth.updateLoginButton();
                }
            }, 500);
        });
    }
})();

var attachBtn = document.getElementById('attach-btn');
if (attachBtn) attachBtn.onclick = sendFile;

// Voice recording
var voiceBtn = document.getElementById('voice-btn');
var deleteVoice = document.getElementById('delete-voice');
var pauseVoice = document.getElementById('pause-voice');
var sendVoiceBtn = document.getElementById('send-voice');

if (voiceBtn) voiceBtn.onclick = startVoiceRecording;
if (deleteVoice) deleteVoice.onclick = deleteVoiceRecording;
if (pauseVoice) pauseVoice.onclick = pauseVoiceRecording;
if (sendVoiceBtn) sendVoiceBtn.onclick = sendVoiceMessage;

// Edit message buttons
var cancelEditBtn = document.getElementById('cancel-edit-btn');
var saveEditBtn = document.getElementById('save-edit-btn');
if (cancelEditBtn) cancelEditBtn.onclick = cancelEditMessage;
if (saveEditBtn) saveEditBtn.onclick = saveEditMessage;

var callBtn = document.getElementById('call-btn');
if (callBtn) callBtn.onclick = toggleCallMenu;

// Search
var searchBtn = document.getElementById('search-btn');
var searchInput = document.getElementById('search-input');
if (searchBtn) searchBtn.onclick = openSearch;
if (searchInput) {
    searchInput.oninput = performSearch;
    searchInput.onkeydown = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            searchNext();
        } else if (e.key === 'Escape') {
            closeSearch();
        }
    };
}

document.getElementById('back-btn').onclick = () => { 
    // v3.8.36: Exit multi-select mode when going back
    if (state.multiSelectMode) {
        exitMultiSelectMode();
    }
    closeSearch();
    stopStatusPolling();
    showScreen('chats'); 
    state.currentChat = null; 
    state.currentChatId = null;
};
document.getElementById('new-chat-btn').onclick = showNewMenu;
document.getElementById('cancel-new-chat').onclick = hideNewChatModal;
document.getElementById('confirm-new-chat').onclick = startNewChat;

// v3.7.30: Group modal handlers
document.getElementById('cancel-new-group').onclick = hideNewGroupModal;
document.getElementById('confirm-new-group').onclick = createGroup;

document.getElementById('show-register').onclick = (e) => {
    e.preventDefault();
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
};

document.getElementById('show-login').onclick = (e) => {
    e.preventDefault();
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
};

document.getElementById('message-text').onkeypress = (e) => { 
    if (e.key === 'Enter') {
        if (editingMessageId) {
            saveEditMessage();
        } else {
            sendMessage();
        }
    }
};
// Use addEventListener to not override other handlers
document.getElementById('message-text').addEventListener('input', sendTypingIndicator);
document.getElementById('message-text').addEventListener('input', updateMarkdownPreview);
document.getElementById('new-chat-username').onkeypress = (e) => { if (e.key === 'Enter') startNewChat(); };
document.getElementById('login-password').onkeypress = (e) => { if (e.key === 'Enter') login(); };

// ==================== PUSH NOTIFICATIONS ====================

async function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) {
        console.log('Service Worker not supported');
        return null;
    }
    
    try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered:', registration.scope);
        return registration;
    } catch (e) {
        console.error('Service Worker registration failed:', e);
        return null;
    }
}

async function subscribeToPush() {
    if (!('PushManager' in window)) {
        console.log('Push notifications not supported');
        return;
    }
    
    try {
        // Wait for service worker to be ready
        const registration = await navigator.serviceWorker.ready;
        
        // Make sure there's an active service worker
        if (!registration.active) {
            console.log('Waiting for service worker to activate...');
            await new Promise((resolve) => {
                if (registration.installing) {
                    registration.installing.addEventListener('statechange', (e) => {
                        if (e.target.state === 'activated') resolve();
                    });
                } else if (registration.waiting) {
                    registration.waiting.addEventListener('statechange', (e) => {
                        if (e.target.state === 'activated') resolve();
                    });
                } else {
                    resolve();
                }
            });
        }
        
        // Get VAPID public key from server
        const response = await api('/push/vapid-key');
        if (!response.ok) {
            console.log('Push not configured on server');
            return;
        }
        const { public_key } = await response.json();
        
        // Convert VAPID key
        const vapidKey = urlBase64ToUint8Array(public_key);
        
        // Check for existing subscription
        let subscription = await registration.pushManager.getSubscription();
        
        // Verify existing subscription uses correct VAPID key
        if (subscription) {
            const existingKey = subscription.options?.applicationServerKey;
            if (existingKey) {
                const existingKeyArray = new Uint8Array(existingKey);
                // Compare keys
                if (!arraysEqual(existingKeyArray, vapidKey)) {
                    console.log('VAPID key changed, unsubscribing old subscription...');
                    await subscription.unsubscribe();
                    subscription = null;
                    // Also clear server-side subscriptions
                    try {
                        await api('/push/clear-all', { method: 'DELETE' });
                        console.log('Cleared old server subscriptions');
                    } catch (e) {
                        console.warn('Failed to clear server subscriptions:', e);
                    }
                }
            }
        }
        
        if (!subscription) {
            // Subscribe to push
            console.log('Creating new push subscription...');
            subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: vapidKey
            });
        }
        
        console.log('Push subscription:', subscription);
        
        // Send subscription to server
        const subJson = subscription.toJSON();
        await api('/push/subscribe', {
            method: 'POST',
            body: JSON.stringify({
                endpoint: subJson.endpoint,
                keys: subJson.keys
            })
        });
        
        console.log('Push subscription saved to server');
    } catch (e) {
        console.error('Push subscription failed:', e);
    }
}

// Helper function to compare Uint8Arrays
function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function requestNotificationPermission() {
    if (!('Notification' in window)) {
        console.log('Notifications not supported');
        return false;
    }
    
    if (Notification.permission === 'granted') {
        return true;
    }
    
    if (Notification.permission !== 'denied') {
        const permission = await Notification.requestPermission();
        return permission === 'granted';
    }
    
    return false;
}

// Handle messages from service worker
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (event) => {
        if (!event.data) return;
        console.log('Message from SW:', event.data);
        
        if (event.data.type === 'notification-click') {
            // Handle notification click
            if (event.data.data && event.data.data.caller_id) {
                // Open chat with caller
                openChat(event.data.data.caller_id);
            }
        } else if (event.data.type === 'push-subscription-changed') {
            // SW created new subscription after VAPID change - send to server
            console.log('Push subscription changed by SW, syncing with server...');
            const subscription = event.data.subscription;
            if (subscription) {
                api('/push/subscribe', {
                    method: 'POST',
                    body: JSON.stringify({
                        endpoint: subscription.endpoint,
                        keys: subscription.keys
                    })
                }).then(() => {
                    console.log('New push subscription synced with server');
                }).catch(e => {
                    console.error('Failed to sync push subscription:', e);
                });
            }
        } else if (event.data.type === 'push-subscription-expired') {
            // Push subscription expired - need to resubscribe
            console.warn('Push subscription expired:', event.data.reason);
            // Trigger full resubscription
            subscribeToPush().catch(e => {
                console.error('Failed to resubscribe after expiry:', e);
            });
        }
        // Don't return anything - synchronous handler
    });
}

async function initPushNotifications() {
    const permission = await requestNotificationPermission();
    if (permission) {
        await registerServiceWorker();
        await subscribeToPush();
    }
}

// ==================== PULL TO REFRESH ====================

function initPullToRefresh() {
    const chatsList = document.getElementById('chats-list');
    const pullIndicator = document.getElementById('pull-indicator');
    
    console.log('initPullToRefresh called, chatsList:', !!chatsList, 'pullIndicator:', !!pullIndicator);
    
    if (!chatsList || !pullIndicator) {
        console.error('Pull to refresh elements not found');
        return;
    }
    
    let startY = 0;
    let currentY = 0;
    let pulling = false;
    let refreshing = false;
    
    chatsList.addEventListener('touchstart', (e) => {
        if (chatsList.scrollTop <= 0 && !refreshing) {
            startY = e.touches[0].clientY;
            pulling = true;
            console.log('Touch start at', startY);
        }
    }, { passive: true });
    
    chatsList.addEventListener('touchmove', (e) => {
        if (!pulling || refreshing) return;
        
        currentY = e.touches[0].clientY;
        const distance = currentY - startY;
        
        if (distance > 0 && chatsList.scrollTop <= 0) {
            const translateY = Math.min(distance * 0.5, 60);
            pullIndicator.style.transform = `translateY(${translateY - 60}px)`;
            pullIndicator.classList.add('visible');
            
            const textEl = pullIndicator.querySelector('.pull-text');
            if (textEl) {
                textEl.textContent = distance > 80 ? 'Release to refresh' : 'Pull to refresh';
            }
        }
    }, { passive: true });
    
    chatsList.addEventListener('touchend', async () => {
        if (!pulling || refreshing) return;
        
        const distance = currentY - startY;
        pulling = false;
        console.log('Touch end, distance:', distance);
        
        if (distance > 80) {
            refreshing = true;
            pullIndicator.classList.add('refreshing');
            const textEl = pullIndicator.querySelector('.pull-text');
            if (textEl) textEl.textContent = 'Refreshing...';
            
            await refreshChats();
            
            setTimeout(() => {
                pullIndicator.classList.remove('visible', 'refreshing');
                pullIndicator.style.transform = '';
                if (textEl) textEl.textContent = 'Pull to refresh';
                refreshing = false;
            }, 500);
        } else {
            pullIndicator.classList.remove('visible');
            pullIndicator.style.transform = '';
        }
        
        startY = 0;
        currentY = 0;
    }, { passive: true });
    
    console.log('Pull to refresh initialized');
}

// Pull to refresh for messages inside chat
function initMessagesPullToRefresh() {
    const container = document.getElementById('messages');
    if (!container) return;
    
    // Skip if already initialized
    if (container.dataset.pullRefreshInit === 'true') return;
    container.dataset.pullRefreshInit = 'true';
    
    // Remove existing indicator if any
    let pullIndicator = document.getElementById('messages-pull-indicator');
    if (!pullIndicator) {
        // Create indicator
        pullIndicator = document.createElement('div');
        pullIndicator.id = 'messages-pull-indicator';
        pullIndicator.className = 'pull-indicator';
        pullIndicator.innerHTML = '<div class="pull-spinner"></div><span class="pull-text">Pull to refresh</span>';
        container.parentElement.insertBefore(pullIndicator, container);
    }
    
    let startY = 0;
    let currentY = 0;
    let pulling = false;
    let refreshing = false;
    
    container.addEventListener('touchstart', (e) => {
        if (container.scrollTop <= 0 && !refreshing) {
            startY = e.touches[0].clientY;
            pulling = true;
        }
    }, { passive: true });
    
    container.addEventListener('touchmove', (e) => {
        if (!pulling || refreshing) return;
        
        currentY = e.touches[0].clientY;
        const distance = currentY - startY;
        
        if (distance > 0 && container.scrollTop <= 0) {
            const translateY = Math.min(distance * 0.5, 60);
            pullIndicator.style.transform = `translateY(${translateY - 60}px)`;
            pullIndicator.classList.add('visible');
            
            const textEl = pullIndicator.querySelector('.pull-text');
            if (textEl) {
                textEl.textContent = distance > 80 ? 'Release to refresh' : 'Pull to refresh';
            }
        }
    }, { passive: true });
    
    container.addEventListener('touchend', async () => {
        if (!pulling || refreshing) return;
        
        const distance = currentY - startY;
        pulling = false;
        
        if (distance > 80) {
            refreshing = true;
            pullIndicator.classList.add('refreshing');
            const textEl = pullIndicator.querySelector('.pull-text');
            if (textEl) textEl.textContent = 'Refreshing...';
            
            await refreshCurrentChat();
            
            setTimeout(() => {
                pullIndicator.classList.remove('visible', 'refreshing');
                pullIndicator.style.transform = '';
                if (textEl) textEl.textContent = 'Pull to refresh';
                refreshing = false;
            }, 500);
        } else {
            pullIndicator.classList.remove('visible');
            pullIndicator.style.transform = '';
        }
        
        startY = 0;
        currentY = 0;
    }, { passive: true });
}

async function refreshCurrentChat() {
    if (!state.currentChat) return;
    
    if (state.currentChat.isGroup) {
        await loadGroupMessages(state.currentChat.id);
    } else {
        // Direct chat - reload messages using loadChatHistory
        await loadChatHistory(state.currentChatId);
    }
    renderMessages();
    scrollToBottom();
}

async function refreshChats() {
    console.log('Refreshing chats...');
    
    // Reload groups
    await loadMyGroups();
    
    // Reload pending invites
    await loadPendingInvites();
    
    // Reload pending messages
    await loadPendingMessages();
    
    // Re-render
    renderChatsList();
    
    console.log('Chats refreshed');
}

async function doManualRefresh() {
    const btn = document.getElementById('refresh-btn');
    if (btn) {
        btn.style.animation = 'spin 1s linear infinite';
    }
    
    await refreshChats();
    
    if (btn) {
        btn.style.animation = '';
    }
}

// Init
if (loadAuth()) {
    initOfflineMode();
    
    // Initialize E2EE (async)
    initE2EE().then(() => {
        console.log('[App] E2EE initialized on page load');
    }).catch(e => {
        console.error('[App] E2EE init failed:', e);
    });
    
    connectWebSocket();
    showScreen('chats');
    loadChats();
    loadUserPermissions();
    initPushNotifications();
    initPullToRefresh();
    updateSoundButton();
    // v3.11.8: Apply screenshot protection if enabled
    applyScreenshotProtection();
    // Ensure invites badge is initialized correctly
    setTimeout(() => {
        updateInvitesBadge();
        console.log('Initial invites badge update');
    }, 100);
    
    // Start timer to check for expired disappearing messages
    setInterval(() => {
        cleanupExpiredMessages();
    }, 10000); // Check every 10 seconds
    
    // v3.10.0: Initialize biometric features (app lock, etc.)
    if (typeof BiometricAuth !== 'undefined') {
        BiometricAuth.init();
    }
} else {
    showScreen('auth');
    
    // v3.10.0: Check for biometric login availability
    if (typeof BiometricAuth !== 'undefined') {
        BiometricAuth.updateLoginButton();
    }
}

// Cleanup expired disappearing messages from local storage
function cleanupExpiredMessages() {
    const now = new Date();
    let needsRerender = false;
    let expiredCount = 0;
    const expiredIds = [];  // КАО#274 (#40): also purge expired plaintext from the IndexedDB cache

    for (const chatId in state.chats) {
        const chat = state.chats[chatId];
        if (!chat.messages) continue;

        const originalLength = chat.messages.length;
        chat.messages = chat.messages.filter(msg => {
            if (!msg.expires_at) return true;
            const expiresAt = new Date(msg.expires_at);
            const isExpired = expiresAt <= now;
            if (isExpired) {
                console.log('Removing expired message:', msg.id);
                expiredCount++;
                if (msg.id) expiredIds.push(msg.id);
            }
            return !isExpired;
        });
        
        if (chat.messages.length !== originalLength) {
            needsRerender = true;
            // Update lastMessage if needed
            if (chat.messages.length > 0) {
                chat.lastMessage = chat.messages[chat.messages.length - 1];
            } else {
                chat.lastMessage = null;
            }
        }
    }
    
    if (needsRerender) {
        console.log('Cleaned up', expiredCount, 'expired messages');
        saveChats();
        // КАО#274 (#40): purge the expired messages' decrypted plaintext from IndexedDB so it doesn't
        // survive on disk after the disappearing timer (the chat-history cache is keyed by message id).
        if (expiredIds.length && typeof offlineDB !== 'undefined' && offlineDB) {
            offlineDB.deleteDecryptedMessages(expiredIds);
        }
        if (state.currentChatId) {
            renderMessages();
        }
        renderChatsList();
    }
}

// Also cleanup when page becomes visible (handles browser throttling)
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        cleanupExpiredMessages();
        // Mark messages as read when returning to app
        if (state.currentChatId) {
            markCurrentChatAsRead();
        }
    }
});

// ==================== КАО#283 (#23 / #21): modal & menu keyboard accessibility ====================
// Previously no modal exposed role=dialog/aria-modal, none trapped focus or closed on Escape, and the
// message context menu had no keyboard path. This adds, app-wide and without touching each modal's markup:
//   • role="dialog" + aria-modal + focus-first whenever any .modal becomes visible (MutationObserver),
//   • Escape closes the topmost open modal / menu / overlay,
//   • Tab is trapped inside an open modal.
(function initA11yModals() {
    const FOCUSABLE = 'a[href], button:not([disabled]), input:not([type=hidden]):not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

    function focusFirst(el) {
        if (el.contains(document.activeElement)) return;
        const f = el.querySelector(FOCUSABLE);
        if (f) { try { f.focus({ preventScroll: true }); } catch (e) {} }
    }

    function markDialog(el) {
        if (!el || !el.setAttribute) return;
        el.setAttribute('role', 'dialog');
        el.setAttribute('aria-modal', 'true');
        focusFirst(el);
    }

    // Static .modal elements toggle .hidden → mark + focus when shown.
    const classObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
            const el = m.target;
            if (el.classList && el.classList.contains('modal') && !el.classList.contains('hidden')) markDialog(el);
        }
    });
    document.querySelectorAll('.modal').forEach(el => classObserver.observe(el, { attributes: true, attributeFilter: ['class'] }));

    // Dynamically-created modals (poll/export/etc. use a .modal-overlay wrapper) → mark + focus on insert.
    const addObserver = new MutationObserver((mutations) => {
        for (const m of mutations) for (const n of m.addedNodes) {
            if (n.nodeType !== 1 || !n.classList) continue;
            if (n.classList.contains('modal-overlay') || n.classList.contains('modal')) markDialog(n.querySelector('.modal') || n);
        }
    });
    addObserver.observe(document.body, { childList: true });

    // КАО#311 (supersedes the DOM-order rule of КАО#285/#287/#296): pick the genuinely-topmost layer by
    // COMPUTED Z-INDEX, falling back to DOM order only on ties. These layers deliberately differ —
    // .system-notification-overlay / .e2ee-confirm-overlay = 10001, .media-lightbox = 10000,
    // .modal-overlay / .side-panel = 1000, .modal = 100 — so "last in DOM order" is right only within one
    // layer, and a per-class pre-emptive branch (what КАО#287 was about, and what the КАО#296 lightbox
    // branch re-introduced) picks the wrong element whenever layers are mixed.
    const OVERLAY_SELECTOR = '.modal-overlay, .system-notification-overlay, .side-panel, .e2ee-confirm-overlay, #media-lightbox:not(.hidden), .modal:not(.hidden)';
    function topmostOverlay() {
        const open = Array.from(document.querySelectorAll(OVERLAY_SELECTOR)).filter(el => {
            const cs = getComputedStyle(el);
            // КАО#334/#344: skip layers that are on their way OUT. A system notification keeps its node for
            // ~300ms while it fades, and being the highest z-index it swallowed the Escape meant for the
            // dialog underneath. Testing opacity alone was wrong — these overlays START at opacity 0 and
            // fade IN, so that also skipped a notification the user could genuinely see. The dismissing
            // path marks the element instead (see showSystemNotification/showAdminNotification).
            if (el.dataset && el.dataset.dismissing === '1') return false;
            return cs.display !== 'none' && cs.visibility !== 'hidden' && cs.pointerEvents !== 'none';
        });
        let best = null, bestZ = -Infinity;
        for (const el of open) {                       // document order → ">=" keeps the LAST on a tie
            const z = parseInt(getComputedStyle(el).zIndex, 10);
            const zz = Number.isFinite(z) ? z : 0;
            if (zz >= bestZ) { bestZ = zz; best = el; }
        }
        return best;
    }

    // Topmost active dialog for the Tab trap (same rule, so Tab and Escape can never disagree).
    function topmostDialog() {
        return topmostOverlay();
    }

    // КАО#283 Round-3: dismiss a modal via its OWN cancel/close control so promise-backed dialogs
    // (showConfirm/showAlert) resolve and run cleanup, and dynamically-appended modals are removed by
    // their handler — instead of blindly toggling .hidden (which hung the promise + leaked listeners,
    // and orphaned re-created modals). Falls back to .hidden only when no control is found.
    function dismissModal(el) {
        // prefer a cancel/close control; NEVER a confirm dialog's OK (Escape must mean cancel, not confirm)
        let btn = el.querySelector('[id$="-cancel-btn"], .cancel-btn, .btn-cancel, .modal-cancel, .close-btn')
               || el.querySelector('[onclick*="close" i], [onclick*="cancel" i], [onclick*="hide" i]');
        // an alert dialog has only an OK button → that IS its safe dismiss
        if (!btn && el.id === 'universal-alert-modal') btn = el.querySelector('#alert-ok-btn');
        if (btn) { btn.click(); return; }
        el.classList.add('hidden');
    }

    // КАО#283 Round-2/3: close via the app's OWN semantics so dynamic overlays are fully removed (not left
    // as an un-dismissable backdrop), promise-dialogs resolve, and menu state flags stay in sync.
    function closeTopmost() {
        const mm = document.getElementById('message-menu');
        if (mm && !mm.classList.contains('hidden')) { hideMessageMenu(); return true; }
        // КАО#311: ONE decision for every layer — close whatever is genuinely on top (see topmostOverlay),
        // then dismiss it with that element's own semantics: the media lightbox via closeLightbox(); the
        // promise-backed unencrypted-send confirm via its Cancel (so the awaiting send resolves to false
        // instead of hanging); dynamic overlays/side panels by removal (they exist only while open); a
        // static .modal via its own cancel/close control. No per-class pre-emptive branches.
        const top = topmostOverlay();
        if (top) {
            if (top.id === 'media-lightbox') {
                closeLightbox();
            } else if (top.classList.contains('e2ee-confirm-overlay')) {
                const cancel = top.querySelector('.cancel');
                if (cancel) cancel.click(); else top.remove();
            } else if (top.classList.contains('modal-overlay') || top.classList.contains('system-notification-overlay') || top.classList.contains('side-panel')) {
                top.remove();
            } else {
                dismissModal(top);
            }
            return true;
        }
        // dropdown menus — canonical closers keep flags/overlays consistent
        const nm = document.getElementById('new-menu');
        if (nm && !nm.classList.contains('hidden') && typeof hideNewMenu === 'function') { hideNewMenu(); return true; }
        const gm = document.getElementById('group-menu');
        if (gm && !gm.classList.contains('hidden') && typeof closeGroupMenu === 'function') { closeGroupMenu(); return true; }
        const other = document.querySelector('#call-menu:not(.hidden), #disappearing-menu:not(.hidden)');
        if (other) { other.classList.add('hidden'); return true; }
        return false;
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            if (closeTopmost()) {
                e.preventDefault();
                // КАО#315: ONE Escape must dismiss exactly ONE layer. This IIFE registers before the
                // media-lightbox's own document-level Escape listener (app.js, "Keyboard navigation for
                // lightbox"), which closes the lightbox regardless of what else is on top — so dismissing
                // a system notification ALSO closed the lightbox underneath it. closeTopmost() already
                // handles the lightbox itself, so stop any later document-level handler from acting on the
                // same key. Element-scoped handlers (search/mentions/password inputs) run earlier in the
                // bubble phase and are unaffected.
                e.stopImmediatePropagation();
            }
            return;
        }
        if (e.key === 'Tab') {
            const modal = topmostDialog();
            if (!modal) return;
            const items = Array.from(modal.querySelectorAll(FOCUSABLE)).filter(el => el.offsetParent !== null);
            if (!items.length) return;
            const first = items[0], last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
            else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
            else if (!modal.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
        }
    });
})();

// ==================== GROUP MENU FUNCTIONS ====================

var groupMenuOpen = false;
var currentGroupMembers = [];

function toggleGroupMenu() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    if (groupMenuOpen) {
        closeGroupMenu();
    } else {
        openGroupMenu();
    }
}

async function openGroupMenu() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    const menu = document.getElementById('group-menu');
    const chatName = document.getElementById('chat-name');
    const overlay = document.getElementById('group-menu-overlay');
    
    menu.classList.remove('hidden');
    overlay.classList.remove('hidden');
    chatName.classList.add('menu-open');
    groupMenuOpen = true;
    
    await loadGroupMembers(chat.id);
    await loadInviteLinkStatus(chat.id);
    renderGroupMenuActions();
}

function closeGroupMenu() {
    const menu = document.getElementById('group-menu');
    const chatName = document.getElementById('chat-name');
    const overlay = document.getElementById('group-menu-overlay');
    
    if (menu) menu.classList.add('hidden');
    if (overlay) overlay.classList.add('hidden');
    if (chatName) chatName.classList.remove('menu-open');
    groupMenuOpen = false;
}

async function loadGroupMembers(groupId) {
    try {
        const response = await api('/groups/' + groupId + '/members');
        if (response.ok) {
            currentGroupMembers = await response.json();
            renderGroupMembersList();
            document.getElementById('chat-status').textContent = currentGroupMembers.length + ' members';
        }
    } catch (e) {
        console.error('Failed to load group members:', e);
    }
}

function renderGroupMembersList() {
    const container = document.getElementById('group-menu-members-list');
    const chat = state.currentChat;
    const myRole = getCurrentUserRole();
    const isOwner = myRole === 'owner';
    const isAdmin = myRole === 'admin';
    const canManageRoles = isOwner || isAdmin;
    
    if (!currentGroupMembers.length) {
        container.innerHTML = '<div class="no-contacts-message">No members</div>';
        return;
    }
    
    let html = '';
    currentGroupMembers.forEach(function(member) {
        const displayName = member.display_name || member.username;
        const isOnline = state.onlineUsers && state.onlineUsers[member.user_id];
        const isCurrentUser = member.user_id === state.user.id;
        const statusClass = isOnline ? 'online' : 'offline';
        const memberRole = member.role || 'member';
        
        html += '<div class="group-member-item" data-user-id="' + escapeHtml(member.user_id) + '">';
        html += '  <div class="group-member-status-dot ' + statusClass + '"></div>';
        html += '  <div class="group-member-info">';
        html += '    <div class="group-member-name">' + escapeHtmlGM(displayName) + '</div>';
        
        // Role display with dropdown for manageable members
        if (canManageRoles && !isCurrentUser && memberRole !== 'owner' && canChangeRole(myRole, memberRole)) {
            html += '    <select class="role-select member-role-select" onchange="changeMemberRole(\'' + escapeHtml(member.user_id) + '\', this.value)">';
            html += '      <option value="member"' + (memberRole === 'member' ? ' selected' : '') + '>Member</option>';
            html += '      <option value="moderator"' + (memberRole === 'moderator' ? ' selected' : '') + '>Moderator</option>';
            if (isOwner) {
                html += '      <option value="admin"' + (memberRole === 'admin' ? ' selected' : '') + '>Admin</option>';
            }
            html += '    </select>';
        } else {
            html += '    <div class="group-member-role ' + memberRole + '">' + getRoleLabelGM(memberRole) + '</div>';
        }
        
        html += '  </div>';
        
        // Remove button for owner/admin (can't remove higher roles)
        if (canManageRoles && !isCurrentUser && memberRole !== 'owner' && canChangeRole(myRole, memberRole)) {
            html += '  <button class="group-member-remove" onclick="removeMemberFromGroup(\'' + escapeHtml(member.user_id) + '\', \'' + safeOnclickArg(displayName) + '\')">✕</button>';
        }
        
        html += '</div>';
    });
    
    container.innerHTML = html;
}

function getCurrentUserRole() {
    if (!currentGroupMembers.length || !state.user) return 'member';
    const me = currentGroupMembers.find(m => m.user_id === state.user.id);
    return me ? (me.role || 'member') : 'member';
}

function canChangeRole(myRole, targetRole) {
    const roleHierarchy = { owner: 4, admin: 3, moderator: 2, member: 1, subscriber: 0 };
    return roleHierarchy[myRole] > roleHierarchy[targetRole];
}

function getRoleLabelGM(role) {
    switch (role) {
        case 'owner': return '👑 Owner';
        case 'admin': return '⭐ Admin';
        case 'moderator': return '🛡️ Moderator';
        case 'subscriber': return '🔔 Subscriber';
        default: return 'Member';
    }
}

function renderGroupMenuActions() {
    const container = document.getElementById('group-menu-actions');
    const chat = state.currentChat;
    const myRole = getCurrentUserRole();
    const isOwner = myRole === 'owner';
    const isAdmin = myRole === 'admin';
    
    let html = '';
    
    // v3.11.10: Channel-aware action labels
    const isCh = chat && chat.isChannel;
    const leaveLabel = isCh ? '🔔 Unsubscribe' : '🚪 Leave group';
    const deleteLabel = isCh ? '🗑 Delete channel' : '🗑 Delete group';

    if (isOwner) {
        html += '<button class="group-menu-btn add-member-btn" onclick="openAddMemberModal()">➕ Add member</button>';
        html += '<button class="group-menu-btn transfer-ownership-btn" onclick="showTransferOwnershipModal()">👑 Transfer ownership</button>';
        html += '<button class="group-menu-btn delete-group-btn" onclick="deleteGroupFromMenu()">' + deleteLabel + '</button>';
    } else if (isAdmin) {
        html += '<button class="group-menu-btn add-member-btn" onclick="openAddMemberModal()">➕ Add member</button>';
        html += '<button class="group-menu-btn leave-group-btn" onclick="leaveGroupFromMenu()">' + leaveLabel + '</button>';
    } else {
        html += '<button class="group-menu-btn leave-group-btn" onclick="leaveGroupFromMenu()">' + leaveLabel + '</button>';
    }
    
    container.innerHTML = html;
    
    // Render invite link section
    renderInviteLinkSection();
}

// ==================== INVITE LINK FUNCTIONS ====================

let currentInviteLinkStatus = null;

async function loadInviteLinkStatus(groupId) {
    try {
        const response = await api('/groups/' + groupId + '/invite-link');
        if (response.ok) {
            currentInviteLinkStatus = await response.json();
        } else if (response.status === 404) {
            currentInviteLinkStatus = { enabled: false, invite_code: null };
        } else {
            currentInviteLinkStatus = null;
        }
    } catch (e) {
        console.error('Load invite link status error:', e);
        currentInviteLinkStatus = null;
    }
}

function renderInviteLinkSection() {
    const container = document.getElementById('group-menu-invite-section');
    if (!container) return;
    
    const myRole = getCurrentUserRole();
    const canManageInviteLink = myRole === 'owner' || myRole === 'admin';
    
    if (!canManageInviteLink) {
        container.innerHTML = '';
        return;
    }
    
    let html = '<div class="group-menu-section-title">Invite Link</div>';
    html += '<div class="invite-link-container">';
    
    if (currentInviteLinkStatus && currentInviteLinkStatus.enabled && currentInviteLinkStatus.invite_code) {
        // Invite link is active
        const inviteUrl = window.location.origin + '/join/' + currentInviteLinkStatus.invite_code;
        html += '<div class="invite-link-active">';
        html += '  <div class="invite-link-display">';
        html += '    <input type="text" class="invite-link-input" value="' + escapeHtml(inviteUrl) + '" readonly onclick="this.select()">';
        html += '    <button class="copy-link-btn invite-link-btn" onclick="copyInviteLink()">📋 Copy</button>';
        html += '  </div>';
        html += '  <div class="invite-link-actions">';
        html += '    <button class="group-menu-btn small invite-link-btn" onclick="resetInviteLink()">🔄 Reset</button>';
        html += '    <button class="group-menu-btn small danger invite-link-btn" onclick="disableInviteLink()">🚫 Disable</button>';
        html += '  </div>';
        html += '</div>';
    } else {
        // Invite link is disabled
        html += '<div class="invite-link-disabled">';
        html += '  <div class="invite-link-status">Invite link is disabled</div>';
        html += '  <button class="group-menu-btn invite-link-btn" onclick="createInviteLink()">🔗 Create invite link</button>';
        html += '</div>';
    }
    
    html += '</div>';
    container.innerHTML = html;
}

async function createInviteLink() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/invite-link', { method: 'POST' });
        if (response.ok) {
            const data = await response.json();
            currentInviteLinkStatus = { enabled: true, invite_code: data.invite_code };
            renderInviteLinkSection();
            showSystemNotification('Invite link created');
        } else {
            const error = await response.json();
            await showAlert(error.detail || 'Failed to create invite link', 'Error', '❌');
        }
    } catch (e) {
        console.error('Create invite link error:', e);
        await showAlert('Error creating invite link', 'Error', '❌');
    }
}

async function copyInviteLink() {
    if (!currentInviteLinkStatus || !currentInviteLinkStatus.invite_code) return;
    
    const inviteUrl = window.location.origin + '/join/' + currentInviteLinkStatus.invite_code;
    
    try {
        await navigator.clipboard.writeText(inviteUrl);
        showSystemNotification('Invite link copied to clipboard');
    } catch (e) {
        // Fallback for older browsers
        const input = document.querySelector('.invite-link-input');
        if (input) {
            input.select();
            document.execCommand('copy');
            showSystemNotification('Invite link copied to clipboard');
        }
    }
}

async function resetInviteLink() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    const confirmed = await showConfirm(
        'Reset invite link? The old link will stop working.',
        'Reset Invite Link?',
        'Reset',
        'Cancel'
    );
    if (!confirmed) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/invite-link/reset', { method: 'POST' });
        if (response.ok) {
            const data = await response.json();
            currentInviteLinkStatus = { enabled: true, invite_code: data.invite_code };
            renderInviteLinkSection();
            showSystemNotification('Invite link reset');
        } else {
            const error = await response.json();
            await showAlert(error.detail || 'Failed to reset invite link', 'Error', '❌');
        }
    } catch (e) {
        console.error('Reset invite link error:', e);
        await showAlert('Error resetting invite link', 'Error', '❌');
    }
}

async function disableInviteLink() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    const confirmed = await showConfirm(
        'Disable invite link? People will not be able to join using this link.',
        'Disable Invite Link?',
        'Disable',
        'Cancel'
    );
    if (!confirmed) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/invite-link', { method: 'DELETE' });
        if (response.ok || response.status === 204) {
            currentInviteLinkStatus = { enabled: false, invite_code: null };
            renderInviteLinkSection();
            showSystemNotification('Invite link disabled');
        } else {
            const error = await response.json();
            await showAlert(error.detail || 'Failed to disable invite link', 'Error', '❌');
        }
    } catch (e) {
        console.error('Disable invite link error:', e);
        await showAlert('Error disabling invite link', 'Error', '❌');
    }
}

// ==================== ROLE MANAGEMENT ====================

async function changeMemberRole(userId, newRole) {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/members/' + userId + '/role', {
            method: 'PUT',
            body: JSON.stringify({ role: newRole })
        });
        
        if (response.ok) {
            // Update local member data
            const member = currentGroupMembers.find(m => m.user_id === userId);
            if (member) {
                member.role = newRole;
            }
            showSystemNotification('Role updated');
        } else {
            const error = await response.json();
            await showAlert(error.detail || 'Failed to change role', 'Error', '❌');
            // Refresh to revert UI
            await loadGroupMembers(chat.id);
            renderGroupMembersList();
        }
    } catch (e) {
        console.error('Change role error:', e);
        await showAlert('Error changing role', 'Error', '❌');
    }
}

// ==================== TRANSFER OWNERSHIP ====================

async function showTransferOwnershipModal() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    // Get list of members (excluding owner)
    const eligibleMembers = currentGroupMembers.filter(m => 
        m.user_id !== state.user.id && m.role !== 'owner'
    );
    
    if (eligibleMembers.length === 0) {
        await showAlert('No other members to transfer ownership to', 'Info', 'ℹ️');
        return;
    }
    
    // Create modal content
    let html = '<div class="transfer-ownership-list">';
    eligibleMembers.forEach(member => {
        const displayName = member.display_name || member.username;
        html += '<div class="transfer-ownership-item" onclick="transferOwnership(\'' + escapeHtml(member.user_id) + '\', \'' + safeOnclickArg(displayName) + '\')">';
        html += '  <span class="transfer-member-name">' + escapeHtml(displayName) + '</span>';
        html += '  <span class="transfer-member-role">' + getRoleLabelGM(member.role) + '</span>';
        html += '</div>';
    });
    html += '</div>';
    
    // Use showModal if available, otherwise create simple modal
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'transfer-ownership-modal';
    modal.innerHTML = `
        <div class="modal-content" onclick="event.stopPropagation()">
            <h3>Transfer Ownership</h3>
            <p>Select new owner:</p>
            ${html}
            <button class="btn" onclick="closeTransferOwnershipModal()">Cancel</button>
        </div>
    `;
    modal.onclick = closeTransferOwnershipModal;
    document.body.appendChild(modal);
}

function closeTransferOwnershipModal() {
    const modal = document.getElementById('transfer-ownership-modal');
    if (modal) modal.remove();
}

async function transferOwnership(newOwnerId, displayName) {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    closeTransferOwnershipModal();
    
    const confirmed = await showConfirm(
        `Transfer ownership to ${displayName}? You will become an admin.`,
        'Transfer Ownership?',
        'Transfer',
        'Cancel'
    );
    if (!confirmed) return;

    // v3.10.0: Step-up biometric verification for this sensitive action.
    // КАО#220 (SER#22): capture the step-up token (biometric OR password fallback) and send it as
    // X-Verify-Token — the server enforces step-up for passkey users on this endpoint, and the
    // token was previously discarded (transfer-ownership was permanently broken for passkey users).
    // Done right before the request so the short-lived (120s) token doesn't expire during the dialog.
    let verifyToken = null;
    if (typeof BiometricAuth !== 'undefined') {
        const verified = await BiometricAuth.requireVerification('Confirm identity to transfer group ownership');
        if (!verified) return;
        if (typeof verified === 'string') verifyToken = verified;
    }

    try {
        const response = await api('/groups/' + chat.id + '/transfer-ownership?new_owner_id=' + newOwnerId, {
            method: 'POST',
            headers: verifyToken ? { 'X-Verify-Token': verifyToken } : {}
        });
        
        if (response.ok) {
            showSystemNotification('Ownership transferred');
            // Refresh group data
            await loadGroupMembers(chat.id);
            renderGroupMembersList();
            renderGroupMenuActions();
        } else {
            const error = await response.json();
            await showAlert(error.detail || 'Failed to transfer ownership', 'Error', '❌');
        }
    } catch (e) {
        console.error('Transfer ownership error:', e);
        await showAlert('Error transferring ownership', 'Error', '❌');
    }
}

// ==================== END INVITE LINK / ROLE MANAGEMENT ====================

async function removeMemberFromGroup(userId, displayName) {
    const confirmed = await showConfirm(
        `Remove ${displayName} from the group?`,
        'Remove Member?',
        'Remove',
        'Cancel'
    );
    if (!confirmed) return;
    
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/members/' + userId, { method: 'DELETE' });
        if (response.ok || response.status === 204) {
            await loadGroupMembers(chat.id);
        } else {
            const data = await response.json();
            await showAlert(data.detail || 'Failed to remove member', 'Error', '❌');
        }
    } catch (e) {
        console.error('Remove member error:', e);
        await showAlert('Error removing member', 'Error', '❌');
    }
}

async function deleteGroupFromMenu() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    const confirmed = await showConfirm(
        `Delete group "${chat.name}" for all members?`,
        'Delete Group?',
        'Delete',
        'Cancel'
    );
    if (!confirmed) return;
    
    closeGroupMenu();
    
    try {
        const response = await api('/groups/' + chat.id, { method: 'DELETE' });
        if (response.ok || response.status === 204) {
            const chatKey = 'group_' + chat.id;
            delete state.chats[chatKey];
            saveChats();
            renderChatsList();
            showScreen('chats');
            showSystemNotification('Group deleted');
        } else {
            const data = await response.json();
            await showAlert(data.detail || 'Failed to delete group', 'Error', '❌');
        }
    } catch (e) {
        console.error('Delete group error:', e);
        await showAlert('Error deleting group', 'Error', '❌');
    }
}

async function leaveGroupFromMenu() {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    const confirmed = await showConfirm(
        `Leave group "${chat.name}"?`,
        'Leave Group?',
        'Leave',
        'Cancel'
    );
    if (!confirmed) return;
    
    closeGroupMenu();
    
    try {
        const response = await api('/groups/' + chat.id + '/members/' + state.user.id, { method: 'DELETE' });
        if (response.ok || response.status === 204) {
            const chatKey = 'group_' + chat.id;
            delete state.chats[chatKey];
            saveChats();
            renderChatsList();
            showScreen('chats');
            showSystemNotification('You left the group');
        } else {
            const data = await response.json();
            await showAlert(data.detail || 'Failed to leave group', 'Error', '❌');
        }
    } catch (e) {
        console.error('Leave group error:', e);
        await showAlert('Error leaving group', 'Error', '❌');
    }
}

var availableContacts = [];

function openAddMemberModal() {
    closeGroupMenu();
    const modal = document.getElementById('add-member-modal');
    modal.classList.remove('hidden');
    loadAvailableContacts();
    setTimeout(function() {
        document.getElementById('add-member-search').focus();
    }, 100);
}

function closeAddMemberModal() {
    const modal = document.getElementById('add-member-modal');
    modal.classList.add('hidden');
    document.getElementById('add-member-search').value = '';
}

function loadAvailableContacts() {
    const memberIds = currentGroupMembers.map(function(m) { return m.user_id; });
    
    availableContacts = Object.values(state.chats)
        .filter(function(chat) { return !chat.isGroup && !memberIds.includes(chat.id); })
        .map(function(chat) {
            return {
                id: chat.id,
                displayName: chat.displayName || chat.username || chat.id,
                username: chat.username
            };
        });
    
    renderAddMemberList('');
}

function renderAddMemberList(filter) {
    const container = document.getElementById('add-member-list');
    const filterLower = (filter || '').toLowerCase();
    
    const filtered = availableContacts.filter(function(contact) {
        if (!filter) return true;
        return (contact.displayName && contact.displayName.toLowerCase().includes(filterLower)) ||
               (contact.username && contact.username.toLowerCase().includes(filterLower));
    });
    
    if (!filtered.length) {
        container.innerHTML = '<div class="no-contacts-message">' + 
            (filter ? 'No contacts found' : 'No available contacts') + '</div>';
        return;
    }
    
    let html = '';
    filtered.forEach(function(contact) {
        const displayName = contact.displayName || contact.username || contact.id;
        const initial = displayName[0].toUpperCase();
        
        html += '<div class="add-member-item" onclick="addMemberToGroup(\'' + escapeHtml(contact.id) + '\')">';
        html += '  <div class="add-member-avatar">' + escapeHtml(initial) + '</div>';
        html += '  <div class="add-member-name">' + escapeHtmlGM(displayName) + '</div>';
        html += '  <span class="add-member-add-icon">+</span>';
        html += '</div>';
    });
    
    container.innerHTML = html;
}

function filterAddMemberList() {
    const search = document.getElementById('add-member-search').value;
    renderAddMemberList(search);
}

async function addMemberToGroup(userId) {
    const chat = state.currentChat;
    if (!chat || !chat.isGroup) return;
    
    try {
        const response = await api('/groups/' + chat.id + '/members', {
            method: 'POST',
            body: JSON.stringify({ user_ids: [userId] })
        });
        
        if (response.ok) {
            closeAddMemberModal();
            showSystemNotification('Invite sent');
        } else {
            let errorMsg = 'Failed to send invite';
            try {
                const data = await response.json();
                errorMsg = data.detail || data.message || JSON.stringify(data);
            } catch (e) {
                errorMsg = 'Error: ' + response.status + ' ' + response.statusText;
            }
            alert(errorMsg);
        }
    } catch (e) {
        console.error('Add member error:', e);
        alert('Error sending invite');
    }
}

function setupGroupMenuForChat() {
    const chat = state.currentChat;
    const chatName = document.getElementById('chat-name');
    
    if (chat && chat.isGroup) {
        chatName.classList.add('group-name-clickable');
        chatName.onclick = toggleGroupMenu;
    } else {
        chatName.classList.remove('group-name-clickable');
        chatName.classList.remove('menu-open');
        chatName.onclick = null;
    }
    
    closeGroupMenu();
}

function escapeHtmlGM(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== POLLS ====================

let currentPollData = null;

function showCreatePollModal() {
    // v3.7.31: Закрыть существующую модалку если есть (предотвращает дублирование)
    closePollModal();
    
    const isGroup = state.currentChat && state.currentChat.isGroup;
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'poll-modal';
    modal.innerHTML = `
        <div class="modal poll-modal">
            <div class="modal-header">
                <h3>📊 Create poll</h3>
                <button class="modal-close" onclick="closePollModal()">×</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>Question</label>
                    <input type="text" id="poll-question" maxlength="500" placeholder="Ask a question...">
                </div>
                <div class="form-group">
                    <label>Answer options (min 2, max 10)</label>
                    <div id="poll-options">
                        <div class="poll-option-input">
                            <input type="text" class="poll-option" maxlength="100" placeholder="Option 1">
                            <button class="remove-option-btn" onclick="removePollOption(this)" style="display:none">×</button>
                        </div>
                        <div class="poll-option-input">
                            <input type="text" class="poll-option" maxlength="100" placeholder="Option 2">
                            <button class="remove-option-btn" onclick="removePollOption(this)" style="display:none">×</button>
                        </div>
                    </div>
                    <button class="add-option-btn" onclick="addPollOption()">+ Add option</button>
                </div>
                <div class="poll-settings">
                    <label class="checkbox-label">
                        <input type="checkbox" id="poll-anonymous" checked>
                        Anonymous poll
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="poll-multiple">
                        Multiple choice
                    </label>
                    <div class="poll-expiry">
                        <label>
                            <input type="checkbox" id="poll-has-expiry">
                            Set time limit
                        </label>
                        <select id="poll-expiry-time" disabled>
                            <option value="60">1 hour</option>
                            <option value="360">6 hours</option>
                            <option value="1440">24 hours</option>
                            <option value="4320">3 days</option>
                            <option value="10080">7 days</option>
                        </select>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closePollModal()">Cancel</button>
                <button class="btn btn-primary" onclick="createPoll()">Create</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Setup expiry checkbox
    document.getElementById('poll-has-expiry').addEventListener('change', (e) => {
        document.getElementById('poll-expiry-time').disabled = !e.target.checked;
    });
    
    updateRemoveButtons();
}

function closePollModal() {
    const modal = document.getElementById('poll-modal');
    if (modal) modal.remove();
}

function addPollOption() {
    const container = document.getElementById('poll-options');
    const options = container.querySelectorAll('.poll-option-input');
    if (options.length >= 10) {
        alert('Maximum 10 options');
        return;
    }
    
    const div = document.createElement('div');
    div.className = 'poll-option-input';
    div.innerHTML = `
        <input type="text" class="poll-option" maxlength="100" placeholder="Option ${options.length + 1}">
        <button class="remove-option-btn" onclick="removePollOption(this)">×</button>
    `;
    container.appendChild(div);
    updateRemoveButtons();
}

function removePollOption(btn) {
    const container = document.getElementById('poll-options');
    const options = container.querySelectorAll('.poll-option-input');
    if (options.length <= 2) return;
    
    btn.parentElement.remove();
    updateRemoveButtons();
    
    // Update placeholders
    container.querySelectorAll('.poll-option').forEach((input, i) => {
        input.placeholder = `Option ${i + 1}`;
    });
}

function updateRemoveButtons() {
    const container = document.getElementById('poll-options');
    if (!container) return;
    const options = container.querySelectorAll('.poll-option-input');
    options.forEach(opt => {
        const btn = opt.querySelector('.remove-option-btn');
        if (btn) btn.style.display = options.length > 2 ? 'block' : 'none';
    });
}

async function createPoll() {
    const question = document.getElementById('poll-question').value.trim();
    if (!question) {
        alert('Enter a question');
        return;
    }
    
    const optionInputs = document.querySelectorAll('#poll-options input.poll-option');
    const options = Array.from(optionInputs)
        .map(input => input.value.trim())
        .filter(v => v);
    
    if (options.length < 2) {
        alert('At least 2 options required');
        return;
    }
    
    const isAnonymous = document.getElementById('poll-anonymous').checked;
    const isMultiple = document.getElementById('poll-multiple').checked;
    const hasExpiry = document.getElementById('poll-has-expiry').checked;
    const expiryMinutes = hasExpiry ? parseInt(document.getElementById('poll-expiry-time').value) : null;
    
    const chat = state.currentChat;
    // КАО#230 (SER#18): poll content is now end-to-end encrypted. A per-poll random key encrypts the
    // question and every option; only ciphertext (prefixed "e2e:") is stored server-side. The key is
    // distributed to participants inside the (already E2E) poll announce message ([pollkey:...]) and
    // recipients decrypt on render. Server tallies by option INDEX, so it never needs the plaintext.
    let pollKey = null;
    let outQuestion = question;
    let outOptions = options;
    if (state.e2eeReady) {
        try {
            pollKey = VibeCrypto.generateContentKey();
            outQuestion = 'e2e:' + await VibeCrypto.encryptWithKey(question, pollKey);
            outOptions = [];
            for (const opt of options) outOptions.push('e2e:' + await VibeCrypto.encryptWithKey(opt, pollKey));
        } catch (e) {
            console.error('[E2EE] Poll content encryption failed:', e);
            showEncryptionFailedError('Poll encryption failed. Poll was NOT created.');
            return;
        }
    } else {
        showEncryptionFailedError('End-to-end encryption is not initialized. Poll was NOT created.');
        return;
    }
    const pollData = {
        question: outQuestion,
        options: outOptions,
        is_anonymous: isAnonymous,
        is_multiple: isMultiple,
        expires_in_minutes: expiryMinutes,
        chat_id: chat.isGroup ? null : chat.id,
        group_id: chat.isGroup ? chat.id : null
    };

    try {
        const response = await api('/polls', {
            method: 'POST',
            body: JSON.stringify(pollData)
        });

        if (response.ok) {
            const poll = await response.json();
            // КАО#230: cache the key, then decrypt the server's (ciphertext) response for immediate render
            if (pollKey) state.pollKeys[poll.id] = pollKey;
            await decryptPollFields(poll);
            // Cache the poll immediately
            pollCache[poll.id] = poll;
            closePollModal();

            // Send as message with poll reference + the per-poll content key (carried inside the E2E message)
            const pollMessage = `📊 **Poll:** ${question}\n[poll:${poll.id}]\n[pollkey:${pollKey || ''}]`;
            await sendPollMessage(poll.id, pollMessage);
        } else {
            const error = await response.json();
            alert(error.detail || 'Failed to create poll');
        }
    } catch (e) {
        console.error('Create poll error:', e);
        alert('Failed to create poll');
    }
}

async function sendPollMessage(pollId, text) {
    const chat = state.currentChat;
    if (!chat) return;
    
    const clientMessageId = 'poll_' + Date.now();
    
    // Add message to UI immediately
    const message = {
        id: clientMessageId,
        text: text,
        sender_id: state.user.id,
        created_at: new Date().toISOString(),
        status: 'sending',
        reactions: [],
    };
    addMessageToUI(message);
    
    // v3.11.10: E2EE encrypt poll message (fail-closed)
    let pollEncPayload;
    let pollSkd = null;
    try {
        if (state.e2eeReady) {
            if (chat.isGroup) {
                const result = await VibeCrypto.encryptGroupMessage(chat.id, text);
                pollEncPayload = result.payload;
                pollSkd = result.distribution;
            } else {
                try {
                    pollEncPayload = await VibeCrypto.encryptMessage(chat.id, text);
                } catch (e) {
                    const kb = await fetchKeyBundle(chat.id);
                    if (kb) {
                        pollEncPayload = await VibeCrypto.encryptMessage(chat.id, text, kb);
                    } else {
                        const recipientName = chat.displayName || chat.username || chat.id;
                        const confirmed = await showUnencryptedConfirmDialog(recipientName);
                        if (!confirmed) {
                            removeMessageFromChat(clientMessageId);
                            return;
                        }
                        pollEncPayload = btoa(unescape(encodeURIComponent(text)));
                    }
                }
            }
        } else {
            console.error("[E2EE] Encryption not initialized for poll");
            showEncryptionFailedError("End-to-end encryption is not initialized. Please reload the page or re-login.");
            removeMessageFromChat(clientMessageId);
            return;
        }
    } catch (e) {
        console.error("[E2EE] Poll encryption failed:", e);
        showEncryptionFailedError("Poll encryption failed. Message was NOT sent.");
        removeMessageFromChat(clientMessageId);
        return;
    }

    const payload = {
        encrypted_payload: pollEncPayload,
        client_message_id: clientMessageId
    };

    if (chat.isGroup) {
        payload.group_id = chat.id;
        if (pollSkd) payload.sender_key_distribution = await encryptDistributionForMembers(chat.id, pollSkd);  // КАО#100
    } else {
        payload.recipient_id = chat.id;
    }
    
    try {
        const response = await api('/messages/send', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            const msg = await response.json();
            // Update message with server ID
            updateMessageWithServerId(clientMessageId, msg.id, msg.status);
            // Link poll to message
            await api(`/polls/${pollId}/message?message_id=${msg.id}`, { method: 'PUT' });
        } else {
            updateMessageStatus(clientMessageId, 'failed');
        }
    } catch (e) {
        console.error('Send poll message error:', e);
        updateMessageStatus(clientMessageId, 'failed');
    }
}

function renderPollInMessage(text, messageElement) {
    const pollMatch = text.match(/\[poll:([a-fA-F0-9-]+)\]/);
    if (!pollMatch) return text;
    
    const pollId = pollMatch[1];
    const cleanText = text.replace(/\[poll:[a-fA-F0-9-]+\]/, '').trim();
    
    // Load and render poll
    loadPoll(pollId, messageElement);
    
    return cleanText;
}

async function loadPoll(pollId, container) {
    try {
        const response = await api(`/polls/${pollId}`);
        if (response.status === 404) {
            // Poll was deleted - show placeholder
            const placeholder = document.createElement('div');
            placeholder.className = 'poll-deleted';
            placeholder.innerHTML = '<span style="color: #888; font-style: italic;">🗑️ Poll deleted</span>';
            const msgContent = container.querySelector('.message-text') || container.querySelector('.message-content');
            if (msgContent) {
                msgContent.appendChild(placeholder);
            }
            return;
        }
        if (!response.ok) return;
        
        const poll = await response.json();
        await decryptPollFields(poll);  // КАО#230 (SER#18)
        pollCache[pollId] = poll; // Cache the poll
        renderPoll(poll, container);
    } catch (e) {
        console.error('Load poll error:', e);
    }
}

// КАО#230 (SER#18): decrypt E2EE poll fields in place using the cached per-poll key.
// Legacy plaintext polls (fields without the "e2e:" prefix) are left untouched. When the key
// is missing (e.g. the announce message hasn't been processed yet) encrypted fields render as a
// lock placeholder; a later poll fetch/update re-decrypts once the key is available. Idempotent.
async function decryptPollFields(poll) {
    if (!poll) return poll;
    const key = state.pollKeys[poll.id];
    const dec = async (v) => {
        if (typeof v !== 'string' || !v.startsWith('e2e:')) return v;  // legacy plaintext or already decrypted
        if (!key) return '🔒';
        try { return await VibeCrypto.decryptWithKey(v.slice(4), key); }
        catch (e) { console.error('[poll] field decrypt failed', e); return '🔒'; }
    };
    if (poll.question) poll.question = await dec(poll.question);
    if (Array.isArray(poll.options)) {
        for (let i = 0; i < poll.options.length; i++) poll.options[i] = await dec(poll.options[i]);
    }
    if (Array.isArray(poll.results)) {
        for (const r of poll.results) r.text = await dec(r.text);
    }
    return poll;
}

function renderPoll(poll, container) {
    const pollDiv = document.createElement('div');
    pollDiv.className = 'poll-container';
    pollDiv.dataset.pollId = poll.id;
    
    // Parse expires_at as UTC (server sends UTC without 'Z')
    let expiresDate = null;
    if (poll.expires_at) {
        const expiresStr = poll.expires_at.endsWith('Z') ? poll.expires_at : poll.expires_at + 'Z';
        expiresDate = new Date(expiresStr);
    }
    const isExpired = expiresDate && expiresDate < new Date();
    const isClosed = poll.is_closed || isExpired;
    
    let statusText = '';
    if (poll.is_closed) {
        statusText = '🔒 Closed';
    } else if (expiresDate) {
        if (isExpired) {
            statusText = '⏰ Expired';
        } else {
            const remaining = formatTimeRemaining(expiresDate);
            statusText = `⏰ ${remaining}`;
        }
    }
    
    let optionsHtml = '';
    for (const result of poll.results) {
        const isSelected = poll.user_selections && poll.user_selections.includes(result.index);
        const barWidth = Math.max(result.percentage, 0);
        
        optionsHtml += `
            <div class="poll-option ${isSelected ? 'selected' : ''} ${isClosed ? 'disabled' : ''}" 
                 onclick="${isClosed ? '' : `votePoll('${poll.id}', ${result.index}, ${poll.is_multiple})`}">
                <div class="poll-option-bar" style="width: ${barWidth}%"></div>
                <div class="poll-option-content">
                    <span class="poll-option-text">${escapeHtml(result.text)}</span>
                    <span class="poll-option-stats">
                        ${result.votes} (${result.percentage}%)
                        ${!poll.is_anonymous && result.voters && result.voters.length > 0 ? `<span class="voters-hint" onclick="showVoters('${poll.id}', ${result.index})" title="${escapeHtml(/*КАО#004*/ getVoterNames(result.voters).join(', '))}">👥</span>` : ''}
                    </span>
                </div>
                ${isSelected ? '<span class="poll-check">✓</span>' : ''}
            </div>
        `;
    }
    
    pollDiv.innerHTML = `
        <div class="poll-header">
            <span class="poll-type">${poll.is_anonymous ? '🔒 Anonymous' : '👁 Public'} ${poll.is_multiple ? '• Multiple choice' : ''}</span>
            ${statusText ? `<span class="poll-status">${statusText}</span>` : ''}
        </div>
        <div class="poll-options">${optionsHtml}</div>
        <div class="poll-footer">
            <span class="poll-total">${poll.total_votes} ${poll.total_votes === 1 ? 'vote' : 'votes'}</span><!-- КАО#22 Round-2: English plural, not the Russian-grammar pluralize() -->
            ${poll.user_voted && !isClosed ? `<button class="poll-retract" onclick="retractVote('${poll.id}')">Retract vote</button>` : ''}
            ${poll.creator_id === state.user?.id && !isClosed ? `<button class="poll-close" onclick="closePoll('${poll.id}')">Close poll</button>` : ''}
        </div>
    `;
    
    // Find message content area and append
    const msgContent = container.querySelector('.message-text') || container.querySelector('.message-content');
    if (msgContent) {
        msgContent.appendChild(pollDiv);
    } else {
        container.appendChild(pollDiv);
    }
    
    // Scroll to bottom after poll renders
    scrollToBottom();
}

function scrollToBottom() {
    setTimeout(() => {
        const messagesContainer = document.getElementById('messages');
        if (messagesContainer) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }, 50);
}

/**
 * Get display names for voter user IDs
 */
function getVoterNames(voterIds) {
    if (!voterIds || !Array.isArray(voterIds)) return [];
    
    const chat = state.currentChat;
    if (!chat) return voterIds;
    
    return voterIds.map(id => {
        // For groups, look in membersCache
        if (chat.isGroup && chat.membersCache) {
            const member = chat.membersCache.find(m => m.user_id === id);
            if (member) return member.display_name || member.username;
        }
        // For direct chats
        if (chat.id === id) {
            return chat.displayName || chat.username;
        }
        // Current user
        if (state.user && state.user.id === id) {
            return state.user.display_name || state.user.username || 'You';
        }
        // Try to find in chats
        const userChat = state.chats[id];
        if (userChat) {
            return userChat.displayName || userChat.username;
        }
        return id.substring(0, 8) + '...';
    });
}

/**
 * Show modal with voters list
 */
function showVoters(pollId, optionIndex) {
    const poll = pollCache[pollId];
    if (!poll) return;
    
    const result = poll.results.find(r => r.index === optionIndex);
    if (!result || !result.voters) return;
    
    const names = getVoterNames(result.voters);
    // КАО#298: was a raw blocking alert() — the last one left after the app moved to showAlert/showConfirm/
    // showToast. Use the app dialog so it is styled, Escape-closable and focus-trapped like everything else.
    showAlert(names.join('\n'), `Voted for "${result.text}"`, '📊');
}

function formatTimeRemaining(date) {
    const now = new Date();
    const diff = date - now;
    if (diff <= 0) return 'Expired';
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    if (hours > 24) {
        const days = Math.floor(hours / 24);
        return `${days}d`;
    } else if (hours > 0) {
        return `${hours}h ${minutes}m`;
    } else {
        return `${minutes}m`;
    }
}

function pluralize(n, one, few, many) {
    const mod10 = n % 10;
    const mod100 = n % 100;
    
    if (mod100 >= 11 && mod100 <= 19) return many;
    if (mod10 === 1) return one;
    if (mod10 >= 2 && mod10 <= 4) return few;
    return many;
}

async function votePoll(pollId, optionIndex, isMultiple) {
    const pollContainer = document.querySelector(`.poll-container[data-poll-id="${pollId}"]`);
    if (!pollContainer) return;
    
    // Ensure optionIndex is a number
    optionIndex = parseInt(optionIndex, 10);
    
    let selectedOptions = [optionIndex];
    
    if (isMultiple) {
        // Get current user selections from cache
        const cachedPoll = pollCache[pollId];
        const currentSelections = (cachedPoll?.user_selections || []).map(i => parseInt(i, 10));
        
        console.log('votePoll debug:', { pollId, optionIndex, currentSelections, isMultiple });
        
        // Toggle current option
        if (currentSelections.includes(optionIndex)) {
            // Remove this option
            selectedOptions = currentSelections.filter(i => i !== optionIndex);
            console.log('Removing option, new selections:', selectedOptions);
        } else {
            // Add this option to existing selections
            selectedOptions = [...currentSelections, optionIndex];
            console.log('Adding option, new selections:', selectedOptions);
        }
        
        // If no options selected, retract vote instead
        if (selectedOptions.length === 0) {
            console.log('No options left, retracting vote');
            await retractVote(pollId);
            return;
        }
    }
    
    try {
        const response = await api(`/polls/${pollId}/vote`, {
            method: 'POST',
            body: JSON.stringify({ selected_options: selectedOptions })
        });
        
        if (response.ok) {
            const poll = await response.json();
            await decryptPollFields(poll);  // КАО#230 (SER#18)
            // Update cache
            pollCache[pollId] = poll;
            console.log('Poll updated, user_selections:', poll.user_selections);
            // Re-render poll - find the message element first before removing container
            const msgElement = pollContainer.closest('.message');
            pollContainer.remove();
            if (msgElement) {
                renderPoll(poll, msgElement);
            }
        } else {
            const error = await response.json().catch(() => ({}));
            showToast(error.detail || 'Failed to vote');  // КАО#136: was raw alert (hard-coded RU)
        }
    } catch (e) {
        console.error('Vote error:', e);
        showToast('Failed to vote');  // КАО#136: was a silent catch (no user feedback)
    }
}

async function retractVote(pollId) {
    try {
        const response = await api(`/polls/${pollId}/vote`, { method: 'DELETE' });
        if (response.ok) {
            // Reload poll
            const pollContainer = document.querySelector(`.poll-container[data-poll-id="${pollId}"]`);
            if (pollContainer) {
                const msgElement = pollContainer.closest('.message');
                pollContainer.remove();
                await loadPoll(pollId, msgElement);
            }
        }
    } catch (e) {
        console.error('Retract vote error:', e);
    }
}

async function closePoll(pollId) {
    const confirmed = await showConfirm(
        'The poll will be closed and voting will end.',
        'Close Poll?',
        'Close',
        'Cancel'
    );
    if (!confirmed) return;
    
    try {
        const response = await api(`/polls/${pollId}/close`, { method: 'POST' });
        if (response.ok) {
            const poll = await response.json();
            await decryptPollFields(poll);  // КАО#230 (SER#18)
            // Update cache
            pollCache[pollId] = poll;
            const pollContainer = document.querySelector(`.poll-container[data-poll-id="${pollId}"]`);
            if (pollContainer) {
                const msgElement = pollContainer.closest('.message');
                pollContainer.remove();
                renderPoll(poll, msgElement);
            }
        }
    } catch (e) {
        console.error('Close poll error:', e);
    }
}

// ==================== FAVORITES ====================

async function toggleFavorite(messageId, senderId, senderName, previewText) {
    try {
        // Check if already favorited
        const checkResponse = await api(`/favorites/check/${messageId}`);
        const checkData = await checkResponse.json();
        
        if (checkData.is_favorite) {
            // Remove from favorites
            await api(`/favorites/${messageId}`, { method: 'DELETE' });
            state.favoriteMessageIds.delete(messageId);  // v3.8.37: Update state
            showToast('Removed from favorites');
            renderMessages();  // v3.8.37: Re-render to remove star
        } else {
            // Add to favorites
            const chat = state.currentChat;
            await api('/favorites', {
                method: 'POST',
                body: JSON.stringify({
                    message_id: messageId,
                    chat_id: chat && !chat.isGroup ? chat.id : null,
                    group_id: chat && chat.isGroup ? chat.id : null,
                    sender_id: senderId,
                    sender_name: senderName,
                    // КАО#162 + #231: strip poll markers (never store the [pollkey:] content key) then
                    // encrypt the preview for self so the server never stores plaintext.
                    preview_text: await (async () => {
                        let pv = (previewText || '').replace(/\s*\[poll:[a-fA-F0-9-]+\]/g, '').replace(/\s*\[pollkey:[^\]\s]*\]/g, '').trim();
                        if (!pv) return '[Media]';
                        if (state.e2eeReady) {
                            // Round-3: never store plaintext when E2EE is on (was `pv || previewText`, which could
                            // return the UNSTRIPPED original). Use ciphertext, or '[Media]' if the self-key is unavailable.
                            try { const e = await VibeCrypto.encryptForSelf(pv); return e || '[Media]'; } catch (err) { return '[Media]'; }
                        }
                        return '[Media]';  // КАО#273 (#39): fail-closed — no plaintext preview to the server when E2EE isn't ready
                    })()
                })
            });
            state.favoriteMessageIds.add(messageId);  // v3.8.37: Update state
            showToast('Added to favorites ⭐');
            renderMessages();  // v3.8.37: Re-render to show star
        }
        
        hideMessageMenu();
    } catch (e) {
        console.error('Toggle favorite error:', e);
    }
}

function showFavoritesPanel() {
    closeSidePanels();
    
    const panel = document.createElement('div');
    panel.className = 'side-panel favorites-panel';
    panel.id = 'favorites-panel';
    panel.innerHTML = `
        <div class="panel-header">
            <button class="back-btn" onclick="closeFavoritesPanel()">←</button>
            <h3>⭐ Favorites</h3>
        </div>
        <div class="panel-content" id="favorites-list">
            <div class="loading">Loading...</div>
        </div>
    `;
    
    document.getElementById('app').appendChild(panel);
    setTimeout(() => panel.classList.add('open'), 10);
    
    loadFavorites();
}

function closeFavoritesPanel() {
    const panel = document.getElementById('favorites-panel');
    if (panel) {
        panel.classList.remove('open');
        panel.remove();  // v3.8.39: Remove immediately to avoid duplicate panels
    }
}

function closeSidePanels() {
    closeFavoritesPanel();
    closeExportPanel();
}

async function loadFavorites() {
    const container = document.getElementById('favorites-list');
    if (!container) return;
    
    try {
        const response = await api('/favorites?limit=100');
        if (!response.ok) throw new Error('Failed to load');
        
        const favorites = await response.json();
        
        if (favorites.length === 0) {
            container.innerHTML = '<div class="empty-state">No favorites yet</div>';
            return;
        }

        // КАО#162: decrypt self-encrypted previews (legacy plaintext previews shown as-is)
        for (const fav of favorites) {
            if (fav.preview_text && state.e2eeReady) {
                try { fav.preview_text = await VibeCrypto.decryptForSelf(fav.preview_text); } catch (e) {}
            }
        }

        container.innerHTML = favorites.map(fav => `
            <div class="favorite-item" onclick="goToFavoriteMessage('${fav.message_id}', '${fav.chat_id || ''}', '${fav.group_id || ''}')">
                <div class="favorite-header">
                    <span class="favorite-sender">${escapeHtml(fav.sender_name || 'Unknown')}</span>
                    <span class="favorite-date">${formatDate(fav.created_at)}</span>
                </div>
                <div class="favorite-preview">${escapeHtml(fav.preview_text || '...')}</div>
                <button class="favorite-remove" onclick="event.stopPropagation(); removeFavorite('${fav.message_id}')">×</button>
            </div>
        `).join('');
    } catch (e) {
        console.error('Load favorites error:', e);
        container.innerHTML = '<div class="error">Loading error</div>';
    }
}

async function removeFavorite(messageId) {
    try {
        await api(`/favorites/${messageId}`, { method: 'DELETE' });
        loadFavorites();
    } catch (e) {
        console.error('Remove favorite error:', e);
    }
}

async function goToFavoriteMessage(messageId, chatId, groupId) {
    closeFavoritesPanel();
    
    // Open the chat
    if (groupId) {
        await openChat(groupId, true);
    } else if (chatId) {
        await openChat(chatId, false);
    }
    
    // Scroll to message with highlight
    setTimeout(() => {
        const msgElement = document.querySelector(`[data-message-id="${messageId}"]`);
        if (msgElement) {
            msgElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            msgElement.classList.add('highlight');
            setTimeout(() => msgElement.classList.remove('highlight'), 2000);
        }
    }, 500);
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now - date;
    
    // КАО#22 Round-2: use the browser's locale (was hard-coded 'ru-RU' → Russian timestamps in an en app)
    if (diff < 86400000) { // Less than 1 day
        return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    } else if (diff < 604800000) { // Less than 1 week
        return date.toLocaleDateString(undefined, { weekday: 'short' });
    } else {
        return date.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
    }
}

// ==================== EXPORT ====================

function showExportModal() {
    const chat = state.currentChat;
    
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'export-modal';
    modal.innerHTML = `
        <div class="modal export-modal">
            <div class="modal-header">
                <h3>📤 Export chat</h3>
                <button class="modal-close" onclick="closeExportModal()">×</button>
            </div>
            <div class="modal-body">
                <div class="export-target">
                    <label class="radio-label">
                        <input type="radio" name="export-target" value="current" checked>
                        Current chat${chat ? ` (${escapeHtml(chat.name || chat.username || 'Chat')})` : ''}
                    </label>
                    <label class="radio-label">
                        <input type="radio" name="export-target" value="all">
                        All chats
                    </label>
                </div>
                <div class="form-group">
                    <label>Format</label>
                    <select id="export-format">
                        <option value="json">JSON (data)</option>
                        <option value="html">HTML (readable)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="export-media">
                        Include file info
                    </label>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeExportModal()">Cancel</button>
                <button class="btn btn-primary" onclick="doExport()">Export</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function closeExportModal() {
    const modal = document.getElementById('export-modal');
    if (modal) modal.remove();
}

function closeExportPanel() {
    // Reserved for future panel implementation
}

async function doExport() {
    const target = document.querySelector('input[name="export-target"]:checked').value;
    const format = document.getElementById('export-format').value;
    const includeMedia = document.getElementById('export-media').checked;
    
    const chat = state.currentChat;
    
    let url;
    if (target === 'all') {
        url = '/export/all';
    } else if (chat) {
        if (chat.isGroup) {
            url = `/export/group/${chat.id}`;
        } else {
            url = `/export/chat/${chat.id}`;
        }
    } else {
        alert('Select a chat to export');
        return;
    }
    
    try {
        const response = await api(url, {
            method: 'POST',
            body: JSON.stringify({
                format: format,
                include_media: includeMedia
            })
        });
        
        if (response.ok) {
            // Get filename from headers
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = `export_${Date.now()}.${format}`;
            if (contentDisposition) {
                const match = contentDisposition.match(/filename="?([^"]+)"?/);
                if (match) filename = match[1];
            }
            
            // Download file
            const blob = await response.blob();
            const downloadUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(downloadUrl);
            
            closeExportModal();
            showToast('Export complete ✓');
        } else {
            const error = await response.json();
            alert(error.detail || 'Export failed');
        }
    } catch (e) {
        console.error('Export error:', e);
        alert('Export failed');
    }
}

// КАО#282 (#14): announce transient messages to assistive tech via a persistent live region —
// previously toasts/errors/status updates were invisible to screen readers (no aria-live anywhere).
function announceA11y(message, assertive) {
    try {
        const id = assertive ? 'a11y-alert' : 'a11y-status';
        let region = document.getElementById(id);
        if (!region) {
            region = document.createElement('div');
            region.id = id;
            region.setAttribute('aria-live', assertive ? 'assertive' : 'polite');
            region.setAttribute('role', assertive ? 'alert' : 'status');
            region.setAttribute('aria-atomic', 'true');
            region.style.cssText = 'position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;';
            document.body.appendChild(region);
        }
        region.textContent = '';
        setTimeout(() => { region.textContent = message; }, 50);  // re-announce identical consecutive messages
    } catch (e) {}
}

function showToast(message) {
    announceA11y(message);  // КАО#282 (#14)
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// ============================================================
// v3.6.0 FEATURES: Link Preview, Media Gallery, Drafts, Mute, Block
// ============================================================

// Helper function to get current chat
function getCurrentChat() {
    if (!state.currentChatId) return null;
    return state.chats[state.currentChatId] || null;
}

// ==================== 1. LINK PREVIEW ====================

const linkPreviewCache = {};

function extractUrls(text) {
    // Match URLs in text
    const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
    return text.match(urlRegex) || [];
}

async function fetchLinkPreview(url) {
    // Check cache
    if (linkPreviewCache[url]) {
        return linkPreviewCache[url];
    }
    
    try {
        const response = await api('/preview?url=' + encodeURIComponent(url));
        if (response.ok) {
            const data = await response.json();
            linkPreviewCache[url] = data;
            return data;
        }
    } catch (e) {
        console.log('Link preview failed:', e);
    }
    return null;
}

function renderLinkPreview(preview) {
    if (!preview || (!preview.title && !preview.description && !preview.image)) {
        return '';
    }
    
    const domain = new URL(preview.url).hostname;
    
    let html = '<a href="' + escapeHtml(preview.url) + '" target="_blank" rel="noopener" class="link-preview">';
    
    if (preview.image) {
        html += '<div class="link-preview-image">';
        html += '<img src="' + escapeHtml(preview.image) + '" alt="" onerror="this.parentElement.style.display=\'none\'">';
        html += '</div>';
    }
    
    html += '<div class="link-preview-content">';
    
    if (preview.site_name || domain) {
        html += '<div class="link-preview-site">';
        if (preview.favicon) {
            html += '<img src="' + escapeHtml(preview.favicon) + '" class="link-preview-favicon" onerror="this.style.display=\'none\'">';
        }
        html += '<span>' + escapeHtml(preview.site_name || domain) + '</span>';
        html += '</div>';
    }
    
    if (preview.title) {
        html += '<div class="link-preview-title">' + escapeHtml(preview.title) + '</div>';
    }
    
    if (preview.description) {
        const desc = preview.description.length > 150 ? preview.description.substring(0, 147) + '...' : preview.description;
        html += '<div class="link-preview-desc">' + escapeHtml(desc) + '</div>';
    }
    
    html += '</div></a>';
    
    return html;
}

// Modify message rendering to include link previews
async function addLinkPreviewsToMessage(messageEl, text) {
    const urls = extractUrls(text);
    if (urls.length === 0) return;

    // Only preview first URL
    const url = urls[0];
    const container = messageEl.querySelector('.message-text');
    if (!container) return;

    // КАО#276 (#17): CLICK-TO-LOAD. Do NOT auto-fetch — auto-previewing would send every URL contained
    // in an end-to-end-encrypted message to the server (zero-knowledge break). Render the preview only
    // if it's already cached this session; otherwise show an opt-in button the user taps to load it.
    if (linkPreviewCache[url]) {
        const html = renderLinkPreview(linkPreviewCache[url]);
        if (html) container.insertAdjacentHTML('afterend', html);
        return;
    }

    const btn = document.createElement('button');
    btn.className = 'link-preview-load-btn';
    btn.type = 'button';
    btn.textContent = '🔗 Load link preview';
    btn.setAttribute('aria-label', 'Load link preview (sends the link to the server)');
    btn.title = url;
    btn.onclick = async () => {
        btn.disabled = true;
        btn.textContent = 'Loading…';
        const preview = await fetchLinkPreview(url);
        const html = preview ? renderLinkPreview(preview) : '';
        if (html) {
            btn.insertAdjacentHTML('afterend', html);
            btn.remove();
        } else {
            btn.textContent = 'Preview unavailable';
            btn.disabled = true;
        }
    };
    container.insertAdjacentElement('afterend', btn);
}

// ==================== 2. MEDIA GALLERY ====================

let galleryMedia = [];
let currentGalleryType = 'images';
let lightboxIndex = 0;

function showMediaGallery() {
    const chat = getCurrentChat();
    if (!chat) return;
    
    document.getElementById('media-gallery-modal').classList.remove('hidden');
    loadMediaGallery(chat);
}

function closeMediaGallery() {
    document.getElementById('media-gallery-modal').classList.add('hidden');
}

function loadMediaGallery(chat) {
    galleryMedia = [];
    
    // Collect all media from messages
    const messages = chat.messages || [];
    
    messages.forEach(msg => {
        if (msg.file) {
            regFileKey(msg.file);  // КАО#090: ensure at-rest key registered for gallery media
            const ext = (msg.file.extension || msg.file.filename?.split('.').pop() || '').toLowerCase();
            const isImage = ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext);
            const isVideo = ['mp4', 'webm', 'mov'].includes(ext);
            
            galleryMedia.push({
                id: msg.file.file_id || msg.file.id,
                filename: msg.file.original_filename || msg.file.filename,
                extension: ext,
                type: isImage ? 'images' : (isVideo ? 'videos' : 'files'),
                timestamp: msg.created_at,
                messageId: msg.id
            });
        }
    });
    
    // Sort by date (newest first)
    galleryMedia.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    filterGallery('images');
}

function filterGallery(type) {
    currentGalleryType = type;
    
    // Update tabs
    document.querySelectorAll('.gallery-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.type === type);
    });
    
    const filtered = galleryMedia.filter(m => m.type === type);
    const grid = document.getElementById('media-gallery-grid');
    
    if (filtered.length === 0) {
        const labels = { images: 'photos', videos: 'videos', files: 'files' };
        grid.innerHTML = '<p class="gallery-empty">No ' + labels[type] + '</p>';
        return;
    }
    
    if (type === 'files') {
        // List view for files
        grid.innerHTML = filtered.map((m, idx) => `
            <div class="gallery-file" onclick="downloadFile('${safeOnclickArg(/*КАО#005*/ m.id)}', '${safeOnclickArg(m.filename)}')">
                <span class="gallery-file-icon">📄</span>
                <span class="gallery-file-name">${escapeHtml(m.filename)}</span>
            </div>
        `).join('');
    } else {
        // Grid view for images/videos
        grid.innerHTML = filtered.map((m, idx) => {
            if (type === 'images') {
                return `<div class="gallery-item" onclick="openLightbox(${idx})">
                    <img data-fileid="${escapeHtml(m.id)}" alt="${escapeHtml(m.filename)}" loading="lazy">
                </div>`;
            } else {
                return `<div class="gallery-item gallery-video" onclick="openLightbox(${idx})">
                    <video data-fileid="${escapeHtml(m.id)}" preload="metadata"></video>
                    <span class="gallery-play-icon">▶</span>
                </div>`;
            }
        }).join('');
        // КАО#090: load thumbnails via fetch+decrypt (also fixes the missing auth header)
        grid.querySelectorAll('[data-fileid]').forEach(el => {
            fetchFileBlob(el.getAttribute('data-fileid'))
                .then(b => { el.src = URL.createObjectURL(b); })
                .catch(e => console.error('[at-rest] gallery media load failed', e));
        });
    }
}

function openLightbox(index) {
    const filtered = galleryMedia.filter(m => m.type === currentGalleryType);
    if (filtered.length === 0) return;
    
    lightboxIndex = index;
    showLightboxItem(filtered[index]);
    
    document.getElementById('lightbox-counter').textContent = (index + 1) + ' / ' + filtered.length;
    document.getElementById('media-lightbox').classList.remove('hidden');
}

function closeLightbox() {
    document.getElementById('media-lightbox').classList.add('hidden');
    const video = document.getElementById('lightbox-video');
    video.pause();
    video.src = '';
}

function showLightboxItem(item) {
    const img = document.getElementById('lightbox-image');
    const video = document.getElementById('lightbox-video');
    
    if (item.type === 'images') {
        fetchFileBlob(item.id).then(b => { img.src = URL.createObjectURL(b); }).catch(e => console.error('[at-rest] lightbox img', e));  // КАО#090
        img.style.display = 'block';
        video.style.display = 'none';
        video.pause();
    } else {
        fetchFileBlob(item.id).then(b => { video.src = URL.createObjectURL(b); }).catch(e => console.error('[at-rest] lightbox video', e));  // КАО#090
        video.style.display = 'block';
        img.style.display = 'none';
    }
}

function lightboxPrev() {
    const filtered = galleryMedia.filter(m => m.type === currentGalleryType);
    lightboxIndex = (lightboxIndex - 1 + filtered.length) % filtered.length;
    showLightboxItem(filtered[lightboxIndex]);
    document.getElementById('lightbox-counter').textContent = (lightboxIndex + 1) + ' / ' + filtered.length;
}

function lightboxNext() {
    const filtered = galleryMedia.filter(m => m.type === currentGalleryType);
    lightboxIndex = (lightboxIndex + 1) % filtered.length;
    showLightboxItem(filtered[lightboxIndex]);
    document.getElementById('lightbox-counter').textContent = (lightboxIndex + 1) + ' / ' + filtered.length;
}

// Keyboard navigation for lightbox
document.addEventListener('keydown', function(e) {
    if (document.getElementById('media-lightbox').classList.contains('hidden')) return;
    
    if (e.key === 'Escape') closeLightbox();
    else if (e.key === 'ArrowLeft') lightboxPrev();
    else if (e.key === 'ArrowRight') lightboxNext();
});

// ==================== 3. DRAFTS (Черновики) ====================

function saveDraft(chatId, text) {
    if (!chatId || !state.user) return;
    
    const key = 'draft_' + state.user.id + '_' + chatId;
    
    if (text && text.trim()) {
        localStorage.setItem(key, text);
    } else {
        localStorage.removeItem(key);
    }
}

function loadDraft(chatId) {
    if (!chatId || !state.user) return '';
    
    const key = 'draft_' + state.user.id + '_' + chatId;
    return localStorage.getItem(key) || '';
}

function clearDraft(chatId) {
    if (!chatId || !state.user) return;
    
    const key = 'draft_' + state.user.id + '_' + chatId;
    localStorage.removeItem(key);
}

// Auto-save draft on input
function initDrafts() {
    const input = document.getElementById('message-text');
    if (!input) return;
    
    let draftTimeout = null;
    
    input.addEventListener('input', function() {
        if (draftTimeout) clearTimeout(draftTimeout);
        
        draftTimeout = setTimeout(() => {
            const chatId = state.currentChatId;
            if (chatId) {
                saveDraft(chatId, input.value);
            }
        }, 500); // Save after 500ms of no typing
    });
}

// ==================== 4. MUTE CHATS ====================

let mutedChats = {};

async function loadMutedChats() {
    try {
        const response = await api('/settings/muted');
        if (response.ok) {
            const data = await response.json();
            mutedChats = {};
            data.muted_chats.forEach(mc => {
                mutedChats[mc.chat_id] = mc.muted_until;
            });
            updateMuteButton();
        }
    } catch (e) {
        console.error('Failed to load muted chats:', e);
    }
}

function isChatMuted(chatId) {
    if (!mutedChats[chatId]) return false;
    
    const mutedUntil = mutedChats[chatId];
    if (mutedUntil === null) return true; // Forever
    
    return new Date(mutedUntil) > new Date();
}

async function toggleMuteChat() {
    const chatId = state.currentChatId;
    if (!chatId) return;
    
    const isMuted = isChatMuted(chatId);
    
    try {
        if (isMuted) {
            // Unmute
            await api('/settings/mute/' + chatId, { method: 'DELETE' });
            delete mutedChats[chatId];
            showToast('Notifications enabled 🔔');
        } else {
            // Show mute options
            showMuteOptions(chatId);
            return;
        }
        
        updateMuteButton();
    } catch (e) {
        console.error('Mute toggle failed:', e);
    }
}

function showMuteOptions(chatId) {
    const options = [
        { label: '1 hour', hours: 1 },
        { label: '8 hours', hours: 8 },
        { label: '1 day', hours: 24 },
        { label: '1 week', hours: 168 },
        { label: 'Forever', hours: null }
    ];
    
    // Create simple popup
    const popup = document.createElement('div');
    popup.className = 'mute-popup';
    popup.innerHTML = `
        <div class="mute-popup-title">Mute for:</div>
        ${options.map(opt => `
            <button class="mute-popup-option" onclick="muteChat('${chatId}', ${opt.hours})">${opt.label}</button>
        `).join('')}
        <button class="mute-popup-cancel" onclick="this.parentElement.remove()">Cancel</button>
    `;
    
    document.body.appendChild(popup);
    
    // Position near button
    const btn = document.getElementById('mute-btn');
    const rect = btn.getBoundingClientRect();
    popup.style.position = 'fixed';
    popup.style.top = (rect.bottom + 5) + 'px';
    popup.style.right = (window.innerWidth - rect.right) + 'px';
    
    // Close on outside click
    setTimeout(() => {
        document.addEventListener('click', function closePopup(e) {
            if (!popup.contains(e.target) && e.target !== btn) {
                popup.remove();
                document.removeEventListener('click', closePopup);
            }
        });
    }, 100);
}

async function muteChat(chatId, hours) {
    try {
        const response = await api('/settings/mute', {
            method: 'POST',
            body: JSON.stringify({ chat_id: chatId, duration_hours: hours })
        });
        
        if (response.ok) {
            const data = await response.json();
            mutedChats[chatId] = data.muted_until;
            updateMuteButton();
            showToast('Notifications disabled 🔕');
        }
    } catch (e) {
        console.error('Mute failed:', e);
    }
    
    // Close popup
    document.querySelector('.mute-popup')?.remove();
}

function updateMuteButton() {
    const btn = document.getElementById('mute-btn');
    if (!btn) return;
    
    const chatId = state.currentChatId;
    const isMuted = chatId && isChatMuted(chatId);
    
    btn.textContent = isMuted ? '🔕' : '🔔';
    btn.title = isMuted ? 'Enable notifications' : 'Mute chat';
}

// Override notification functions to respect mute
const originalPlayNotificationSound = typeof playNotificationSound === 'function' ? playNotificationSound : null;

function playNotificationSoundWithMuteCheck() {
    if (state.currentChatId && isChatMuted(state.currentChatId)) {
        return; // Don't play sound for muted chat
    }
    if (originalPlayNotificationSound) {
        originalPlayNotificationSound();
    }
}

// ==================== 5. BLOCK USERS ====================

let blockedUsers = [];
let currentProfileUserId = null;

async function loadBlockedUsers() {
    try {
        const response = await api('/settings/blocked');
        if (response.ok) {
            const data = await response.json();
            blockedUsers = data.blocked_users || [];
        }
    } catch (e) {
        console.error('Failed to load blocked users:', e);
    }
}

function isUserBlocked(userId) {
    return blockedUsers.includes(userId);
}

function showUserProfile(userId, userName, avatarUrl) {
    currentProfileUserId = userId;
    
    const avatarEl = document.getElementById('profile-avatar');
    const nameEl = document.getElementById('profile-name');
    const statusEl = document.getElementById('profile-status');
    const blockBtn = document.getElementById('profile-block-btn');
    
    // Отображаем аватар - изображение или первую букву имени
    if (avatarUrl) {
        avatarEl.innerHTML = `<img src="${escapeHtml(avatarUrl)}" alt="${escapeHtml(userName)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`; // КАО#003: escape stored XSS (display_name/avatar)
    } else {
        avatarEl.innerHTML = '';
        avatarEl.textContent = userName ? userName[0].toUpperCase() : 'U';
    }
    
    nameEl.textContent = userName || 'Unknown';
    
    // Запрашиваем статус online/offline
    if (statusEl) {
        statusEl.textContent = 'checking...';
        checkUserOnline(userId).then(isOnline => {
            statusEl.textContent = isOnline ? 'online' : 'offline';
            statusEl.className = 'user-profile-status ' + (isOnline ? 'online' : 'offline');
        }).catch(() => {
            statusEl.textContent = 'offline';
            statusEl.className = 'user-profile-status offline';
        });
    }
    
    const isBlocked = isUserBlocked(userId);
    blockBtn.textContent = isBlocked ? '✅ Unblock' : '🚫 Block';
    blockBtn.className = isBlocked ? 'btn btn-secondary' : 'btn btn-danger';
    
    document.getElementById('user-profile-modal').classList.remove('hidden');
}

function closeUserProfileModal() {
    document.getElementById('user-profile-modal').classList.add('hidden');
    currentProfileUserId = null;
}

async function toggleBlockUser() {
    if (!currentProfileUserId) return;
    
    const isBlocked = isUserBlocked(currentProfileUserId);
    
    try {
        if (isBlocked) {
            // Unblock
            await api('/settings/block/' + currentProfileUserId, { method: 'DELETE' });
            blockedUsers = blockedUsers.filter(id => id !== currentProfileUserId);
            showToast('User unblocked ✓');
        } else {
            // Block
            const response = await api('/settings/block', {
                method: 'POST',
                body: JSON.stringify({ user_id: currentProfileUserId })
            });
            if (response.ok) {
                blockedUsers.push(currentProfileUserId);
                showToast('User blocked 🚫');
            }
        }
        
        // Update button
        const blockBtn = document.getElementById('profile-block-btn');
        const nowBlocked = isUserBlocked(currentProfileUserId);
        blockBtn.textContent = nowBlocked ? '✅ Unblock' : '🚫 Block';
        blockBtn.className = nowBlocked ? 'btn btn-secondary' : 'btn btn-danger';
        
        // v3.6.0: Update messages display to show/hide blocked user messages
        if (state.currentChatId === currentProfileUserId) {
            renderMessages();
        }
        
    } catch (e) {
        console.error('Block toggle failed:', e);
        showToast('Error');
    }
}

function startChatFromProfile() {
    if (!currentProfileUserId) return;
    closeUserProfileModal();
    openChat(currentProfileUserId);
}

// Filter blocked users from message display
function shouldShowMessage(msg) {
    // Don't filter own messages
    if (msg.sender_id === state.user?.id) return true;
    
    // Filter blocked users
    return !isUserBlocked(msg.sender_id);
}

// ==================== INITIALIZATION ====================

// Hook into existing init
const originalInitApp = typeof initApp === 'function' ? initApp : null;

async function initNewFeatures() {
    console.log('Initializing v3.6.1 features...');
    
    // Initialize IndexedDB for offline mode
    const dbInitialized = await offlineDB.init();
    console.log('IndexedDB initialized:', dbInitialized);
    
    // Load message queue (with migration from localStorage if needed)
    await loadMessageQueue();
    
    // Load muted chats
    await loadMutedChats();
    
    // Load blocked users
    await loadBlockedUsers();
    
    // Init drafts
    initDrafts();
    
    // Check for pending messages and show count
    const pendingCount = await offlineDB.getPendingCount();
    if (pendingCount > 0) {
        console.log(`${pendingCount} pending message(s) waiting to sync`);
        // If we're online, try to send them
        if (navigator.onLine) {
            setTimeout(() => sendQueuedMessages(), 2000);
        }
    }
    
    console.log('v3.6.0 features initialized');
    
    // v3.8.26: Add verify keys button to chat header if not exists
    addVerifyKeysButton();
    
    // Clean up old decrypted messages (older than 30 days)
    offlineDB.cleanupOldDecryptedMessages();
}

/**
 * v3.8.26: Add verify keys button to chat header
 */
function addVerifyKeysButton() {
    const exportBtn = document.getElementById('export-btn');
    if (!exportBtn) return;
    
    // Check if button already exists
    if (document.getElementById('verify-keys-btn')) return;
    
    const verifyBtn = document.createElement('button');
    verifyBtn.id = 'verify-keys-btn';
    verifyBtn.className = 'icon-btn';
    verifyBtn.title = 'Verify encryption keys';
    verifyBtn.textContent = '🔑';
    verifyBtn.onclick = openKeyVerification;
    
    // Insert after export button
    exportBtn.parentNode.insertBefore(verifyBtn, exportBtn.nextSibling);
    console.log('[E2EE] Verify keys button added to header');
}

// Call after auth
document.addEventListener('DOMContentLoaded', function() {
    // Will be called after login
    const checkAuth = setInterval(() => {
        if (state.user && state.token) {
            clearInterval(checkAuth);
            initNewFeatures();
        }
    }, 1000);
});

// v3.6.0: Open profile of current chat user (for blocking)
function openCurrentChatProfile() {
    if (!state.currentChatId) return;
    
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    // Don't open profile for groups
    if (chat.isGroup) {
        // For groups, toggle group menu instead
        if (typeof toggleGroupMenu === 'function') {
            toggleGroupMenu();
        }
        return;
    }
    
    // Open user profile modal
    const userId = state.currentChatId;
    const userName = chat.displayName || chat.username || 'Unknown';
    const avatarUrl = chat.avatar_url;
    
    showUserProfile(userId, userName, avatarUrl);
}

// ==================== V3.7.0: LOW PREKEYS HANDLER ====================

/**
 * Handle LOW_PREKEYS notification from server
 * Automatically generates and uploads new OTPs
 */
async function handleLowPrekeys(payload) {
    console.log('[E2EE] LOW_PREKEYS notification:', payload);
    
    // КАО#377: `window.vibeE2EE` is NEVER assigned — the instance is a module-local const inside the
    // vibe-crypto.js IIFE and is exported only as `VibeCrypto.e2ee`. So this guard always took the early
    // return and the server's low_prekeys push was a no-op: once the one-time-prekey pool ran out, every new
    // contact's X3DH proceeded without DH4.
    if (!state.e2eeReady || typeof VibeCrypto === 'undefined' || !VibeCrypto.e2ee) {
        console.warn('[E2EE] Cannot replenish prekeys - E2EE not ready');
        return;
    }

    try {
        // Generate 100 new one-time prekeys
        const newPrekeys = await VibeCrypto.e2ee.generateOneTimePreKeysOnly(100);
        
        // Upload to server
        const response = await api('/keys/bundle/prekeys', {
            method: 'POST',
            body: JSON.stringify(newPrekeys),
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('[E2EE] Prekeys replenished. Total on server:', data.total_prekeys);
        } else {
            console.error('[E2EE] Failed to upload prekeys:', await response.text());
        }
    } catch (e) {
        console.error('[E2EE] Error replenishing prekeys:', e);
    }
}

// ==================== V3.8.6: KEY RESET HANDLING ====================

/**
 * Check if we can encrypt messages to a recipient
 * Returns true if we have a session or can get their key bundle
 */
async function checkCanEncrypt(recipientId) {
    if (!state.e2eeReady || typeof VibeCrypto === 'undefined') {
        return false;
    }
    
    try {
        // Check if we have an existing session
        const hasSession = await VibeCrypto.hasSession(recipientId);
        if (hasSession) {
            return true;
        }
        
        // Try to fetch key bundle
        const keyBundle = await fetchKeyBundle(recipientId);
        return keyBundle !== null;
    } catch (e) {
        console.warn('[E2EE] checkCanEncrypt error:', e);
        return false;
    }
}

/**
 * Show confirmation dialog for sending unencrypted message
 * Returns promise that resolves to true if user confirms, false if cancels
 */
function showUnencryptedConfirmDialog(recipientName) {
    return new Promise((resolve) => {
        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.className = 'e2ee-confirm-overlay';
        // КАО#285: expose as a dialog for screen readers (Escape/Tab handled centrally in initA11yModals)
        overlay.innerHTML = `
            <div class="e2ee-confirm-dialog" role="dialog" aria-modal="true" aria-label="Cannot encrypt message">
                <div class="e2ee-confirm-icon">🔓</div>
                <h3>Cannot encrypt message</h3>
                <p><strong>${escapeHtml(recipientName)}</strong> doesn't have encryption keys or their keys were reset.</p>
                <p class="e2ee-confirm-warning">This message will be sent <strong>without end-to-end encryption</strong> and can be read on the server.</p>
                <div class="e2ee-confirm-buttons">
                    <button class="e2ee-confirm-btn cancel">Cancel</button>
                    <button class="e2ee-confirm-btn send">Send anyway</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        // Handle buttons
        const cancelBtn = overlay.querySelector('.cancel');
        const sendBtn = overlay.querySelector('.send');
        
        cancelBtn.onclick = () => {
            overlay.remove();
            resolve(false);
        };
        
        sendBtn.onclick = () => {
            overlay.remove();
            resolve(true);
        };
        
        // Close on overlay click
        overlay.onclick = (e) => {
            if (e.target === overlay) {
                overlay.remove();
                resolve(false);
            }
        };
        
        // Focus cancel button
        cancelBtn.focus();
    });
}

/**
 * Handle KEY_RESET notification from server
 * Another user has reset their E2EE keys - we need to delete our session with them
 */
async function handleKeyReset(payload) {
    console.log('[E2EE] KEY_RESET notification:', payload);
    
    const userId = payload.user_id;
    const displayName = payload.display_name || payload.username || userId;
    
    if (!userId) {
        console.warn('[E2EE] KEY_RESET missing user_id');
        return;
    }
    
    // Delete local session with this user
    if (state.e2eeReady && typeof VibeCrypto !== 'undefined') {
        try {
            await VibeCrypto.deleteSession(userId);
            console.log('[E2EE] Deleted session with', userId);
        } catch (e) {
            console.warn('[E2EE] Failed to delete session:', e);
        }
    }
    
    // Clear cached key bundle
    if (state.keyBundles) {
        delete state.keyBundles[userId];
    }
    
    // Clear verification status - keys changed, need to re-verify
    if (typeof VibeCryptoVerification !== 'undefined' && state.user) {
        VibeCryptoVerification.clearVerificationStatus(state.user.id, userId);
        console.log('[E2EE] Cleared verification status for', userId);
    }
    
    // v3.11.0: Mark identity key as untrusted instead of deleting
    // This ensures verifyContactIdentityKey detects "changed" (not "isNew") on next chat open
    // and saves the new key as untrusted, so the banner persists until dismissed
    
    // v3.11.6: Store reset timestamp for chronological system message positioning
    localStorage.setItem('vibe_key_reset_time_' + userId, Date.now().toString());
    
    if (knownIdentityKeys[userId]) {
        knownIdentityKeys[userId].trusted = false;
        saveKnownIdentityKey(userId, knownIdentityKeys[userId].identityKey, false);
        console.log('[E2EE] Marked identity key as untrusted for', userId);
    } else {
        // No key in memory yet - save placeholder so verifyContactIdentityKey detects change
        saveKnownIdentityKey(userId, '__key_reset_pending__', false);
        console.log('[E2EE] Saved key reset placeholder for', userId);
    }
    
    // Show notification toast
    showKeyResetNotification(displayName);
    
    // Add system message to chat or queue for later (also queues keyResetPending)
    addKeyResetSystemMessage(userId, displayName);
    
    // v3.8.56: Show verification banner if currently in this chat
    if (state.currentChatId === userId) {
        showIdentityKeyChangedBanner(userId, displayName);
    }
    // Note: if not in chat, banner will be shown by checkPendingKeyReset when chat is opened
    
    console.log('[E2EE] KEY_RESET handling complete');
}

/**
 * Add system message to chat indicating key reset
 */
function addKeyResetSystemMessage(userId, displayName) {
    // If currently viewing this chat, show immediately
    if (state.currentChatId === userId) {
        showKeyResetInChat(displayName);
    } else {
        // Save for when chat is opened
        state.keyResetPending[userId] = displayName;
        console.log('[E2EE] Queued key reset message for', userId);
    }
}

/**
 * Show key reset system message in current chat
 */
function showKeyResetInChat(displayName) {
    const messagesContainer = document.getElementById('messages');
    if (!messagesContainer) return;
    
    // v3.11.0: Prevent duplicate key reset messages in same chat view
    if (messagesContainer.querySelector('.key-reset-message')) return;
    
    const systemMsg = document.createElement('div');
    systemMsg.className = 'system-message key-reset-message';
    systemMsg.innerHTML = `
        <div class="system-message-content">
            <span class="system-message-icon">🔑</span>
            <span class="system-message-text">Security code with <strong>${escapeHtml(displayName)}</strong> changed. Your messages are secured with new encryption keys.</span>
        </div>
    `;
    
    messagesContainer.appendChild(systemMsg);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

/**
 * Show notification that a contact reset their keys
 */
function showKeyResetNotification(displayName) {
    console.log('[E2EE] Showing key reset notification for:', displayName);
    const notification = document.createElement('div');
    notification.className = 'e2ee-warning-toast key-reset-toast';
    notification.innerHTML = `
        <div class="e2ee-warning-content">
            <span class="e2ee-warning-icon">🔑</span>
            <div class="e2ee-warning-text">
                <strong>Encryption keys reset</strong>
                <p>${escapeHtml(displayName)} has reset their encryption keys. Next message will establish a new secure session.</p>
            </div>
            <button class="e2ee-warning-close" onclick="this.parentElement.parentElement.remove()">✕</button>
        </div>
    `;
    document.body.appendChild(notification);
    
    // Auto-remove after 7 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 7000);
}

// ==================== V3.7.0: SIGNED PREKEY ROTATION ====================

/**
 * Check if signed prekey needs rotation (> 7 days old)
 * Called on app startup
 */
async function checkSignedPreKeyRotation() {
    // КАО#377: this guard is DELIBERATELY left on the never-assigned `window.vibeE2EE`, i.e. SPK rotation
    // stays disabled. Flipping it to VibeCrypto.e2ee (the obvious one-line "fix") would enable rotation and
    // immediately detonate a latent protocol bug: the current SPK id is not persisted anywhere, while
    // VibeE2EE.init() reloads it with a HARDCODED `getSignedPreKey(1)`. After one rotation to id 2 plus a
    // page reload the client would run X3DH with the WRONG signed-prekey secret and every INCOMING session
    // would fail to decrypt — worse than the hygiene problem it is meant to solve.
    // Enabling it correctly is a wire-format change on both legs and must be its own piece of work:
    //   1. persist the current SPK id on generate/rotate;
    //   2. load that id in init() instead of the constant 1;
    //   3. send `signed_prekey_id` in the X3DH header;
    //   4. select the SPK by the received id on the receiving side, falling back to the previous one
    //      (getPreviousSignedPreKey, currently unreachable) before failing.
    // Until then the SPK generated at registration is never rotated. That weakens medium-term key hygiene;
    // it does NOT break per-message forward secrecy, which the Double Ratchet provides after session setup.
    if (!state.e2eeReady || !window.vibeE2EE) {
        return;
    }
    
    try {
        // Check bundle status from server
        const response = await api('/keys/bundle/status/me');
        if (!response.ok) {
            console.log('[E2EE] No key bundle on server');
            return;
        }
        
        const status = await response.json();
        console.log('[E2EE] Bundle status:', status);
        
        // Check if SPK needs rotation (>= 7 days)
        if (status.needs_spk_rotation) {
            console.log('[E2EE] Signed prekey needs rotation');
            await rotateSignedPreKey();
        }
        
        // Check if OTPs need replenishment
        if (status.needs_replenishment) {
            console.log('[E2EE] OTPs need replenishment');
            await handleLowPrekeys({ remaining: status.prekeys_remaining });
        }
    } catch (e) {
        console.error('[E2EE] Error checking SPK rotation:', e);
    }
}

/**
 * Rotate signed prekey
 */
async function rotateSignedPreKey() {
    if (!window.vibeE2EE) return;
    
    try {
        console.log('[E2EE] Rotating signed prekey...');
        
        // Generate new signed prekey with rotation (keeps previous)
        const bundle = await window.vibeE2EE.rotateSignedPreKey();
        
        // Upload to server
        const response = await api('/keys/bundle', {
            method: 'POST',
            body: JSON.stringify(bundle),
        });
        
        if (response.ok) {
            console.log('[E2EE] Signed prekey rotated successfully');
        } else {
            console.error('[E2EE] Failed to upload rotated SPK:', await response.text());
        }
    } catch (e) {
        console.error('[E2EE] Error rotating signed prekey:', e);
    }
}

// ==================== V3.7.0: IDENTITY KEY CHANGE DETECTION ====================

/**
 * Store for known identity keys
 * Key: user_id, Value: { identityKey, lastVerified, trusted }
 */
const knownIdentityKeys = {};

/**
 * Load known identity keys from IndexedDB
 */
async function loadKnownIdentityKeys() {
    if (!offlineDB?.db) {
        console.log('[E2EE] loadKnownIdentityKeys: offlineDB not ready');
        return;
    }
    
    try {
        const db = offlineDB.db;
        if (!db.objectStoreNames.contains('knownIdentityKeys')) {
            console.log('[E2EE] knownIdentityKeys store not available yet');
            return;
        }
        
        const tx = db.transaction('knownIdentityKeys', 'readonly');
        const store = tx.objectStore('knownIdentityKeys');
        const request = store.getAll();
        
        return new Promise((resolve) => {
            request.onsuccess = () => {
                const keys = request.result || [];
                keys.forEach(k => {
                    knownIdentityKeys[k.user_id] = {
                        identityKey: k.identity_key,
                        lastVerified: k.last_verified,
                        trusted: k.trusted
                    };
                });
                console.log('[E2EE] Loaded', keys.length, 'known identity keys from IndexedDB');
                resolve();
            };
            request.onerror = () => {
                console.error('[E2EE] Error in getAll request');
                resolve();
            };
        });
    } catch (e) {
        console.error('[E2EE] Error loading known identity keys:', e);
    }
}

/**
 * Save known identity key
 */
async function saveKnownIdentityKey(userId, identityKey, trusted = false) {
    knownIdentityKeys[userId] = {
        identityKey,
        lastVerified: new Date().toISOString(),
        trusted
    };
    
    if (!offlineDB?.db) {
        console.log('[E2EE] saveKnownIdentityKey: offlineDB not ready, saved to memory only');
        return;
    }
    
    try {
        const db = offlineDB.db;
        if (!db.objectStoreNames.contains('knownIdentityKeys')) return;
        
        const tx = db.transaction('knownIdentityKeys', 'readwrite');
        const store = tx.objectStore('knownIdentityKeys');
        store.put({
            user_id: userId,
            identity_key: identityKey,
            last_verified: new Date().toISOString(),
            trusted
        });
        console.log('[E2EE] Saved identity key to IndexedDB for', userId);
    } catch (e) {
        console.error('[E2EE] Error saving known identity key:', e);
    }
}

/**
 * Check if identity key changed
 * Returns: { changed: boolean, previousKey: string | null }
 */
function checkIdentityKeyChange(userId, currentIdentityKey) {
    const known = knownIdentityKeys[userId];
    
    if (!known) {
        // First time seeing this user
        return { changed: false, previousKey: null, isNew: true };
    }
    
    if (known.identityKey !== currentIdentityKey) {
        return { changed: true, previousKey: known.identityKey, isNew: false };
    }
    
    return { changed: false, previousKey: known.identityKey, isNew: false };
}

/**
 * Show identity key changed banner in chat header
 * @param {string} chatId - Chat/user ID
 * @param {string} displayName - Display name of contact
 * @param {boolean} weResetKeys - True if WE reset our keys (not the contact)
 */
function showIdentityKeyChangedBanner(chatId, displayName, weResetKeys = false) {
    // v3.11.2: Skip if banner already exists (prevents visual flicker from multiple callers)
    const existing = document.getElementById('identity-key-changed-banner');
    if (existing) return;
    
    const chatHeader = document.querySelector('.chat-header');
    if (!chatHeader) return;
    
    const banner = document.createElement('div');
    banner.id = 'identity-key-changed-banner';
    banner.className = 'identity-key-changed-banner';
    
    // Different text depending on who reset keys
    const bannerText = weResetKeys 
        ? `Your security keys were reset. <a href="#" onclick="verifyIdentityKey('${chatId}'); return false;">Verify</a> with <strong>${escapeHtml(displayName)}</strong>`
        : `<strong>${escapeHtml(displayName)}'s</strong> security key has changed. <a href="#" onclick="verifyIdentityKey('${chatId}'); return false;">Verify</a>`;
    
    banner.innerHTML = `
        <span class="banner-icon">🔐</span>
        <span class="banner-text">${bannerText}</span>
        <button class="banner-dismiss" onclick="dismissIdentityKeyBanner('${chatId}')">&times;</button>
    `;
    
    // Insert after header
    chatHeader.parentNode.insertBefore(banner, chatHeader.nextSibling);
}

/**
 * Hide identity key changed banner
 */
function hideIdentityKeyChangedBanner() {
    const banner = document.getElementById('identity-key-changed-banner');
    if (banner) {
        banner.remove();
    }
}

/**
 * Dismiss banner and mark key as trusted
 */
async function dismissIdentityKeyBanner(userId) {
    hideIdentityKeyChangedBanner();
    
    // v3.11.5: Also remove system message from chat
    const sysMsg = document.querySelector('.key-reset-message');
    if (sysMsg) sysMsg.remove();
    
    // v3.11.6: Clean up reset timestamp
    localStorage.removeItem('vibe_key_reset_time_' + userId);
    
    // Mark current key as trusted
    const known = knownIdentityKeys[userId];
    if (known) {
        await saveKnownIdentityKey(userId, known.identityKey, true);
    }
}

/**
 * Open verification modal for identity key
 */
async function verifyIdentityKey(userId) {
    // v3.8.25: Use existing KeyVerificationUI module
    if (typeof KeyVerificationUI !== 'undefined' && KeyVerificationUI.open) {
        const displayName = state.currentChat?.displayName || state.currentChat?.username || userId;
        await KeyVerificationUI.open(userId, displayName);
    } else {
        console.log('[E2EE] KeyVerificationUI not available');
        dismissIdentityKeyBanner(userId);
    }
}

/**
 * v3.8.26: Open key verification for current chat (called from header button)
 */
function openKeyVerification() {
    if (!state.currentChatId) {
        console.log('[E2EE] No current chat');
        return;
    }
    
    // Don't show for groups
    if (state.currentChat?.isGroup) {
        showToast('Key verification is only available for direct chats');
        return;
    }
    
    const displayName = state.currentChat?.displayName || state.currentChat?.username || state.currentChatId;
    
    if (typeof KeyVerificationUI !== 'undefined' && KeyVerificationUI.open) {
        KeyVerificationUI.open(state.currentChatId, displayName);
    } else {
        console.log('[E2EE] KeyVerificationUI not available');
    }
}

/**
 * v3.8.20: Verify contact's identity key on chat open (Signal-style)
 * This detects key changes even if device was offline during KEY_RESET
 */
async function verifyContactIdentityKey(userId, displayName) {
    if (!state.e2eeReady || typeof VibeCrypto === 'undefined') {
        return;
    }
    
    try {
        // Ensure knownIdentityKeys are loaded (may not be loaded if IndexedDB wasn't ready during initE2EE)
        const keysBeforeLoad = Object.keys(knownIdentityKeys).length;
        if (keysBeforeLoad === 0 && offlineDB?.db) {
            console.log('[E2EE] knownIdentityKeys empty, attempting to load from IndexedDB...');
            await loadKnownIdentityKeys();
            console.log('[E2EE] After load: knownIdentityKeys count:', Object.keys(knownIdentityKeys).length);
        }
        
        // v3.11.0: Immediately show banner if key is known but untrusted (no network required)
        // v3.11.2: Moved to openChat sync block. Here we only load keys from IndexedDB if needed.
        const existingKnown = knownIdentityKeys[userId];
        
        // Fetch current identity key from server to detect changes
        const response = await api('/keys/identity/' + userId);
        if (!response.ok) {
            if (response.status === 429 || response.status >= 500) {
                console.log('[E2EE] Server error or rate limit, will retry later:', response.status);
                return; // Banner already shown above if untrusted
            }
            console.log('[E2EE] User has no identity key:', userId, 'status:', response.status);
            return;
        }
        
        const data = await response.json();
        const currentIdentityKey = data.identity_key;
        
        if (!currentIdentityKey) {
            return;
        }
        
        // Check if identity key changed
        const check = checkIdentityKeyChange(userId, currentIdentityKey);
        console.log('[E2EE] Identity key check for', userId, ':', check, 'knownIdentityKeys count:', Object.keys(knownIdentityKeys).length);
        
        if (check.isNew) {
            // First time seeing this contact - save their key
            console.log('[E2EE] Saving new identity key for', userId);
            
            // v3.8.58: Check if WE just reset our keys (flag set by resetE2EE)
            const keysJustReset = localStorage.getItem('vibe_keys_just_reset');
            const resetTime = keysJustReset ? parseInt(keysJustReset) : 0;
            const timeSinceReset = Date.now() - resetTime;
            const recentReset = timeSinceReset < 5 * 60 * 1000; // 5 minutes
            
            console.log('[E2EE] Check for "we reset keys": keysJustReset:', !!keysJustReset, 'timeSinceReset:', Math.round(timeSinceReset/1000), 'sec, recentReset:', recentReset);
            
            // v3.11.0: If we recently reset keys, save as untrusted (banner will persist).
            // Otherwise this is a genuinely new contact - trust immediately.
            await saveKnownIdentityKey(userId, currentIdentityKey, !recentReset);
            
            if (recentReset) {
                console.log('[E2EE] We recently reset our keys, showing banner for', userId);
                showIdentityKeyChangedBanner(userId, displayName || userId, true); // weResetKeys = true
                showKeyResetInChat(displayName || userId);
            }
        } else if (check.changed) {
            // Key changed! User reset their keys while we were offline
            console.log('[E2EE] Identity key CHANGED for', userId, '- invalidating session');
            
            // Delete local session
            try {
                await VibeCrypto.deleteSession(userId);
                console.log('[E2EE] Deleted session with', userId);
            } catch (e) {
                console.warn('[E2EE] Failed to delete session:', e);
            }
            
            // Clear cached key bundle
            if (state.keyBundles) {
                delete state.keyBundles[userId];
            }
            
            // Clear verification status - keys changed, need to re-verify
            if (typeof VibeCryptoVerification !== 'undefined' && state.user) {
                VibeCryptoVerification.clearVerificationStatus(state.user.id, userId);
                console.log('[E2EE] Cleared verification status for', userId);
            }
            
            // Save new identity key (not trusted yet)
            await saveKnownIdentityKey(userId, currentIdentityKey, false);
            
            // Show banner and system message
            showIdentityKeyChangedBanner(userId, displayName || userId);
            showKeyResetInChat(displayName || userId);
        } else {
            // Key unchanged
            console.log('[E2EE] Identity key unchanged for', userId, 'trusted:', existingKnown?.trusted);
            // v3.11.3: Show banner if untrusted and not already showing
            // (covers case when knownIdentityKeys was empty during openChat sync check)
            if (existingKnown?.trusted === false) {
                const keysJustReset = localStorage.getItem('vibe_keys_just_reset');
                const resetTime = keysJustReset ? parseInt(keysJustReset) : 0;
                const weResetRecently = (Date.now() - resetTime) < 5 * 60 * 1000;
                showIdentityKeyChangedBanner(userId, displayName || userId, weResetRecently);
                showKeyResetInChat(displayName || userId);
            }
        }
        
    } catch (e) {
        console.error('[E2EE] Error verifying contact identity key:', e);
    }
}

// ==================== V3.7.0: SESSION MANAGEMENT UI ====================

/**
 * Load and display active sessions
 */
async function loadSessions() {
    const sessionsContainer = document.getElementById('sessions-list');
    if (!sessionsContainer) return;
    
    sessionsContainer.innerHTML = '<div class="loading-sessions">Loading sessions...</div>';
    
    try {
        const response = await api('/auth/sessions');
        if (!response.ok) {
            sessionsContainer.innerHTML = '<div class="sessions-error">Failed to load sessions</div>';
            return;
        }
        
        const data = await response.json();
        renderSessions(data.sessions);
    } catch (e) {
        console.error('Error loading sessions:', e);
        sessionsContainer.innerHTML = '<div class="sessions-error">Network error</div>';
    }
}

/**
 * Render sessions list
 */
function renderSessions(sessions) {
    const container = document.getElementById('sessions-list');
    if (!container) return;
    
    if (!sessions || sessions.length === 0) {
        container.innerHTML = '<div class="no-sessions">No active sessions</div>';
        updateTerminateAllButton(0);
        return;
    }
    
    // Count other sessions (not current)
    const otherSessionsCount = sessions.filter(s => !s.is_current).length;
    updateTerminateAllButton(otherSessionsCount);
    
    container.innerHTML = sessions.map(session => {
        const deviceInfo = parseSessionUserAgent(session.user_agent);
        const lastActive = formatSessionTime(session.last_activity);
        const createdAt = formatSessionTime(session.created_at);
        const safeSessionId = escapeHtml(session.id);
        
        // Current session is always online, others check last_activity
        const status = session.is_current ? 'online' : getSessionStatus(session.last_activity);
        
        // Status labels for tooltip
        const statusLabels = {
            'online': 'Online',
            'away': 'Away',
            'offline': 'Offline'
        };
        
        return `
            <div class="session-item ${session.is_current ? 'current-session' : ''}" data-session-id="${safeSessionId}">
                <div class="session-info">
                    <div class="session-device">
                        <span class="device-icon">${deviceInfo.icon}</span>
                        <span class="device-name">${escapeHtml(deviceInfo.name)}</span>
                        <span class="session-status-indicator status-${status}" title="${statusLabels[status]}"></span>
                        ${session.is_current ? '<span class="current-badge">This device</span>' : ''}
                    </div>
                    <div class="session-details">
                        <span class="session-ip">${escapeHtml(session.ip_address || 'Unknown IP')}</span>
                        <span class="session-separator">•</span>
                        <span class="session-time">Last active: ${lastActive}</span>
                        <span class="session-separator">•</span>
                        <span class="session-created">Created: ${createdAt}</span>
                    </div>
                </div>
                ${!session.is_current ? `
                    <button class="btn-terminate-session" onclick="terminateSession('${safeSessionId}')">
                        Terminate
                    </button>
                ` : ''}
            </div>
        `;
    }).join('');
}

/**
 * Update "Terminate All Other Sessions" button state
 */
function updateTerminateAllButton(otherSessionsCount) {
    const btn = document.querySelector('.btn-danger-outline');
    if (!btn) return;
    
    if (otherSessionsCount === 0) {
        btn.disabled = true;
        btn.textContent = 'No Other Sessions';
        btn.style.opacity = '0.5';
        btn.style.cursor = 'not-allowed';
    } else {
        btn.disabled = false;
        btn.textContent = `Terminate All Other Sessions (${otherSessionsCount})`;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
    }
}

/**
 * Get session online status
 */
function getSessionStatus(lastActivityISO) {
    if (!lastActivityISO) return 'offline';
    
    const lastActivity = new Date(lastActivityISO);
    const now = new Date();
    const diffMinutes = (now - lastActivity) / 60000; // milliseconds to minutes
    
    if (diffMinutes < 5) return 'online';      // < 5 min - online
    if (diffMinutes < 30) return 'away';       // 5-30 min - away
    return 'offline';                           // > 30 min - offline
}

/**
 * Parse user agent to get device info
 */
function parseSessionUserAgent(ua) {
    if (!ua) return { icon: '💻', name: 'Unknown Device' };
    
    // Mobile detection
    if (/iPhone|iPad|iPod/i.test(ua)) {
        return { icon: '📱', name: 'iPhone/iPad' };
    }
    if (/Android/i.test(ua)) {
        return { icon: '📱', name: 'Android' };
    }
    
    // Browser detection
    if (/Chrome/i.test(ua)) {
        if (/Windows/i.test(ua)) return { icon: '💻', name: 'Chrome on Windows' };
        if (/Mac/i.test(ua)) return { icon: '💻', name: 'Chrome on Mac' };
        if (/Linux/i.test(ua)) return { icon: '🐧', name: 'Chrome on Linux' };
        return { icon: '💻', name: 'Chrome' };
    }
    if (/Firefox/i.test(ua)) {
        return { icon: '🦊', name: 'Firefox' };
    }
    if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) {
        return { icon: '🧭', name: 'Safari' };
    }
    if (/Edge/i.test(ua)) {
        return { icon: '💻', name: 'Edge' };
    }
    
    return { icon: '💻', name: 'Unknown Browser' };
}

/**
 * Format session time
 */
function formatSessionTime(isoString) {
    if (!isoString) return 'Unknown';
    
    const date = new Date(isoString);
    const now = new Date();
    const diff = now - date;
    
    // Less than a minute
    if (diff < 60000) return 'Just now';
    
    // Less than an hour
    if (diff < 3600000) {
        const minutes = Math.floor(diff / 60000);
        return minutes === 1 ? '1 min ago' : `${minutes} min ago`;
    }
    
    // Less than a day
    if (diff < 86400000) {
        const hours = Math.floor(diff / 3600000);
        return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
    }
    
    // Less than a week
    if (diff < 604800000) {
        const days = Math.floor(diff / 86400000);
        return days === 1 ? '1 day ago' : `${days} days ago`;
    }
    
    // Full date
    return date.toLocaleDateString();
}

/**
 * Terminate a specific session
 */
async function terminateSession(sessionId) {
    const confirmed = await showConfirm(
        'The device will be logged out.',
        'Terminate Session?',
        'Terminate',
        'Cancel'
    );
    
    if (!confirmed) return;
    
    // Disable button and show loading
    const sessionItem = document.querySelector(`[data-session-id="${sessionId}"]`);
    const btn = sessionItem?.querySelector('.btn-terminate-session');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Terminating...';
        btn.style.opacity = '0.6';
    }
    
    try {
        const response = await api(`/auth/sessions/${sessionId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            showLocalMessage('sessions-message', 'Session terminated', 'success');
            loadSessions(); // Reload list
        } else {
            const data = await response.json();
            showLocalMessage('sessions-message', data.detail || 'Failed to terminate session', 'error');
            
            // Restore button on error
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Terminate';
                btn.style.opacity = '1';
            }
        }
    } catch (e) {
        console.error('Error terminating session:', e);
        showLocalMessage('sessions-message', 'Network error', 'error');
        
        // Restore button on error
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Terminate';
            btn.style.opacity = '1';
        }
    }
}

/**
 * Terminate all other sessions
 */
async function terminateOtherSessions() {
    const btn = document.querySelector('.btn-danger-outline');
    if (btn && btn.disabled) return;
    
    const confirmed = await showConfirm(
        'All other devices will be logged out.',
        'Terminate All Other Sessions?',
        'Terminate',
        'Cancel'
    );
    
    if (!confirmed) return;
    
    // Save original text and show loading
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Terminating...';
    btn.style.opacity = '0.6';
    
    try {
        console.log('[Sessions] Terminating other sessions...');
        const response = await api('/auth/sessions', {
            method: 'DELETE'
        });
        
        console.log('[Sessions] Response status:', response.status);
        const data = await response.json();
        console.log('[Sessions] Response data:', data);
        
        if (response.ok) {
            showLocalMessage('sessions-message', `Terminated ${data.revoked_count || 0} session(s)`, 'success');
            await loadSessions(); // Reload list (will re-enable button via updateTerminateAllButton)
        } else {
            showLocalMessage('sessions-message', data.detail || data.error || 'Failed to terminate sessions', 'error');
            
            // Restore button on error
            btn.disabled = false;
            btn.textContent = originalText;
            btn.style.opacity = '1';
        }
    } catch (e) {
        console.error('Error terminating sessions:', e);
        showLocalMessage('sessions-message', 'Network error', 'error');
        
        // Restore button on error
        btn.disabled = false;
        btn.textContent = originalText;
        btn.style.opacity = '1';
    }
}

// ==================== v3.8.36: BATCH OPERATIONS (Multi-Select Mode) ====================

/**
 * Toggle multi-select mode on/off
 */
function toggleMultiSelectMode() {
    if (state.multiSelectMode) {
        exitMultiSelectMode();
    } else {
        enterMultiSelectMode();
    }
}

/**
 * Enter multi-select mode
 */
function enterMultiSelectMode() {
    state.multiSelectMode = true;
    state.selectedMessages = [];
    
    // Update UI
    document.body.classList.add('multi-select-mode');
    document.getElementById('select-btn')?.classList.add('active');
    document.getElementById('messages')?.classList.add('multi-select-mode');
    
    // Show batch panel, hide input
    document.getElementById('batch-actions-panel')?.classList.remove('hidden');
    document.querySelector('.message-input')?.classList.add('hidden');
    
    // Add multi-select-mode class to all messages
    document.querySelectorAll('.message[data-id]').forEach(el => {
        el.classList.add('multi-select-mode');
    });
    
    updateBatchActionsPanel();
    showToast('Select messages to perform batch actions');
}

/**
 * Exit multi-select mode
 */
function exitMultiSelectMode() {
    state.multiSelectMode = false;
    state.selectedMessages = [];
    
    // Update UI
    document.body.classList.remove('multi-select-mode');
    document.getElementById('select-btn')?.classList.remove('active');
    document.getElementById('messages')?.classList.remove('multi-select-mode');
    
    // Hide batch panel, show input
    document.getElementById('batch-actions-panel')?.classList.add('hidden');
    document.querySelector('.message-input')?.classList.remove('hidden');
    
    // Remove selection classes from messages
    document.querySelectorAll('.message.multi-select-mode').forEach(el => {
        el.classList.remove('multi-select-mode', 'selected');
    });
}

/**
 * Toggle message selection (called when clicking on a message in multi-select mode)
 */
function toggleMessageSelection(messageId, isSent) {
    if (!state.multiSelectMode) return;
    
    const chat = state.chats[state.currentChatId];
    if (!chat) return;
    
    const message = chat.messages.find(m => m.id === messageId);
    if (!message) return;
    
    const idx = state.selectedMessages.findIndex(m => m.id === messageId);
    const msgEl = document.querySelector(`.message[data-id="${messageId}"]`);
    
    if (idx === -1) {
        // Add to selection
        state.selectedMessages.push({ id: messageId, isSent, message });
        msgEl?.classList.add('selected');
    } else {
        // Remove from selection
        state.selectedMessages.splice(idx, 1);
        msgEl?.classList.remove('selected');
    }
    
    updateBatchActionsPanel();
}

/**
 * Update batch actions panel based on selection
 */
function updateBatchActionsPanel() {
    const count = state.selectedMessages.length;
    const countEl = document.getElementById('batch-selected-count');
    const deleteAllBtn = document.getElementById('batch-delete-all-btn');
    
    // Update count text
    if (countEl) {
        countEl.textContent = count + ' selected';
    }
    
    // Check if all selected messages are sent by current user
    const allOwn = state.selectedMessages.every(m => m.isSent);
    
    // Show/hide "Delete for all" button
    if (deleteAllBtn) {
        if (allOwn && count > 0) {
            deleteAllBtn.classList.remove('hidden');
            deleteAllBtn.disabled = false;
        } else {
            deleteAllBtn.classList.add('hidden');
            deleteAllBtn.disabled = true;
        }
    }
    
    // Disable all buttons if nothing selected
    const buttons = document.querySelectorAll('.batch-btn');
    buttons.forEach(btn => {
        if (btn.id !== 'batch-delete-all-btn') {
            btn.disabled = count === 0;
        }
    });
}

/**
 * Batch delete messages for me
 */
async function batchDeleteForMe() {
    if (state.selectedMessages.length === 0) return;
    
    const count = state.selectedMessages.length;
    const confirmed = await showConfirm(
        `Delete ${count} message${count > 1 ? 's' : ''} for you?`,
        'Delete for me',
        'Delete'  // КАО#124: was '🗑' (emoji shown as OK button label)
    );
    
    if (!confirmed) return;
    
    try {
        const messageIds = state.selectedMessages.map(m => m.id);
        
        const response = await api('/messages/batch/delete', {
            method: 'POST',
            body: JSON.stringify({
                message_ids: messageIds,
                for_everyone: false
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            
            // Remove deleted messages from local state
            result.deleted.forEach(id => {
                removeMessageFromChat(id);
            });
            
            showToast(`Deleted ${result.deleted_count} message${result.deleted_count > 1 ? 's' : ''}`);
            
            if (result.error_count > 0) {
                console.warn('Some messages could not be deleted:', result.errors);
            }
        } else {
            await showAlert('Failed to delete messages', 'Error', '❌');
        }
    } catch (e) {
        console.error('Batch delete error:', e);
        await showAlert('Failed to delete messages', 'Error', '❌');
    }
    
    exitMultiSelectMode();
}

/**
 * Batch delete messages for everyone (only own messages)
 */
async function batchDeleteForAll() {
    if (state.selectedMessages.length === 0) return;
    
    // Double check all are own messages
    const allOwn = state.selectedMessages.every(m => m.isSent);
    if (!allOwn) {
        await showAlert('You can only delete your own messages for everyone', 'Error', '❌');
        return;
    }
    
    const count = state.selectedMessages.length;
    const confirmed = await showConfirm(
        `Delete ${count} message${count > 1 ? 's' : ''} for everyone? This cannot be undone.`,
        'Delete for everyone',
        'Delete'  // КАО#124: was '🗑' (emoji shown as OK button label)
    );
    
    if (!confirmed) return;
    
    try {
        const messageIds = state.selectedMessages.map(m => m.id);
        
        const response = await api('/messages/batch/delete', {
            method: 'POST',
            body: JSON.stringify({
                message_ids: messageIds,
                for_everyone: true
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            
            // Remove deleted messages from local state
            result.deleted.forEach(id => {
                removeMessageFromChat(id);
            });
            
            showToast(`Deleted ${result.deleted_count} message${result.deleted_count > 1 ? 's' : ''} for everyone`);
            
            if (result.error_count > 0) {
                console.warn('Some messages could not be deleted:', result.errors);
            }
        } else {
            await showAlert('Failed to delete messages', 'Error', '❌');
        }
    } catch (e) {
        console.error('Batch delete error:', e);
        await showAlert('Failed to delete messages', 'Error', '❌');
    }
    
    exitMultiSelectMode();
}

/**
 * Batch toggle favorites (add if not favorited, remove if favorited)
 */
async function batchToggleFavorites() {
    if (state.selectedMessages.length === 0) return;
    
    const chat = state.currentChat;
    if (!chat) return;
    
    try {
        // Split messages into add/remove groups
        const toAdd = [];
        const toRemove = [];
        
        for (const m of state.selectedMessages) {
            if (state.favoriteMessageIds.has(m.id)) {
                toRemove.push(m.id);
            } else {
                // КАО#231 (SER, Round-3): encrypt the preview for self so the server never stores plaintext —
                // the single-favorite path already did this (КАО#162) but this batch path did NOT, leaking the
                // plaintext question + [pollkey:] content key of a favorited poll announce message. Strip poll
                // markers first so the key never lands in the preview even after self-decryption.
                let preview = (m.message.text || '[Media]')
                    .replace(/\s*\[poll:[a-fA-F0-9-]+\]/g, '').replace(/\s*\[pollkey:[^\]\s]*\]/g, '').trim()
                    .substring(0, 200) || '[Media]';
                if (state.e2eeReady) {
                    // Round-3: never store plaintext when E2EE is on — use ciphertext, or '[Media]' if the self-key is unavailable
                    try { const enc = await VibeCrypto.encryptForSelf(preview); preview = enc || '[Media]'; }
                    catch (e) { console.warn('[favorite] preview encryptForSelf failed', e); preview = '[Media]'; }
                } else {
                    preview = '[Media]';  // КАО#273 (#39): fail-closed — never store a plaintext preview to the server when E2EE isn't ready
                }
                toAdd.push({
                    message_id: m.id,
                    chat_id: chat.isGroup ? null : chat.id,
                    group_id: chat.isGroup ? chat.id : null,
                    sender_id: m.message.sender_id || (m.isSent ? state.user?.id : state.currentChatId),
                    sender_name: m.message.sender_name || (m.isSent ? state.user?.username : chat.displayName || chat.username),
                    preview_text: preview
                });
            }
        }
        
        let addedCount = 0;
        let removedCount = 0;
        
        // Add new favorites
        if (toAdd.length > 0) {
            const response = await api('/favorites/batch', {
                method: 'POST',
                body: JSON.stringify({ items: toAdd })
            });
            
            if (response.ok) {
                const result = await response.json();
                result.added.forEach(id => state.favoriteMessageIds.add(id));
                addedCount = result.added_count;
            }
        }
        
        // Remove existing favorites
        for (const messageId of toRemove) {
            try {
                await api(`/favorites/${messageId}`, { method: 'DELETE' });
                state.favoriteMessageIds.delete(messageId);
                removedCount++;
            } catch (e) {
                console.warn('Failed to remove favorite:', messageId, e);
            }
        }
        
        // Show result
        let message = '';
        if (addedCount > 0) {
            message = `Added ${addedCount} ⭐`;
        }
        if (removedCount > 0) {
            message += message ? `, removed ${removedCount}` : `Removed ${removedCount} from favorites`;
        }
        showToast(message || 'Done');
        
    } catch (e) {
        console.error('Batch toggle favorite error:', e);
        await showAlert('Failed to toggle favorites', 'Error', '❌');
    }
    
    exitMultiSelectMode();
    renderMessages();  // Re-render to update stars
}

/**
 * Handle click on message in multi-select mode
 */
function handleMessageClickInMultiSelect(event) {
    if (!state.multiSelectMode) return false;
    
    const messageEl = event.target.closest('.message[data-id]');
    if (!messageEl) return false;
    
    // Don't intercept clicks on interactive elements
    if (event.target.closest('button, a, .file-message, .voice-play-btn, .poll-container, .reaction-emoji, .reaction-count')) {
        return false;
    }
    
    event.preventDefault();
    event.stopPropagation();
    
    const messageId = messageEl.dataset.id;
    const isSent = messageEl.dataset.isSent === 'true';
    
    toggleMessageSelection(messageId, isSent);
    return true;
}

// ==================== v3.8.37: FAVORITE MESSAGE IDS ====================

/**
 * Load favorite message IDs for current user (for star indicator)
 */
async function loadFavoriteMessageIds() {
    try {
        const response = await api('/favorites?limit=1000');
        if (response.ok) {
            const favorites = await response.json();
            state.favoriteMessageIds = new Set(favorites.map(f => f.message_id));
            // Re-render if in chat to show stars
            if (state.currentChatId) {
                renderMessages();
            }
        }
    } catch (e) {
        console.error('Load favorite IDs error:', e);
    }
}


// ==================== КАО#347: 2FA UI reconciliation ====================
// index.html's 2FA dialogs call these names; app.js only ever defined differently-named functions, so
// every button in the 2FA setup / disable / regenerate dialogs threw "is not defined" and the whole
// feature was unreachable from the UI (the REST API worked the entire time).
function showTOTPStep2() {
    // КАО#347: the setup dialog's "Next" button calls this; it was never defined, so the flow died
    // between the QR pane and the verification pane.
    document.getElementById('totp-setup-step1').classList.add('hidden');
    document.getElementById('totp-setup-step2').classList.remove('hidden');
    const input = document.getElementById('totp-verify-code');
    if (input) { input.value = ''; input.focus(); }
}
function closeTOTPSetup() { hideTOTPSetupModal(); }
function verifyTOTPSetup() { return verifyAndEnableTOTP(); }
function closeDisableTOTPModal() { hideDisableTOTPModal(); }
function confirmDisableTOTP() { return disableTOTP(); }
function closeRegenerateCodesModal() {
    const m = document.getElementById('regenerate-codes-modal');
    if (m) m.classList.add('hidden');
}
function confirmRegenerateCodes() { return regenerateRecoveryCodes(); }
