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

/**
 * VibeMessenger Key Store
 * 
 * Secure storage for cryptographic keys using IndexedDB.
 * 
 * Stores:
 * - Identity keys (long-term)
 * - Signed prekeys (medium-term)
 * - One-time prekeys (single-use)
 * - Session states (per contact)
 * - Sender keys (for groups)
 */

const KeyStore = {
    DB_NAME: 'VibeMessenger_KeyStore',
    DB_VERSION: 1,
    db: null,
    
    // Store names
    STORES: {
        IDENTITY: 'identity_keys',
        SIGNED_PREKEYS: 'signed_prekeys',
        ONE_TIME_PREKEYS: 'one_time_prekeys',
        SESSIONS: 'sessions',
        SENDER_KEYS: 'sender_keys',
        TRUSTED_KEYS: 'trusted_keys'
    },
    
    // Key for storing current user ID in localStorage
    CURRENT_USER_KEY: 'e2ee_current_user_id',
    
    // ==================== DATABASE INITIALIZATION ====================
    
    /**
     * Initialize the database
     * @returns {Promise<IDBDatabase>}
     */
    async init() {
        if (this.db) {
            return this.db;
        }
        
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);
            
            request.onerror = () => {
                console.error('Failed to open KeyStore:', request.error);
                reject(request.error);
            };
            
            request.onsuccess = () => {
                this.db = request.result;
                console.log('KeyStore initialized');
                resolve(this.db);
            };
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Identity keys store (one per user)
                if (!db.objectStoreNames.contains(this.STORES.IDENTITY)) {
                    const identityStore = db.createObjectStore(this.STORES.IDENTITY, { keyPath: 'id' });
                    identityStore.createIndex('created_at', 'created_at', { unique: false });
                }
                
                // Signed prekeys store
                if (!db.objectStoreNames.contains(this.STORES.SIGNED_PREKEYS)) {
                    const signedStore = db.createObjectStore(this.STORES.SIGNED_PREKEYS, { keyPath: 'id' });
                    signedStore.createIndex('created_at', 'created_at', { unique: false });
                }
                
                // One-time prekeys store
                if (!db.objectStoreNames.contains(this.STORES.ONE_TIME_PREKEYS)) {
                    const otpStore = db.createObjectStore(this.STORES.ONE_TIME_PREKEYS, { keyPath: 'id' });
                    otpStore.createIndex('created_at', 'created_at', { unique: false });
                }
                
                // Sessions store (keyed by recipientId)
                if (!db.objectStoreNames.contains(this.STORES.SESSIONS)) {
                    const sessionStore = db.createObjectStore(this.STORES.SESSIONS, { keyPath: 'recipientId' });
                    sessionStore.createIndex('updated_at', 'updated_at', { unique: false });
                }
                
                // Sender keys store (keyed by groupId:senderId)
                if (!db.objectStoreNames.contains(this.STORES.SENDER_KEYS)) {
                    const senderKeyStore = db.createObjectStore(this.STORES.SENDER_KEYS, { keyPath: 'id' });
                    senderKeyStore.createIndex('groupId', 'groupId', { unique: false });
                }
                
                // Trusted keys store (known identity keys of contacts)
                if (!db.objectStoreNames.contains(this.STORES.TRUSTED_KEYS)) {
                    const trustedStore = db.createObjectStore(this.STORES.TRUSTED_KEYS, { keyPath: 'recipientId' });
                    trustedStore.createIndex('verified', 'verified', { unique: false });
                }
                
                console.log('KeyStore schema created/upgraded');
            };
        });
    },
    
    /**
     * Clear all data (for logout)
     */
    async clearAll() {
        await this.init();
        
        const transaction = this.db.transaction(
            Object.values(this.STORES),
            'readwrite'
        );
        
        for (const storeName of Object.values(this.STORES)) {
            transaction.objectStore(storeName).clear();
        }
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => {
                console.log('KeyStore cleared');
                resolve();
            };
            transaction.onerror = () => reject(transaction.error);
        });
    },
    
    /**
     * Save current user ID to localStorage
     * @param {string} userId
     */
    saveCurrentUserId(userId) {
        localStorage.setItem(this.CURRENT_USER_KEY, userId);
    },
    
    /**
     * Get current user ID from localStorage
     * @returns {string|null}
     */
    getCurrentUserId() {
        return localStorage.getItem(this.CURRENT_USER_KEY);
    },
    
    /**
     * Clear current user ID from localStorage
     */
    clearCurrentUserId() {
        localStorage.removeItem(this.CURRENT_USER_KEY);
    },
    
    // ==================== IDENTITY KEYS ====================
    
    /**
     * Save identity keys
     * @param {string} userId 
     * @param {object} identityKey 
     * @param {object} signingKey 
     */
    async saveIdentityKeys(userId, identityKey, signingKey) {
        await this.init();
        
        const data = {
            id: userId,
            identityKey: identityKey,
            signingKey: signingKey,
            created_at: Date.now()
        };
        
        return this._put(this.STORES.IDENTITY, data);
    },
    
    /**
     * Get identity keys
     * @param {string} userId 
     * @returns {Promise<object|null>}
     */
    async getIdentityKeys(userId) {
        await this.init();
        return this._get(this.STORES.IDENTITY, userId);
    },
    
    /**
     * Check if identity keys exist
     * @param {string} userId 
     * @returns {Promise<boolean>}
     */
    async hasIdentityKeys(userId) {
        const keys = await this.getIdentityKeys(userId);
        return keys !== null;
    },
    
    // ==================== SIGNED PREKEYS ====================
    
    /**
     * Save signed prekey
     * @param {object} signedPrekey 
     */
    async saveSignedPrekey(signedPrekey) {
        await this.init();
        
        const data = {
            ...signedPrekey,
            created_at: Date.now()
        };
        
        return this._put(this.STORES.SIGNED_PREKEYS, data);
    },
    
    /**
     * Get signed prekey by ID
     * @param {number} prekeyId 
     * @returns {Promise<object|null>}
     */
    async getSignedPrekey(prekeyId) {
        await this.init();
        return this._get(this.STORES.SIGNED_PREKEYS, prekeyId);
    },
    
    /**
     * Get latest signed prekey
     * @returns {Promise<object|null>}
     */
    async getLatestSignedPrekey() {
        await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(this.STORES.SIGNED_PREKEYS, 'readonly');
            const store = transaction.objectStore(this.STORES.SIGNED_PREKEYS);
            const index = store.index('created_at');
            
            const request = index.openCursor(null, 'prev');
            
            request.onsuccess = () => {
                const cursor = request.result;
                resolve(cursor ? cursor.value : null);
            };
            
            request.onerror = () => reject(request.error);
        });
    },
    
    /**
     * Delete old signed prekeys (keep only last N)
     * @param {number} keep - Number of prekeys to keep
     */
    async cleanupSignedPrekeys(keep = 5) {
        await this.init();
        
        const all = await this._getAll(this.STORES.SIGNED_PREKEYS);
        
        if (all.length <= keep) return;
        
        // Sort by created_at descending
        all.sort((a, b) => b.created_at - a.created_at);
        
        // Delete old ones
        const toDelete = all.slice(keep);
        for (const prekey of toDelete) {
            await this._delete(this.STORES.SIGNED_PREKEYS, prekey.id);
        }
        
        console.log(`Cleaned up ${toDelete.length} old signed prekeys`);
    },
    
    // ==================== ONE-TIME PREKEYS ====================
    
    /**
     * Save one-time prekeys
     * @param {Array} prekeys 
     */
    async saveOneTimePrekeys(prekeys) {
        await this.init();
        
        const transaction = this.db.transaction(this.STORES.ONE_TIME_PREKEYS, 'readwrite');
        const store = transaction.objectStore(this.STORES.ONE_TIME_PREKEYS);
        
        for (const prekey of prekeys) {
            store.put({
                ...prekey,
                created_at: Date.now()
            });
        }
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    },
    
    /**
     * Get one-time prekey by ID
     * @param {number} prekeyId 
     * @returns {Promise<object|null>}
     */
    async getOneTimePrekey(prekeyId) {
        await this.init();
        return this._get(this.STORES.ONE_TIME_PREKEYS, prekeyId);
    },
    
    /**
     * Remove used one-time prekey
     * @param {number} prekeyId 
     */
    async removeOneTimePrekey(prekeyId) {
        await this.init();
        return this._delete(this.STORES.ONE_TIME_PREKEYS, prekeyId);
    },
    
    /**
     * Count remaining one-time prekeys
     * @returns {Promise<number>}
     */
    async countOneTimePrekeys() {
        await this.init();
        
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(this.STORES.ONE_TIME_PREKEYS, 'readonly');
            const store = transaction.objectStore(this.STORES.ONE_TIME_PREKEYS);
            const request = store.count();
            
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    },
    
    /**
     * Get next prekey ID to use
     * @returns {Promise<number>}
     */
    async getNextPrekeyId() {
        await this.init();
        
        const all = await this._getAll(this.STORES.ONE_TIME_PREKEYS);
        if (all.length === 0) return 1;
        
        const maxId = Math.max(...all.map(p => p.id));
        return maxId + 1;
    },
    
    // ==================== SESSIONS ====================
    
    /**
     * Save session state
     * @param {string} recipientId 
     * @param {object} state - Ratchet state
     */
    async saveSession(recipientId, state) {
        await this.init();
        
        const serialized = SignalProtocol.serializeState(state);
        
        const data = {
            recipientId: recipientId,
            state: serialized,
            updated_at: Date.now()
        };
        
        return this._put(this.STORES.SESSIONS, data);
    },
    
    /**
     * Get session state
     * @param {string} recipientId 
     * @returns {Promise<object|null>}
     */
    async getSession(recipientId) {
        await this.init();
        
        const data = await this._get(this.STORES.SESSIONS, recipientId);
        if (!data) return null;
        
        return SignalProtocol.deserializeState(data.state);
    },
    
    /**
     * Check if session exists
     * @param {string} recipientId 
     * @returns {Promise<boolean>}
     */
    async hasSession(recipientId) {
        const session = await this.getSession(recipientId);
        return session !== null;
    },
    
    /**
     * Delete session
     * @param {string} recipientId 
     */
    async deleteSession(recipientId) {
        await this.init();
        return this._delete(this.STORES.SESSIONS, recipientId);
    },
    
    /**
     * Delete all sessions
     */
    async deleteAllSessions() {
        await this.init();
        
        const transaction = this.db.transaction(this.STORES.SESSIONS, 'readwrite');
        transaction.objectStore(this.STORES.SESSIONS).clear();
        
        return new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    },
    
    // ==================== SENDER KEYS (Groups) ====================
    
    /**
     * Save our sender key for a group
     * @param {string} groupId 
     * @param {string} senderId 
     * @param {object} senderKey 
     */
    async saveSenderKey(groupId, senderId, senderKey) {
        await this.init();
        
        const data = {
            id: `${groupId}:${senderId}`,
            groupId: groupId,
            senderId: senderId,
            senderKey: senderKey,
            updated_at: Date.now()
        };
        
        return this._put(this.STORES.SENDER_KEYS, data);
    },
    
    /**
     * Get sender key for a group member
     * @param {string} groupId 
     * @param {string} senderId 
     * @returns {Promise<object|null>}
     */
    async getSenderKey(groupId, senderId) {
        await this.init();
        
        const data = await this._get(this.STORES.SENDER_KEYS, `${groupId}:${senderId}`);
        return data ? data.senderKey : null;
    },
    
    /**
     * Delete all sender keys for a group
     * @param {string} groupId 
     */
    async deleteSenderKeys(groupId) {
        await this.init();
        
        const all = await this._getAll(this.STORES.SENDER_KEYS);
        const toDelete = all.filter(sk => sk.groupId === groupId);
        
        for (const sk of toDelete) {
            await this._delete(this.STORES.SENDER_KEYS, sk.id);
        }
    },
    
    // ==================== TRUSTED KEYS ====================
    
    /**
     * Save/update trusted identity key for a contact
     * @param {string} recipientId 
     * @param {string} identityKey - Base64 public key
     * @param {boolean} verified - Manually verified (QR code, etc.)
     */
    async saveTrustedKey(recipientId, identityKey, verified = false) {
        await this.init();
        
        const existing = await this._get(this.STORES.TRUSTED_KEYS, recipientId);
        
        const data = {
            recipientId: recipientId,
            identityKey: identityKey,
            verified: verified,
            firstSeen: existing ? existing.firstSeen : Date.now(),
            lastSeen: Date.now()
        };
        
        // Check for key change
        if (existing && existing.identityKey !== identityKey) {
            console.warn(`Identity key changed for ${recipientId}!`);
            data.keyChanged = true;
            data.previousKey = existing.identityKey;
            data.verified = false; // Reset verification on key change
        }
        
        return this._put(this.STORES.TRUSTED_KEYS, data);
    },
    
    /**
     * Get trusted identity key for a contact
     * @param {string} recipientId 
     * @returns {Promise<object|null>}
     */
    async getTrustedKey(recipientId) {
        await this.init();
        return this._get(this.STORES.TRUSTED_KEYS, recipientId);
    },
    
    /**
     * Verify if identity key matches stored trusted key
     * @param {string} recipientId 
     * @param {string} identityKey 
     * @returns {Promise<{trusted: boolean, changed: boolean}>}
     */
    async verifyIdentityKey(recipientId, identityKey) {
        const stored = await this.getTrustedKey(recipientId);
        
        if (!stored) {
            // First time seeing this key - trust on first use (TOFU)
            await this.saveTrustedKey(recipientId, identityKey, false);
            return { trusted: true, changed: false, firstTime: true };
        }
        
        if (stored.identityKey === identityKey) {
            return { trusted: true, changed: false, verified: stored.verified };
        }
        
        // Key changed! This could be an attack or device change
        return { trusted: false, changed: true, previousKey: stored.identityKey };
    },
    
    /**
     * Mark a contact's identity key as verified
     * @param {string} recipientId 
     */
    async markVerified(recipientId) {
        const stored = await this.getTrustedKey(recipientId);
        if (stored) {
            stored.verified = true;
            await this._put(this.STORES.TRUSTED_KEYS, stored);
        }
    },
    
    // ==================== INTERNAL HELPERS ====================
    
    async _get(storeName, key) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.get(key);
            
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });
    },
    
    async _put(storeName, data) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.put(data);
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },
    
    async _delete(storeName, key) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(storeName, 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.delete(key);
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    },
    
    async _getAll(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(storeName, 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.getAll();
            
            request.onsuccess = () => resolve(request.result || []);
            request.onerror = () => reject(request.error);
        });
    }
};

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.KeyStore = KeyStore;
}
