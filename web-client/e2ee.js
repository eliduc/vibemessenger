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
 * VibeMessenger E2EE Integration Module
 * 
 * High-level API for end-to-end encryption:
 * - Key generation and management
 * - Session establishment
 * - Message encryption/decryption
 * - Group encryption
 * - File encryption
 */

const E2EE = {
    initialized: false,
    userId: null,
    
    // Cache for decrypted messages (prevents re-decryption issues with X3DH)
    _decryptedCache: new Map(),
    apiBaseUrl: '',
    
    // ==================== INITIALIZATION ====================
    
    /**
     * Initialize E2EE for the current user
     * @param {string} userId 
     * @param {string} apiBaseUrl 
     * @param {string} accessToken 
     */
    async init(userId, apiBaseUrl, accessToken) {
        this.userId = userId;
        this.apiBaseUrl = apiBaseUrl;
        this.accessToken = accessToken;
        
        // Initialize IndexedDB key store
        await KeyStore.init();
        
        // Check if this is the same user as before
        const previousUserId = KeyStore.getCurrentUserId();
        
        if (previousUserId && previousUserId !== userId) {
            // Different user - clear all keys for security
            console.log('Different user detected, clearing old keys...');
            await KeyStore.clearAll();
        }
        
        // Save current user ID
        KeyStore.saveCurrentUserId(userId);
        
        // Check if we have identity keys
        const hasKeys = await KeyStore.hasIdentityKeys(userId);
        
        if (!hasKeys) {
            // Generate new keys for first time user
            await this.generateAndUploadKeys();
        } else {
            console.log('Using existing identity keys');
            // Check if we need to replenish one-time prekeys
            await this.checkAndReplenishPrekeys();
        }
        
        this.initialized = true;
        console.log('E2EE initialized for user:', userId);
    },
    
    /**
     * Generate identity keys and upload to server
     */
    async generateAndUploadKeys() {
        console.log('Generating new identity keys...');
        
        // Generate identity keys
        const { identityKey, signingKey } = await SignalProtocol.generateIdentityKeys();
        
        // Generate signed prekey
        const signedPrekey = await SignalProtocol.generateSignedPrekey(signingKey, 1);
        
        // Generate one-time prekeys
        const oneTimePrekeys = await SignalProtocol.generateOneTimePrekeys(1, 100);
        
        // Save locally
        await KeyStore.saveIdentityKeys(this.userId, identityKey, signingKey);
        await KeyStore.saveSignedPrekey(signedPrekey);
        await KeyStore.saveOneTimePrekeys(oneTimePrekeys);
        
        // Create bundle for server (includes signing_public_key)
        const bundle = SignalProtocol.createKeyBundle(identityKey, signingKey, signedPrekey, oneTimePrekeys);
        
        // Upload to server
        await this.uploadKeyBundle(bundle);
        
        console.log('Keys generated and uploaded successfully');
    },
    
    /**
     * Check and replenish one-time prekeys if running low
     */
    async checkAndReplenishPrekeys() {
        const count = await KeyStore.countOneTimePrekeys();
        
        if (count < 20) {
            console.log('Replenishing one-time prekeys...');
            
            const nextId = await KeyStore.getNextPrekeyId();
            const newPrekeys = await SignalProtocol.generateOneTimePrekeys(nextId, 100);
            
            await KeyStore.saveOneTimePrekeys(newPrekeys);
            
            // Upload to server
            await this.uploadPrekeys(newPrekeys.map(p => ({
                id: p.id,
                key: p.publicKey
            })));
            
            console.log('Prekeys replenished');
        }
    },
    
    // ==================== API CALLS ====================
    
    /**
     * Upload key bundle to server
     * @param {object} bundle 
     */
    async uploadKeyBundle(bundle) {
        const response = await fetch(`${this.apiBaseUrl}/keys/bundle`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.accessToken}`
            },
            body: JSON.stringify(bundle)
        });
        
        if (!response.ok) {
            throw new Error('Failed to upload key bundle');
        }
        
        return await response.json();
    },
    
    /**
     * Upload additional one-time prekeys
     * @param {Array} prekeys 
     */
    async uploadPrekeys(prekeys) {
        const response = await fetch(`${this.apiBaseUrl}/keys/bundle/prekeys`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.accessToken}`
            },
            body: JSON.stringify(prekeys)
        });
        
        if (!response.ok) {
            throw new Error('Failed to upload prekeys');
        }
        
        return await response.json();
    },
    
    /**
     * Fetch recipient's key bundle from server
     * @param {string} recipientId 
     * @returns {Promise<object>}
     */
    async fetchKeyBundle(recipientId) {
        const response = await fetch(`${this.apiBaseUrl}/keys/bundle/${recipientId}`, {
            headers: {
                'Authorization': `Bearer ${this.accessToken}`
            }
        });
        
        if (!response.ok) {
            if (response.status === 404) {
                throw new Error('Recipient has no encryption keys');
            }
            throw new Error('Failed to fetch key bundle');
        }
        
        return await response.json();
    },
    
    // ==================== SESSION MANAGEMENT ====================
    
    /**
     * Establish a session with a recipient
     * @param {string} recipientId 
     * @returns {Promise<object>} Session state
     */
    async establishSession(recipientId) {
        // Check if session already exists
        const existingSession = await KeyStore.getSession(recipientId);
        if (existingSession) {
            return existingSession;
        }
        
        console.log('Establishing new session with:', recipientId);
        
        // Get our identity keys
        const identity = await KeyStore.getIdentityKeys(this.userId);
        if (!identity) {
            throw new Error('No identity keys found');
        }
        
        // Fetch recipient's key bundle
        const bundle = await this.fetchKeyBundle(recipientId);
        
        // Verify and store recipient's identity key
        const verification = await KeyStore.verifyIdentityKey(recipientId, bundle.identity_key);
        if (verification.changed) {
            // Handle key change - could be legitimate device change or MITM attack
            console.warn('Recipient identity key changed!');
            // In production, you might want to show a warning to the user
        }
        
        // Perform X3DH
        const x3dhResult = await SignalProtocol.x3dhInitiate(identity, bundle);
        
        // Initialize Double Ratchet as sender
        const session = await SignalProtocol.initSenderRatchet(
            x3dhResult.sessionKey,
            bundle.signed_prekey  // Use signed prekey as initial ratchet key
        );
        
        // Add metadata for initial message (includes recipient's prekey IDs)
        session._x3dh = {
            ephemeralPublicKey: x3dhResult.ephemeralPublicKey,
            usedOtpId: x3dhResult.usedOtpId,
            signedPrekeyId: bundle.signed_prekey_id  // Recipient's signed prekey ID
        };
        
        // Save session
        await KeyStore.saveSession(recipientId, session);
        
        return session;
    },
    
    /**
     * Process an incoming initial message to establish session
     * @param {string} senderId 
     * @param {object} x3dhInfo - Sender's X3DH info from message
     * @returns {Promise<object>} Session state
     */
    async processInitialMessage(senderId, x3dhInfo) {
        console.log('Processing initial message from:', senderId);
        
        // Get our identity keys
        const identity = await KeyStore.getIdentityKeys(this.userId);
        if (!identity) {
            throw new Error('No identity keys found');
        }
        
        // Get our signed prekey
        const signedPrekey = await KeyStore.getSignedPrekey(x3dhInfo.signedPrekeyId);
        if (!signedPrekey) {
            throw new Error('Signed prekey not found');
        }
        
        // Get one-time prekey if used
        let oneTimePrekey = null;
        if (x3dhInfo.oneTimePrekeyId) {
            oneTimePrekey = await KeyStore.getOneTimePrekey(x3dhInfo.oneTimePrekeyId);
            if (!oneTimePrekey) {
                // OTP was specified but not found - this is an error
                // The sender used an OTP we don't have, so session key will be wrong
                throw new Error('One-time prekey not found - key may have been used by another session');
            }
            // Remove used one-time prekey
            await KeyStore.removeOneTimePrekey(x3dhInfo.oneTimePrekeyId);
        }
        
        // Verify and store sender's identity key
        await KeyStore.verifyIdentityKey(senderId, x3dhInfo.identityKey);
        
        // Perform X3DH as responder
        const sessionKey = await SignalProtocol.x3dhRespond(
            identity,
            signedPrekey,
            oneTimePrekey,
            x3dhInfo.identityKey,
            x3dhInfo.ephemeralKey
        );
        
        // Initialize Double Ratchet as receiver
        const session = SignalProtocol.initReceiverRatchet(sessionKey, signedPrekey);
        
        // Save session
        await KeyStore.saveSession(senderId, session);
        
        // Check if we need to replenish prekeys
        await this.checkAndReplenishPrekeys();
        
        return session;
    },
    
    // ==================== MESSAGE ENCRYPTION ====================
    
    /**
     * Encrypt a message for a recipient
     * @param {string} recipientId 
     * @param {string} plaintext 
     * @returns {Promise<object>} Encrypted message
     */
    async encryptMessage(recipientId, plaintext) {
        if (!this.initialized) {
            throw new Error('E2EE not initialized');
        }
        
        // Get or establish session
        let session = await KeyStore.getSession(recipientId);
        let isInitialMessage = false;
        let x3dhInfo = null;
        
        if (!session) {
            session = await this.establishSession(recipientId);
            isInitialMessage = true;
            // Capture x3dh info before it's potentially modified
            x3dhInfo = session._x3dh ? { ...session._x3dh } : null;
        }
        
        // Encrypt with Double Ratchet
        const result = await SignalProtocol.ratchetEncrypt(session, plaintext);
        
        // Clear x3dh from state after first message (no longer needed)
        if (isInitialMessage) {
            delete result.state._x3dh;
        }
        
        // Save updated session
        await KeyStore.saveSession(recipientId, result.state);
        
        // Build encrypted message
        const encryptedMessage = {
            header: result.message.header,
            ciphertext: result.message.ciphertext,
            nonce: result.message.nonce
        };
        
        // Include X3DH info for initial message
        if (isInitialMessage && x3dhInfo) {
            const identity = await KeyStore.getIdentityKeys(this.userId);
            
            encryptedMessage.x3dh = {
                identityKey: identity.identityKey.publicKey,
                ephemeralKey: x3dhInfo.ephemeralPublicKey,
                signedPrekeyId: x3dhInfo.signedPrekeyId,
                oneTimePrekeyId: x3dhInfo.usedOtpId
            };
        }
        
        return encryptedMessage;
    },
    
    /**
     * Decrypt a message from a sender
     * @param {string} senderId 
     * @param {object} encryptedMessage 
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decryptMessage(senderId, encryptedMessage, messageId = null) {
        if (!this.initialized) {
            throw new Error('E2EE not initialized');
        }
        
        // Check cache first (for historical messages that were already decrypted)
        if (messageId && this._decryptedCache.has(messageId)) {
            return this._decryptedCache.get(messageId);
        }
        
        // Get existing session first
        let session = await KeyStore.getSession(senderId);
        
        // Check if this is an initial message
        if (encryptedMessage.x3dh) {
            if (session) {
                // Session already exists - this could be:
                // 1. A replay attack
                // 2. A race condition where both users sent first message
                // 3. The sender re-established session (device change)
                // 4. Historical message being re-loaded (most common)
                // For security, we should use the existing session and try to decrypt
                // If decryption fails, we can try establishing new session
                console.warn('Received X3DH message but session already exists for:', senderId);
                
                try {
                    // Try with existing session first
                    const result = await SignalProtocol.ratchetDecrypt(session, encryptedMessage);
                    await KeyStore.saveSession(senderId, result.state);
                    // Cache the result
                    if (messageId) {
                        this._decryptedCache.set(messageId, result.plaintext);
                    }
                    return result.plaintext;
                } catch (e) {
                    // Existing session failed - likely this is a historical message
                    // that was already decrypted and the ratchet has moved forward
                    console.warn('Existing session failed:', e.message);
                    
                    // Check if OTP exists before trying to create new session
                    const identity = await KeyStore.getIdentityKeys(this.userId);
                    const oneTimePrekey = encryptedMessage.x3dh.oneTimePrekeyId ? 
                        await KeyStore.getOneTimePrekey(encryptedMessage.x3dh.oneTimePrekeyId) : null;
                    
                    if (encryptedMessage.x3dh.oneTimePrekeyId && !oneTimePrekey) {
                        // OTP was used but is gone - this is a historical message
                        // that we can't re-decrypt. Return placeholder.
                        console.warn('Historical message cannot be re-decrypted (OTP used)');
                        throw new Error('Historical message - already decrypted previously');
                    }
                    
                    // OTP exists or not needed, try establishing new session
                    console.warn('Trying new X3DH session');
                    await this.processInitialMessage(senderId, encryptedMessage.x3dh);
                    session = await KeyStore.getSession(senderId);
                }
            } else {
                // No existing session - establish new one
                await this.processInitialMessage(senderId, encryptedMessage.x3dh);
                session = await KeyStore.getSession(senderId);
            }
        }
        
        if (!session) {
            throw new Error('No session found for sender');
        }
        
        // Decrypt with Double Ratchet
        const result = await SignalProtocol.ratchetDecrypt(session, encryptedMessage);
        
        // Save updated session
        await KeyStore.saveSession(senderId, result.state);
        
        // Cache the result
        if (messageId) {
            this._decryptedCache.set(messageId, result.plaintext);
        }
        
        return result.plaintext;
    },
    
    // ==================== GROUP ENCRYPTION ====================
    
    /**
     * Initialize group encryption for a group
     * @param {string} groupId 
     * @param {Array<string>} memberIds 
     */
    async initGroupEncryption(groupId, memberIds) {
        console.log('Initializing group encryption for:', groupId);
        
        // Generate our sender key for this group
        const senderKey = await SignalProtocol.generateSenderKey();
        await KeyStore.saveSenderKey(groupId, this.userId, senderKey);
        
        // Create distribution message
        const distribution = SignalProtocol.createSenderKeyDistribution(groupId, senderKey);
        
        // Encrypt and send distribution to each member
        for (const memberId of memberIds) {
            if (memberId === this.userId) continue;
            
            const encryptedDist = await this.encryptMessage(
                memberId,
                JSON.stringify({
                    type: 'sender_key_distribution',
                    ...distribution
                })
            );
            
            // This should be sent via the existing message channel
            // The caller should handle actually sending this
        }
        
        return distribution;
    },
    
    /**
     * Process a received sender key distribution
     * @param {string} senderId 
     * @param {object} distribution 
     */
    async processSenderKeyDistribution(senderId, distribution) {
        console.log('Processing sender key distribution from:', senderId);
        
        const senderKey = {
            chainKey: distribution.chainKey,
            signingPublicKey: distribution.signingPublicKey,
            iteration: distribution.iteration
        };
        
        await KeyStore.saveSenderKey(distribution.groupId, senderId, senderKey);
    },
    
    /**
     * Encrypt a group message
     * @param {string} groupId 
     * @param {string} plaintext 
     * @returns {Promise<object>}
     */
    async encryptGroupMessage(groupId, plaintext) {
        // Get our sender key for this group
        let senderKey = await KeyStore.getSenderKey(groupId, this.userId);
        let includeDistribution = false;
        
        if (!senderKey) {
            // Auto-generate sender key for first message in group
            console.log('Auto-generating sender key for group:', groupId);
            senderKey = await SignalProtocol.generateSenderKey();
            await KeyStore.saveSenderKey(groupId, this.userId, senderKey);
            includeDistribution = true;  // Include distribution with first message
        }
        
        // Encrypt with Sender Key
        const result = await SignalProtocol.senderKeyEncrypt(senderKey, plaintext);
        
        // Save updated sender key
        await KeyStore.saveSenderKey(groupId, this.userId, result.senderKey);
        
        const response = {
            senderId: this.userId,
            groupMessage: result.message
        };
        
        // Include sender key distribution for new keys
        // This allows recipients to decrypt without prior key exchange
        if (includeDistribution) {
            response.senderKeyDistribution = {
                groupId: groupId,
                chainKey: senderKey.chainKey,
                signingPublicKey: senderKey.signingKey.publicKey,
                iteration: 0  // Distribution always starts at 0
            };
        }
        
        return response;
    },
    
    /**
     * Decrypt a group message
     * @param {string} groupId 
     * @param {string} senderId 
     * @param {object} groupMessage 
     * @param {object} senderKeyDistribution - Optional sender key distribution
     * @returns {Promise<string>}
     */
    async decryptGroupMessage(groupId, senderId, groupMessage, senderKeyDistribution = null) {
        // Process sender key distribution if provided
        if (senderKeyDistribution) {
            console.log('Processing inline sender key distribution from:', senderId);
            await this.processSenderKeyDistribution(senderId, senderKeyDistribution);
        }
        
        // Get sender's key for this group
        let senderKey = await KeyStore.getSenderKey(groupId, senderId);
        
        if (!senderKey) {
            throw new Error('No sender key from this sender. Request key distribution.');
        }
        
        // Decrypt with Sender Key
        const result = await SignalProtocol.senderKeyDecrypt(senderKey, groupMessage);
        
        // Save updated sender key
        await KeyStore.saveSenderKey(groupId, senderId, result.senderKey);
        
        return result.plaintext;
    },
    
    // ==================== FILE ENCRYPTION ====================
    
    /**
     * Encrypt a file
     * @param {ArrayBuffer} fileData 
     * @returns {Promise<{encryptedData: ArrayBuffer, key: string, nonce: string}>}
     */
    async encryptFile(fileData) {
        // Generate random key for file
        const fileKey = CryptoUtils.randomBytes(32);
        
        // Encrypt file data
        const encrypted = await CryptoUtils.encrypt(fileData, fileKey.buffer);
        
        return {
            encryptedData: CryptoUtils.base64ToArrayBuffer(encrypted.ciphertext),
            key: CryptoUtils.arrayBufferToBase64(fileKey),
            nonce: encrypted.nonce
        };
    },
    
    /**
     * Decrypt a file
     * @param {ArrayBuffer} encryptedData 
     * @param {string} key - Base64 encoded key
     * @param {string} nonce - Base64 encoded nonce
     * @returns {Promise<ArrayBuffer>}
     */
    async decryptFile(encryptedData, key, nonce) {
        const keyBuffer = CryptoUtils.base64ToArrayBuffer(key);
        const ciphertextBase64 = CryptoUtils.arrayBufferToBase64(encryptedData);
        
        // Use decryptRaw to preserve binary data
        return await CryptoUtils.decryptRaw(ciphertextBase64, nonce, keyBuffer);
    },
    
    // ==================== UTILITIES ====================
    
    /**
     * Get encryption status
     * @returns {Promise<object>}
     */
    async getStatus() {
        const hasIdentity = await KeyStore.hasIdentityKeys(this.userId);
        const prekeyCount = await KeyStore.countOneTimePrekeys();
        
        return {
            initialized: this.initialized,
            hasIdentityKeys: hasIdentity,
            remainingPrekeys: prekeyCount,
            needsReplenishment: prekeyCount < 20
        };
    },
    
    /**
     * Clear E2EE state (for logout)
     * Does NOT clear keys - they are preserved for next login
     */
    async clear() {
        // Clear decrypted message cache
        this._decryptedCache.clear();
        
        // Reset state
        this.initialized = false;
        this.userId = null;
        
        console.log('E2EE state cleared (keys preserved)');
    },
    
    /**
     * Export identity key for verification (Safety Number)
     * Returns the same number for both parties
     * @param {string} recipientId 
     * @returns {Promise<string>} Safety number
     */
    async getSafetyNumber(recipientId) {
        const ourIdentity = await KeyStore.getIdentityKeys(this.userId);
        const theirIdentity = await KeyStore.getTrustedKey(recipientId);
        
        if (!ourIdentity || !theirIdentity) {
            return null;
        }
        
        // Sort keys to ensure same result for both parties
        const ourKey = ourIdentity.identityKey.publicKey;
        const theirKey = theirIdentity.identityKey;
        
        // Combine in deterministic order (alphabetically)
        const combined = ourKey < theirKey 
            ? ourKey + theirKey 
            : theirKey + ourKey;
        
        const hash = await CryptoUtils.sha256(combined);
        
        // Convert to readable format (like Signal's safety number)
        const bytes = new Uint8Array(hash);
        let safetyNumber = '';
        
        for (let i = 0; i < 30; i++) {
            safetyNumber += (bytes[i] % 10).toString();
            if ((i + 1) % 5 === 0 && i < 29) {
                safetyNumber += ' ';
            }
        }
        
        return safetyNumber;
    }
};

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.E2EE = E2EE;
}
