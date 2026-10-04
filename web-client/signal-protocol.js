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
 * VibeMessenger Signal Protocol Implementation
 * 
 * Implements:
 * - X3DH (Extended Triple Diffie-Hellman) for session establishment
 * - Double Ratchet Algorithm for message encryption
 * 
 * Based on Signal Protocol specification:
 * https://signal.org/docs/specifications/x3dh/
 * https://signal.org/docs/specifications/doubleratchet/
 */

const SignalProtocol = {
    // Constants
    MAX_SKIP: 1000,  // Maximum messages to skip in a chain
    INFO_RATCHET: 'VibeMessenger_Ratchet',
    INFO_MESSAGE: 'VibeMessenger_MessageKeys',
    
    // ==================== X3DH KEY AGREEMENT ====================
    
    /**
     * Generate identity key pair (long-term)
     * @returns {Promise<{identityKey: object, signingKey: object}>}
     */
    async generateIdentityKeys() {
        const identityKey = await CryptoUtils.generateKeyPair();
        const signingKey = await CryptoUtils.generateSigningKeyPair();
        
        return {
            identityKey: {
                publicKey: identityKey.publicKey,
                privateKey: identityKey.privateKey
            },
            signingKey: {
                publicKey: signingKey.publicKey,
                privateKey: signingKey.privateKey
            }
        };
    },
    
    /**
     * Generate signed prekey (medium-term, rotate weekly)
     * @param {object} signingKey - Identity signing key
     * @param {number} prekeyId 
     * @returns {Promise<object>}
     */
    async generateSignedPrekey(signingKey, prekeyId) {
        const prekey = await CryptoUtils.generateKeyPair();
        
        // Sign the prekey with identity key
        const signature = await CryptoUtils.sign(
            prekey.publicKey,
            signingKey.privateKey
        );
        
        return {
            id: prekeyId,
            publicKey: prekey.publicKey,
            privateKey: prekey.privateKey,
            signature: signature
        };
    },
    
    /**
     * Generate one-time prekeys (consume once per session)
     * @param {number} startId 
     * @param {number} count 
     * @returns {Promise<Array>}
     */
    async generateOneTimePrekeys(startId, count = 100) {
        const prekeys = [];
        
        for (let i = 0; i < count; i++) {
            const prekey = await CryptoUtils.generateKeyPair();
            prekeys.push({
                id: startId + i,
                publicKey: prekey.publicKey,
                privateKey: prekey.privateKey
            });
        }
        
        return prekeys;
    },
    
    /**
     * Create key bundle for uploading to server
     * @param {object} identityKey - ECDH identity key
     * @param {object} signingKey - ECDSA signing key
     * @param {object} signedPrekey 
     * @param {Array} oneTimePrekeys 
     * @returns {object}
     */
    createKeyBundle(identityKey, signingKey, signedPrekey, oneTimePrekeys) {
        return {
            identity_key: identityKey.publicKey,
            signing_public_key: signingKey.publicKey,  // ECDSA key for signature verification
            signed_prekey_id: signedPrekey.id,
            signed_prekey: signedPrekey.publicKey,
            signed_prekey_signature: signedPrekey.signature,
            one_time_prekeys: oneTimePrekeys.map(otp => ({
                id: otp.id,
                key: otp.publicKey
            }))
        };
    },
    
    /**
     * X3DH: Sender initiates session with recipient's key bundle
     * @param {object} senderIdentity - Sender's identity keys
     * @param {object} recipientBundle - Recipient's key bundle from server
     * @returns {Promise<{sessionKey: ArrayBuffer, ephemeralPublicKey: string, usedOtpId: number|null}>}
     */
    async x3dhInitiate(senderIdentity, recipientBundle) {
        // Generate ephemeral key pair
        const ephemeral = await CryptoUtils.generateKeyPair();
        
        // Verify signed prekey signature using ECDSA signing key
        // If signing_public_key is not available, skip verification (backward compatibility)
        if (recipientBundle.signing_public_key) {
            const isValid = await CryptoUtils.verify(
                recipientBundle.signed_prekey,
                recipientBundle.signed_prekey_signature,
                recipientBundle.signing_public_key  // Use ECDSA key, not ECDH identity key
            );
            
            if (!isValid) {
                throw new Error('Invalid signed prekey signature');
            }
        }
        
        // DH calculations:
        // DH1 = DH(IKa, SPKb)  - Sender identity, Recipient signed prekey
        // DH2 = DH(EKa, IKb)   - Sender ephemeral, Recipient identity
        // DH3 = DH(EKa, SPKb)  - Sender ephemeral, Recipient signed prekey
        // DH4 = DH(EKa, OPKb)  - Sender ephemeral, Recipient one-time prekey (optional)
        
        const dh1 = await CryptoUtils.ecdh(
            senderIdentity.identityKey.privateKey,
            recipientBundle.signed_prekey
        );
        
        const dh2 = await CryptoUtils.ecdh(
            ephemeral.privateKey,
            recipientBundle.identity_key
        );
        
        const dh3 = await CryptoUtils.ecdh(
            ephemeral.privateKey,
            recipientBundle.signed_prekey
        );
        
        let usedOtpId = null;
        let sharedSecret;
        
        if (recipientBundle.one_time_prekey) {
            // DH4 with one-time prekey
            const dh4 = await CryptoUtils.ecdh(
                ephemeral.privateKey,
                recipientBundle.one_time_prekey.key
            );
            usedOtpId = recipientBundle.one_time_prekey.id;
            
            sharedSecret = CryptoUtils.concatBuffers(dh1, dh2, dh3, dh4);
        } else {
            sharedSecret = CryptoUtils.concatBuffers(dh1, dh2, dh3);
        }
        
        // Derive session key using HKDF
        const sessionKey = await CryptoUtils.hkdf(
            sharedSecret,
            new Uint8Array(32), // salt
            'X3DH_VibeMessenger',
            32
        );
        
        return {
            sessionKey: sessionKey,
            ephemeralPublicKey: ephemeral.publicKey,
            usedOtpId: usedOtpId
        };
    },
    
    /**
     * X3DH: Recipient processes initial message to establish session
     * @param {object} recipientIdentity - Recipient's identity keys
     * @param {object} signedPrekey - Recipient's signed prekey
     * @param {object|null} oneTimePrekey - Used one-time prekey (if any)
     * @param {string} senderIdentityKey - Sender's identity public key
     * @param {string} senderEphemeralKey - Sender's ephemeral public key
     * @returns {Promise<ArrayBuffer>} Session key
     */
    async x3dhRespond(recipientIdentity, signedPrekey, oneTimePrekey, senderIdentityKey, senderEphemeralKey) {
        // DH calculations (mirror of initiate):
        // DH1 = DH(SPKb, IKa)
        // DH2 = DH(IKb, EKa)
        // DH3 = DH(SPKb, EKa)
        // DH4 = DH(OPKb, EKa) (optional)
        
        const dh1 = await CryptoUtils.ecdh(
            signedPrekey.privateKey,
            senderIdentityKey
        );
        
        const dh2 = await CryptoUtils.ecdh(
            recipientIdentity.identityKey.privateKey,
            senderEphemeralKey
        );
        
        const dh3 = await CryptoUtils.ecdh(
            signedPrekey.privateKey,
            senderEphemeralKey
        );
        
        let sharedSecret;
        
        if (oneTimePrekey) {
            const dh4 = await CryptoUtils.ecdh(
                oneTimePrekey.privateKey,
                senderEphemeralKey
            );
            sharedSecret = CryptoUtils.concatBuffers(dh1, dh2, dh3, dh4);
        } else {
            sharedSecret = CryptoUtils.concatBuffers(dh1, dh2, dh3);
        }
        
        // Derive session key using HKDF
        const sessionKey = await CryptoUtils.hkdf(
            sharedSecret,
            new Uint8Array(32),
            'X3DH_VibeMessenger',
            32
        );
        
        return sessionKey;
    },
    
    // ==================== DOUBLE RATCHET ====================
    
    /**
     * Initialize Double Ratchet state for sender (after X3DH)
     * @param {ArrayBuffer} sessionKey - From X3DH
     * @param {string} remotePublicKey - Recipient's ratchet public key
     * @returns {Promise<object>} Ratchet state
     */
    async initSenderRatchet(sessionKey, remotePublicKey) {
        // Generate our ratchet key pair
        const dhPair = await CryptoUtils.generateKeyPair();
        
        // Perform DH ratchet step
        const dhResult = await CryptoUtils.ecdh(dhPair.privateKey, remotePublicKey);
        
        // Derive root and chain keys
        const { rootKey, chainKey } = await CryptoUtils.deriveRootAndChainKey(
            CryptoUtils.concatBuffers(sessionKey, dhResult),
            this.INFO_RATCHET
        );
        
        return {
            DHs: dhPair,                    // Our current ratchet key pair
            DHr: remotePublicKey,           // Their current ratchet public key
            RK: rootKey,                    // Root key
            CKs: chainKey,                  // Sending chain key
            CKr: null,                      // Receiving chain key
            Ns: 0,                          // Sending message number
            Nr: 0,                          // Receiving message number
            PN: 0,                          // Previous chain message number
            MKSKIPPED: new Map()            // Skipped message keys
        };
    },
    
    /**
     * Initialize Double Ratchet state for recipient (after X3DH)
     * @param {ArrayBuffer} sessionKey - From X3DH
     * @param {object} dhPair - Our initial DH pair (usually signed prekey)
     * @returns {object} Ratchet state
     */
    initReceiverRatchet(sessionKey, dhPair) {
        return {
            DHs: dhPair,
            DHr: null,
            RK: sessionKey,
            CKs: null,
            CKr: null,
            Ns: 0,
            Nr: 0,
            PN: 0,
            MKSKIPPED: new Map()
        };
    },
    
    /**
     * Perform DH ratchet step
     * @param {object} state - Ratchet state
     * @param {string} remotePublicKey - New remote public key
     * @returns {Promise<object>} Updated state
     */
    async dhRatchet(state, remotePublicKey) {
        state.PN = state.Ns;
        state.Ns = 0;
        state.Nr = 0;
        state.DHr = remotePublicKey;
        
        // Calculate DH
        const dhResult = await CryptoUtils.ecdh(state.DHs.privateKey, state.DHr);
        
        // Derive new receiving chain key
        const receiving = await CryptoUtils.deriveRootAndChainKey(
            CryptoUtils.concatBuffers(state.RK, dhResult),
            this.INFO_RATCHET
        );
        state.RK = receiving.rootKey;
        state.CKr = receiving.chainKey;
        
        // Generate new DH key pair
        state.DHs = await CryptoUtils.generateKeyPair();
        
        // Calculate DH with new keys
        const dhResult2 = await CryptoUtils.ecdh(state.DHs.privateKey, state.DHr);
        
        // Derive new sending chain key
        const sending = await CryptoUtils.deriveRootAndChainKey(
            CryptoUtils.concatBuffers(state.RK, dhResult2),
            this.INFO_RATCHET
        );
        state.RK = sending.rootKey;
        state.CKs = sending.chainKey;
        
        return state;
    },
    
    /**
     * Derive message key from chain key
     * @param {ArrayBuffer} chainKey 
     * @returns {Promise<{messageKey: ArrayBuffer, nextChainKey: ArrayBuffer}>}
     */
    async deriveMessageKey(chainKey) {
        const messageKey = await CryptoUtils.hkdf(
            chainKey,
            new Uint8Array(32),
            'MessageKey',
            32
        );
        
        const nextChainKey = await CryptoUtils.hkdf(
            chainKey,
            new Uint8Array(32),
            'ChainKey',
            32
        );
        
        return { messageKey, nextChainKey };
    },
    
    /**
     * Encrypt a message using Double Ratchet
     * @param {object} state - Ratchet state
     * @param {string} plaintext - Message to encrypt
     * @returns {Promise<{state: object, message: object}>}
     */
    async ratchetEncrypt(state, plaintext) {
        // Derive message key
        const { messageKey, nextChainKey } = await this.deriveMessageKey(state.CKs);
        state.CKs = nextChainKey;
        
        // Encrypt message
        const header = {
            dh: state.DHs.publicKey,
            pn: state.PN,
            n: state.Ns
        };
        
        const headerStr = JSON.stringify(header);
        const encrypted = await CryptoUtils.encrypt(plaintext, messageKey, headerStr);
        
        state.Ns++;
        
        return {
            state: state,
            message: {
                header: header,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce
            }
        };
    },
    
    /**
     * Decrypt a message using Double Ratchet
     * @param {object} state - Ratchet state
     * @param {object} message - Encrypted message
     * @returns {Promise<{state: object, plaintext: string}>}
     */
    async ratchetDecrypt(state, message) {
        const { header, ciphertext, nonce } = message;
        
        // Try skipped message keys first
        const skippedKey = this.trySkippedMessageKeys(state, header);
        if (skippedKey) {
            const plaintext = await CryptoUtils.decrypt(
                ciphertext,
                nonce,
                skippedKey,
                JSON.stringify(header)
            );
            return { state, plaintext };
        }
        
        // Check if we need to perform DH ratchet
        if (header.dh !== state.DHr) {
            // Skip messages from previous chain
            await this.skipMessageKeys(state, header.pn);
            
            // Perform DH ratchet
            state = await this.dhRatchet(state, header.dh);
        }
        
        // Skip messages in current chain
        await this.skipMessageKeys(state, header.n);
        
        // Derive message key
        const { messageKey, nextChainKey } = await this.deriveMessageKey(state.CKr);
        state.CKr = nextChainKey;
        state.Nr++;
        
        // Decrypt
        const plaintext = await CryptoUtils.decrypt(
            ciphertext,
            nonce,
            messageKey,
            JSON.stringify(header)
        );
        
        return { state, plaintext };
    },
    
    /**
     * Try to decrypt with skipped message keys
     * @param {object} state 
     * @param {object} header 
     * @returns {ArrayBuffer|null}
     */
    trySkippedMessageKeys(state, header) {
        const key = `${header.dh}:${header.n}`;
        if (state.MKSKIPPED.has(key)) {
            const mk = state.MKSKIPPED.get(key);
            state.MKSKIPPED.delete(key);
            return mk;
        }
        return null;
    },
    
    /**
     * Store skipped message keys for out-of-order delivery
     * @param {object} state 
     * @param {number} until 
     */
    async skipMessageKeys(state, until) {
        if (state.Nr + this.MAX_SKIP < until) {
            throw new Error('Too many skipped messages');
        }
        
        if (state.CKr !== null) {
            while (state.Nr < until) {
                const { messageKey, nextChainKey } = await this.deriveMessageKey(state.CKr);
                state.CKr = nextChainKey;
                
                const key = `${state.DHr}:${state.Nr}`;
                state.MKSKIPPED.set(key, messageKey);
                state.Nr++;
            }
        }
    },
    
    // ==================== SESSION MANAGEMENT ====================
    
    /**
     * Serialize ratchet state for storage
     * @param {object} state 
     * @returns {object}
     */
    serializeState(state) {
        const skipped = [];
        for (const [key, value] of state.MKSKIPPED) {
            skipped.push({
                key: key,
                value: CryptoUtils.arrayBufferToBase64(value)
            });
        }
        
        return {
            DHs: {
                publicKey: state.DHs.publicKey,
                privateKey: state.DHs.privateKey
            },
            DHr: state.DHr,
            RK: state.RK ? CryptoUtils.arrayBufferToBase64(state.RK) : null,
            CKs: state.CKs ? CryptoUtils.arrayBufferToBase64(state.CKs) : null,
            CKr: state.CKr ? CryptoUtils.arrayBufferToBase64(state.CKr) : null,
            Ns: state.Ns,
            Nr: state.Nr,
            PN: state.PN,
            MKSKIPPED: skipped,
            _x3dh: state._x3dh || null  // Preserve X3DH metadata for initial message
        };
    },
    
    /**
     * Deserialize ratchet state from storage
     * @param {object} data 
     * @returns {object}
     */
    deserializeState(data) {
        const skipped = new Map();
        if (data.MKSKIPPED) {
            for (const item of data.MKSKIPPED) {
                skipped.set(item.key, CryptoUtils.base64ToArrayBuffer(item.value));
            }
        }
        
        return {
            DHs: data.DHs,
            DHr: data.DHr,
            RK: data.RK ? CryptoUtils.base64ToArrayBuffer(data.RK) : null,
            CKs: data.CKs ? CryptoUtils.base64ToArrayBuffer(data.CKs) : null,
            CKr: data.CKr ? CryptoUtils.base64ToArrayBuffer(data.CKr) : null,
            Ns: data.Ns,
            Nr: data.Nr,
            PN: data.PN,
            MKSKIPPED: skipped,
            _x3dh: data._x3dh || null  // Restore X3DH metadata
        };
    },
    
    // ==================== GROUP ENCRYPTION (Sender Keys) ====================
    
    /**
     * Generate a sender key for group messaging
     * @returns {Promise<object>}
     */
    async generateSenderKey() {
        const key = CryptoUtils.randomBytes(32);
        const signingKey = await CryptoUtils.generateSigningKeyPair();
        
        return {
            chainKey: CryptoUtils.arrayBufferToBase64(key),
            signingKey: signingKey,
            iteration: 0
        };
    },
    
    /**
     * Create a group session distribution message
     * @param {string} groupId 
     * @param {object} senderKey 
     * @returns {object}
     */
    createSenderKeyDistribution(groupId, senderKey) {
        return {
            groupId: groupId,
            chainKey: senderKey.chainKey,
            signingPublicKey: senderKey.signingKey.publicKey,
            iteration: senderKey.iteration
        };
    },
    
    /**
     * Encrypt a group message using Sender Key
     * @param {object} senderKey - Sender key state
     * @param {string} plaintext 
     * @returns {Promise<{senderKey: object, message: object}>}
     */
    async senderKeyEncrypt(senderKey, plaintext) {
        // Derive message key from chain key
        const chainKeyBuffer = CryptoUtils.base64ToArrayBuffer(senderKey.chainKey);
        const { messageKey, nextChainKey } = await this.deriveMessageKey(chainKeyBuffer);
        
        // Encrypt
        const encrypted = await CryptoUtils.encrypt(plaintext, messageKey);
        
        // Sign the ciphertext
        const signature = await CryptoUtils.sign(
            encrypted.ciphertext,
            senderKey.signingKey.privateKey
        );
        
        // Update sender key
        const newSenderKey = {
            ...senderKey,
            chainKey: CryptoUtils.arrayBufferToBase64(nextChainKey),
            iteration: senderKey.iteration + 1
        };
        
        return {
            senderKey: newSenderKey,
            message: {
                iteration: senderKey.iteration,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
                signature: signature
            }
        };
    },
    
    /**
     * Decrypt a group message using stored Sender Key
     * @param {object} storedSenderKey - Sender key from the message sender
     * @param {object} message 
     * @returns {Promise<{senderKey: object, plaintext: string}>}
     */
    async senderKeyDecrypt(storedSenderKey, message) {
        // Verify signature
        const isValid = await CryptoUtils.verify(
            message.ciphertext,
            message.signature,
            storedSenderKey.signingPublicKey
        );
        
        if (!isValid) {
            throw new Error('Invalid message signature');
        }
        
        // Check if message is too old (already processed)
        if (message.iteration < storedSenderKey.iteration) {
            throw new Error('Message iteration is too old - possible replay or out-of-order delivery');
        }
        
        // Check if we need to skip too many messages
        const skipCount = message.iteration - storedSenderKey.iteration;
        if (skipCount > this.MAX_SKIP) {
            throw new Error('Too many skipped group messages');
        }
        
        // Fast-forward chain key if needed
        let chainKeyBuffer = CryptoUtils.base64ToArrayBuffer(storedSenderKey.chainKey);
        let currentIteration = storedSenderKey.iteration;
        
        while (currentIteration < message.iteration) {
            const { nextChainKey } = await this.deriveMessageKey(chainKeyBuffer);
            chainKeyBuffer = nextChainKey;
            currentIteration++;
        }
        
        // Derive message key
        const { messageKey, nextChainKey } = await this.deriveMessageKey(chainKeyBuffer);
        
        // Decrypt
        const plaintext = await CryptoUtils.decrypt(
            message.ciphertext,
            message.nonce,
            messageKey
        );
        
        // Update stored sender key
        const newSenderKey = {
            ...storedSenderKey,
            chainKey: CryptoUtils.arrayBufferToBase64(nextChainKey),
            iteration: message.iteration + 1
        };
        
        return { senderKey: newSenderKey, plaintext };
    }
};

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.SignalProtocol = SignalProtocol;
}
