/**
 * VibeMessenger E2EE Crypto Module
 * 
 * Implements cryptographic primitives for Signal Protocol:
 * - X25519 key exchange (via Web Crypto API P-256 as fallback, or libsodium)
 * - AES-256-GCM encryption
 * - HKDF key derivation
 * - Ed25519 signatures (via ECDSA P-256 as fallback)
 * 
 * Note: Web Crypto API doesn't support X25519 directly in all browsers,
 * so we use ECDH with P-256 curve which provides similar security.
 */

const CryptoUtils = {
    // ==================== KEY GENERATION ====================
    
    /**
     * Generate an ECDH key pair for key exchange
     * @returns {Promise<{publicKey: string, privateKey: string}>} Base64 encoded keys
     */
    async generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true, // extractable
            ['deriveBits']
        );
        
        const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        
        return {
            publicKey: this.arrayBufferToBase64(publicKeyRaw),
            privateKey: JSON.stringify(privateKeyJwk),
            keyPair: keyPair // Keep CryptoKey objects for direct use
        };
    },
    
    /**
     * Generate a signing key pair (for signed prekeys)
     * @returns {Promise<{publicKey: string, privateKey: string}>}
     */
    async generateSigningKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );
        
        const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        
        return {
            publicKey: this.arrayBufferToBase64(publicKeyRaw),
            privateKey: JSON.stringify(privateKeyJwk),
            keyPair: keyPair
        };
    },
    
    /**
     * Import a public key from Base64
     * @param {string} publicKeyBase64 
     * @param {string} algorithm - 'ECDH' or 'ECDSA'
     * @returns {Promise<CryptoKey>}
     */
    async importPublicKey(publicKeyBase64, algorithm = 'ECDH') {
        const publicKeyRaw = this.base64ToArrayBuffer(publicKeyBase64);
        
        const usages = algorithm === 'ECDH' ? [] : ['verify'];
        
        return await crypto.subtle.importKey(
            'raw',
            publicKeyRaw,
            {
                name: algorithm,
                namedCurve: 'P-256'
            },
            true,
            usages
        );
    },
    
    /**
     * Import a private key from JWK string
     * @param {string} privateKeyJwk 
     * @param {string} algorithm
     * @returns {Promise<CryptoKey>}
     */
    async importPrivateKey(privateKeyJwk, algorithm = 'ECDH') {
        const jwk = typeof privateKeyJwk === 'string' ? JSON.parse(privateKeyJwk) : privateKeyJwk;
        
        const usages = algorithm === 'ECDH' ? ['deriveBits'] : ['sign'];
        
        return await crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: algorithm,
                namedCurve: 'P-256'
            },
            true,
            usages
        );
    },
    
    // ==================== ECDH KEY EXCHANGE ====================
    
    /**
     * Perform ECDH to derive shared secret
     * @param {CryptoKey|string} privateKey - Our private key
     * @param {CryptoKey|string} publicKey - Their public key
     * @returns {Promise<ArrayBuffer>} Shared secret (32 bytes)
     */
    async ecdh(privateKey, publicKey) {
        // Import keys if they're strings
        if (typeof privateKey === 'string') {
            privateKey = await this.importPrivateKey(privateKey, 'ECDH');
        }
        if (typeof publicKey === 'string') {
            publicKey = await this.importPublicKey(publicKey, 'ECDH');
        }
        
        const sharedBits = await crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: publicKey
            },
            privateKey,
            256 // 32 bytes
        );
        
        return sharedBits;
    },
    
    // ==================== HKDF KEY DERIVATION ====================
    
    /**
     * HKDF-SHA256 key derivation
     * @param {ArrayBuffer} inputKeyMaterial 
     * @param {ArrayBuffer|string} salt 
     * @param {ArrayBuffer|string} info 
     * @param {number} length - Output length in bytes
     * @returns {Promise<ArrayBuffer>}
     */
    async hkdf(inputKeyMaterial, salt, info, length = 32) {
        // Convert strings to ArrayBuffer
        if (typeof salt === 'string') {
            salt = new TextEncoder().encode(salt);
        }
        if (typeof info === 'string') {
            info = new TextEncoder().encode(info);
        }
        
        // Import IKM as HKDF key
        const hkdfKey = await crypto.subtle.importKey(
            'raw',
            inputKeyMaterial,
            'HKDF',
            false,
            ['deriveBits']
        );
        
        // Derive bits
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: info
            },
            hkdfKey,
            length * 8
        );
        
        return derivedBits;
    },
    
    /**
     * Derive multiple keys from shared secret using HKDF
     * @param {ArrayBuffer} sharedSecret 
     * @param {string} info 
     * @returns {Promise<{rootKey: ArrayBuffer, chainKey: ArrayBuffer}>}
     */
    async deriveRootAndChainKey(sharedSecret, info = 'VibeMessenger_RootKey') {
        const derived = await this.hkdf(sharedSecret, new Uint8Array(32), info, 64);
        
        return {
            rootKey: derived.slice(0, 32),
            chainKey: derived.slice(32, 64)
        };
    },
    
    // ==================== AES-256-GCM ENCRYPTION ====================
    
    /**
     * Encrypt data with AES-256-GCM
     * @param {string|ArrayBuffer} plaintext 
     * @param {ArrayBuffer} key - 32 bytes
     * @param {ArrayBuffer} [associatedData] - Optional AAD
     * @returns {Promise<{ciphertext: string, nonce: string}>} Base64 encoded
     */
    async encrypt(plaintext, key, associatedData = null) {
        // Convert plaintext to ArrayBuffer if string
        const plaintextBuffer = typeof plaintext === 'string' 
            ? new TextEncoder().encode(plaintext)
            : plaintext;
        
        // Generate random 12-byte nonce
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        
        // Import key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        // Encrypt
        const algorithm = {
            name: 'AES-GCM',
            iv: nonce,
            tagLength: 128
        };
        
        if (associatedData) {
            algorithm.additionalData = typeof associatedData === 'string'
                ? new TextEncoder().encode(associatedData)
                : associatedData;
        }
        
        const ciphertext = await crypto.subtle.encrypt(
            algorithm,
            aesKey,
            plaintextBuffer
        );
        
        return {
            ciphertext: this.arrayBufferToBase64(ciphertext),
            nonce: this.arrayBufferToBase64(nonce)
        };
    },
    
    /**
     * Decrypt data with AES-256-GCM
     * @param {string} ciphertextBase64 
     * @param {string} nonceBase64 
     * @param {ArrayBuffer} key 
     * @param {ArrayBuffer} [associatedData]
     * @returns {Promise<string>} Decrypted plaintext
     */
    async decrypt(ciphertextBase64, nonceBase64, key, associatedData = null) {
        const ciphertext = this.base64ToArrayBuffer(ciphertextBase64);
        const nonce = this.base64ToArrayBuffer(nonceBase64);
        
        // Import key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const algorithm = {
            name: 'AES-GCM',
            iv: nonce,
            tagLength: 128
        };
        
        if (associatedData) {
            algorithm.additionalData = typeof associatedData === 'string'
                ? new TextEncoder().encode(associatedData)
                : associatedData;
        }
        
        const plaintext = await crypto.subtle.decrypt(
            algorithm,
            aesKey,
            ciphertext
        );
        
        return new TextDecoder().decode(plaintext);
    },
    
    /**
     * Decrypt binary data with AES-256-GCM (returns ArrayBuffer)
     * Use this for files and binary data that may not be valid UTF-8
     * @param {string} ciphertextBase64 
     * @param {string} nonceBase64 
     * @param {ArrayBuffer} key 
     * @param {ArrayBuffer} [associatedData]
     * @returns {Promise<ArrayBuffer>} Decrypted data
     */
    async decryptRaw(ciphertextBase64, nonceBase64, key, associatedData = null) {
        const ciphertext = this.base64ToArrayBuffer(ciphertextBase64);
        const nonce = this.base64ToArrayBuffer(nonceBase64);
        
        // Import key
        const aesKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        // Decrypt
        const algorithm = {
            name: 'AES-GCM',
            iv: nonce,
            tagLength: 128
        };
        
        if (associatedData) {
            algorithm.additionalData = typeof associatedData === 'string'
                ? new TextEncoder().encode(associatedData)
                : associatedData;
        }
        
        return await crypto.subtle.decrypt(
            algorithm,
            aesKey,
            ciphertext
        );
    },
    
    // ==================== SIGNATURES ====================
    
    /**
     * Sign data with ECDSA
     * @param {ArrayBuffer|string} data 
     * @param {CryptoKey|string} privateKey 
     * @returns {Promise<string>} Base64 encoded signature
     */
    async sign(data, privateKey) {
        const dataBuffer = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;
        
        if (typeof privateKey === 'string') {
            privateKey = await this.importPrivateKey(privateKey, 'ECDSA');
        }
        
        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            privateKey,
            dataBuffer
        );
        
        return this.arrayBufferToBase64(signature);
    },
    
    /**
     * Verify signature with ECDSA
     * @param {ArrayBuffer|string} data 
     * @param {string} signatureBase64 
     * @param {CryptoKey|string} publicKey 
     * @returns {Promise<boolean>}
     */
    async verify(data, signatureBase64, publicKey) {
        const dataBuffer = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;
        const signature = this.base64ToArrayBuffer(signatureBase64);
        
        if (typeof publicKey === 'string') {
            publicKey = await this.importPublicKey(publicKey, 'ECDSA');
        }
        
        return await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            publicKey,
            signature,
            dataBuffer
        );
    },
    
    // ==================== UTILITIES ====================
    
    /**
     * Generate random bytes
     * @param {number} length 
     * @returns {Uint8Array}
     */
    randomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    },
    
    /**
     * Convert ArrayBuffer to Base64
     * @param {ArrayBuffer} buffer 
     * @returns {string}
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },
    
    /**
     * Convert Base64 to ArrayBuffer
     * @param {string} base64 
     * @returns {ArrayBuffer}
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },
    
    /**
     * Concatenate multiple ArrayBuffers
     * @param  {...ArrayBuffer} buffers 
     * @returns {ArrayBuffer}
     */
    concatBuffers(...buffers) {
        const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const buf of buffers) {
            result.set(new Uint8Array(buf), offset);
            offset += buf.byteLength;
        }
        return result.buffer;
    },
    
    /**
     * Compare two ArrayBuffers for equality (constant-time)
     * @param {ArrayBuffer} a 
     * @param {ArrayBuffer} b 
     * @returns {boolean}
     */
    constantTimeEqual(a, b) {
        const viewA = new Uint8Array(a);
        const viewB = new Uint8Array(b);
        
        if (viewA.length !== viewB.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < viewA.length; i++) {
            result |= viewA[i] ^ viewB[i];
        }
        
        return result === 0;
    },
    
    /**
     * SHA-256 hash
     * @param {ArrayBuffer|string} data 
     * @returns {Promise<ArrayBuffer>}
     */
    async sha256(data) {
        const dataBuffer = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;
        
        return await crypto.subtle.digest('SHA-256', dataBuffer);
    },
    
    /**
     * Generate a unique ID
     * @returns {string}
     */
    generateId() {
        return this.arrayBufferToBase64(this.randomBytes(16)).replace(/[+/=]/g, '');
    }
};

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.CryptoUtils = CryptoUtils;
}
