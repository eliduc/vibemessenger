/**
 * VibeMessenger Biometric Authentication Module
 * Version: 3.10.0
 *
 * Provides:
 * - Passkey registration (Settings → Security)
 * - Passkey login (login screen)
 * - Step-up biometric verification (sensitive actions)
 * - App lock (biometric screen lock on inactivity)
 * - Credential management (list, rename, delete)
 *
 * Uses Web Authentication API (WebAuthn / FIDO2).
 * Works with Windows Hello, Face ID, Touch ID, Android biometrics.
 *
 * Dependencies: api() from app.js, showConfirm(), showAlert()
 */

// ============== Base64URL Helpers ==============

const BiometricBase64 = {
    /**
     * Decode base64url string to ArrayBuffer.
     * Handles both standard base64 and base64url.
     */
    decode(base64url) {
        if (!base64url) return new ArrayBuffer(0);
        // Convert base64url to standard base64
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding
        while (base64.length % 4 !== 0) {
            base64 += '=';
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    /**
     * Encode ArrayBuffer to base64url string.
     */
    encode(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    },
};

// ============== Feature Detection ==============

const BiometricAuth = {
    _available: null,
    _lockTimer: null,
    _lockTimeoutMinutes: 0, // 0 = disabled
    _isLocked: false,
    _lastActivity: Date.now(),

    /**
     * Check if WebAuthn with platform authenticator is available.
     * Returns true if the device supports biometric/PIN authentication.
     */
    async isAvailable() {
        if (this._available !== null) return this._available;

        try {
            if (!window.PublicKeyCredential) {
                this._available = false;
                return false;
            }

            // Check for platform authenticator (built-in biometric)
            if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
                this._available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            } else {
                this._available = false;
            }
        } catch (e) {
            console.warn('[Biometric] Availability check failed:', e);
            this._available = false;
        }

        console.log('[Biometric] Platform authenticator available:', this._available);
        return this._available;
    },

    // ============== Registration ==============

    /**
     * Register a new passkey for the current user.
     * @param {string} deviceName - Human-readable name for this passkey
     * @returns {Promise<{success: boolean, error?: string}>}
     */
    async registerPasskey(deviceName = 'Passkey') {
        try {
            // 1. Get registration options from server
            const optionsRes = await api('/webauthn/register/options', {
                method: 'POST',
                body: JSON.stringify({ device_name: deviceName }),
            });

            if (!optionsRes.ok) {
                const err = await optionsRes.json();
                return { success: false, error: err.detail || err.error || 'Failed to get options' };
            }

            const options = await optionsRes.json();

            // 2. Convert base64url fields to ArrayBuffers for WebAuthn API
            const publicKeyOptions = {
                challenge: BiometricBase64.decode(options.challenge),
                rp: options.rp,
                user: {
                    ...options.user,
                    id: BiometricBase64.decode(options.user.id),
                },
                pubKeyCredParams: options.pubKeyCredParams,
                timeout: options.timeout,
                attestation: options.attestation || 'none',
                authenticatorSelection: options.authenticatorSelection,
            };

            // Add excludeCredentials if present
            if (options.excludeCredentials && options.excludeCredentials.length > 0) {
                publicKeyOptions.excludeCredentials = options.excludeCredentials.map(cred => ({
                    type: cred.type,
                    id: BiometricBase64.decode(cred.id),
                    transports: cred.transports,
                }));
            }

            // 3. Call browser WebAuthn API (triggers biometric prompt)
            console.log('[Biometric] Requesting credential creation...');
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions,
            });

            if (!credential) {
                return { success: false, error: 'Credential creation was cancelled' };
            }

            // 4. Serialize the credential response for the server
            const attestationResponse = credential.response;
            const credentialJSON = {
                id: credential.id,
                rawId: BiometricBase64.encode(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: BiometricBase64.encode(attestationResponse.clientDataJSON),
                    attestationObject: BiometricBase64.encode(attestationResponse.attestationObject),
                },
            };

            // Include transports if available
            if (typeof attestationResponse.getTransports === 'function') {
                credentialJSON.response.transports = attestationResponse.getTransports();
            }

            // 5. Send to server for verification
            const verifyRes = await api('/webauthn/register/verify', {
                method: 'POST',
                body: JSON.stringify({
                    credential: credentialJSON,
                    device_name: deviceName,
                }),
            });

            if (!verifyRes.ok) {
                const err = await verifyRes.json();
                return { success: false, error: err.detail || err.error || 'Verification failed' };
            }

            const result = await verifyRes.json();
            console.log('[Biometric] Passkey registered:', result.device_name);
            return { success: true };
        } catch (e) {
            console.error('[Biometric] Registration error:', e);

            // Handle specific browser errors
            if (e.name === 'NotAllowedError') {
                return { success: false, error: 'Authentication was cancelled or timed out' };
            }
            if (e.name === 'InvalidStateError') {
                return { success: false, error: 'A passkey is already registered on this device' };
            }
            if (e.name === 'SecurityError') {
                return { success: false, error: 'Security error. Ensure you are using HTTPS.' };
            }

            return { success: false, error: e.message || 'Unknown error' };
        }
    },

    // ============== Authentication (Login) ==============

    /**
     * Authenticate with a passkey (login without password).
     * @param {string} username - Optional username hint
     * @returns {Promise<{success: boolean, data?: object, error?: string}>}
     */
    async authenticateWithPasskey(username = '', totpCode = null) {  // КАО#180 (C2): totpCode for 2FA passkey login
        try {
            // 1. Get authentication options from server
            const optionsRes = await fetch(API_URL + '/webauthn/authenticate/options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username }),
            });

            if (!optionsRes.ok) {
                const err = await optionsRes.json();
                return { success: false, error: err.detail || err.error || 'Failed to get options' };
            }

            const options = await optionsRes.json();
            const sessionKey = options._session_key;

            // 2. Convert for WebAuthn API
            const publicKeyOptions = {
                challenge: BiometricBase64.decode(options.challenge),
                rpId: options.rpId,
                timeout: options.timeout,
                userVerification: options.userVerification,
            };

            if (options.allowCredentials && options.allowCredentials.length > 0) {
                publicKeyOptions.allowCredentials = options.allowCredentials.map(cred => ({
                    type: cred.type,
                    id: BiometricBase64.decode(cred.id),
                    transports: cred.transports,
                }));
            }

            // 3. Call browser WebAuthn API (triggers biometric prompt)
            console.log('[Biometric] Requesting authentication...');
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyOptions,
            });

            if (!assertion) {
                return { success: false, error: 'Authentication was cancelled' };
            }

            // 4. Serialize the assertion for the server
            const assertionResponse = assertion.response;
            const assertionJSON = {
                id: assertion.id,
                rawId: BiometricBase64.encode(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: BiometricBase64.encode(assertionResponse.clientDataJSON),
                    authenticatorData: BiometricBase64.encode(assertionResponse.authenticatorData),
                    signature: BiometricBase64.encode(assertionResponse.signature),
                },
                _session_key: sessionKey,
            };

            // Include userHandle if present (for discoverable credentials)
            if (assertionResponse.userHandle) {
                assertionJSON.response.userHandle = BiometricBase64.encode(assertionResponse.userHandle);
            }

            // 5. Send to server for verification (КАО#180: include TOTP code for 2FA-enabled accounts)
            const verifyRes = await fetch(API_URL + '/webauthn/authenticate/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credential: assertionJSON, totp_code: totpCode }),
            });

            if (!verifyRes.ok) {
                // КАО#180 (C2): server requires TOTP 2FA — prompt and retry the passkey assertion with the code
                if (verifyRes.status === 403 && verifyRes.headers.get('X-TOTP-Required') === 'true' && !totpCode) {
                    const code = (typeof prompt === 'function') ? prompt('Two-factor authentication: enter your TOTP or recovery code') : null;
                    if (!code || !code.trim()) return { success: false, error: 'TOTP code required' };
                    return await this.authenticateWithPasskey(username, code.trim());
                }
                const err = await verifyRes.json();
                return { success: false, error: err.detail || err.error || 'Authentication failed' };
            }

            const data = await verifyRes.json();
            console.log('[Biometric] Authentication successful:', data.user.username);
            return { success: true, data };
        } catch (e) {
            console.error('[Biometric] Authentication error:', e);

            if (e.name === 'NotAllowedError') {
                return { success: false, error: 'Authentication was cancelled or timed out' };
            }
            if (e.name === 'SecurityError') {
                return { success: false, error: 'Security error. Ensure you are using HTTPS.' };
            }

            return { success: false, error: e.message || 'Unknown error' };
        }
    },

    // ============== Step-Up Verification ==============

    /**
     * Perform biometric step-up verification for sensitive actions.
     * Returns a one-time verification token valid for ~2 minutes.
     *
     * @returns {Promise<{success: boolean, verifyToken?: string, error?: string}>}
     */
    async verifyBiometric() {
        try {
            // 1. Get verification options from server
            const optionsRes = await api('/webauthn/verify/options', {
                method: 'POST',
            });

            if (!optionsRes.ok) {
                const err = await optionsRes.json();
                // If no passkeys registered, signal to use password fallback
                if (optionsRes.status === 404) {
                    return { success: false, error: 'no_passkeys', noPasskeys: true };
                }
                return { success: false, error: err.detail || 'Failed to get options' };
            }

            const options = await optionsRes.json();

            // 2. Convert for WebAuthn API
            const publicKeyOptions = {
                challenge: BiometricBase64.decode(options.challenge),
                rpId: options.rpId,
                timeout: options.timeout,
                userVerification: options.userVerification,
            };

            if (options.allowCredentials && options.allowCredentials.length > 0) {
                publicKeyOptions.allowCredentials = options.allowCredentials.map(cred => ({
                    type: cred.type,
                    id: BiometricBase64.decode(cred.id),
                    transports: cred.transports,
                }));
            }

            // 3. Trigger biometric prompt
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyOptions,
            });

            if (!assertion) {
                return { success: false, error: 'Verification was cancelled' };
            }

            // 4. Serialize
            const assertionResponse = assertion.response;
            const assertionJSON = {
                id: assertion.id,
                rawId: BiometricBase64.encode(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: BiometricBase64.encode(assertionResponse.clientDataJSON),
                    authenticatorData: BiometricBase64.encode(assertionResponse.authenticatorData),
                    signature: BiometricBase64.encode(assertionResponse.signature),
                },
            };

            if (assertionResponse.userHandle) {
                assertionJSON.response.userHandle = BiometricBase64.encode(assertionResponse.userHandle);
            }

            // 5. Complete verification
            const verifyRes = await api('/webauthn/verify/complete', {
                method: 'POST',
                body: JSON.stringify({ credential: assertionJSON }),
            });

            if (!verifyRes.ok) {
                const err = await verifyRes.json();
                return { success: false, error: err.detail || 'Verification failed' };
            }

            const data = await verifyRes.json();
            console.log('[Biometric] Step-up verification successful');
            return { success: true, verifyToken: data.verify_token };
        } catch (e) {
            console.error('[Biometric] Verification error:', e);

            if (e.name === 'NotAllowedError') {
                return { success: false, error: 'Verification was cancelled or timed out' };
            }

            return { success: false, error: e.message || 'Unknown error' };
        }
    },

    /**
     * High-level helper: require biometric verification before a sensitive action.
     * Shows appropriate UI with password fallback.
     *
     * @param {string} actionDescription - Human-readable description shown to user
     * @returns {Promise<boolean|string>} false if cancelled/failed; `true` when no passkeys
     *   (no server step-up possible); a step-up token STRING when verified via biometric or
     *   password fallback (КАО#220 — caller forwards it as X-Verify-Token for server step-up).
     */
    async requireVerification(actionDescription) {
        // Check if user has passkeys registered
        const statusRes = await api('/webauthn/status');
        if (!statusRes.ok) return true; // If can't check, allow (don't block)

        const status = await statusRes.json();

        if (!status.enabled) {
            // No passkeys → skip biometric, rely on existing password checks
            return true;
        }

        // Has passkeys → try biometric verification
        const result = await this.verifyBiometric();
        if (result.success) {
            return result.verifyToken || true;  // v3.11.9: Return token for step-up
        }

        // v3.11.9: Always offer password fallback when biometric fails
        // (covers NotAllowedError, extension interference, timeout, etc.)
        return await this._showPasswordFallback(actionDescription);
    },

    /**
     * Show password input as fallback for biometric verification.
     * @returns {Promise<boolean>}
     */
    async _showPasswordFallback(actionDescription) {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'biometric-password-overlay';
            overlay.innerHTML = `
                <div class="biometric-password-dialog">
                    <div class="dialog-icon">🔑</div>
                    <h3>Password Required</h3>
                    <p>${actionDescription || 'Enter your password to continue'}</p>
                    <input type="password" class="biometric-password-input" placeholder="Password" autocomplete="current-password">
                    <div class="modal-actions">
                        <button class="btn biometric-cancel-btn">Cancel</button>
                        <button class="btn primary biometric-confirm-btn">Verify</button>
                    </div>
                    <div class="biometric-password-error hidden"></div>
                </div>
            `;
            document.body.appendChild(overlay);

            const input = overlay.querySelector('.biometric-password-input');
            const confirmBtn = overlay.querySelector('.biometric-confirm-btn');
            const cancelBtn = overlay.querySelector('.biometric-cancel-btn');
            const errorEl = overlay.querySelector('.biometric-password-error');

            const cleanup = () => {
                overlay.remove();
            };

            const handleConfirm = async () => {
                const password = input.value;
                if (!password) {
                    errorEl.textContent = 'Enter your password';
                    errorEl.classList.remove('hidden');
                    return;
                }

                confirmBtn.disabled = true;
                confirmBtn.textContent = 'Verifying...';

                try {
                    // v3.10.0: Verify password via dedicated endpoint
                    const response = await api('/auth/verify-password', {
                        method: 'POST',
                        body: JSON.stringify({ password }),
                    });

                    if (!response.ok) {
                        const err = await response.json().catch(() => ({}));
                        errorEl.textContent = err.detail || 'Server error, try again';
                        errorEl.classList.remove('hidden');
                        confirmBtn.disabled = false;
                        confirmBtn.textContent = 'Verify';
                        return;
                    }

                    const res = await response.json();

                    if (res.verified) {
                        cleanup();
                        // КАО#220 (SER#22): propagate the step-up token so the caller can send
                        // X-Verify-Token (password fallback now satisfies server-side step-up).
                        resolve(res.verify_token || true);
                    } else {
                        errorEl.textContent = 'Incorrect password';
                        errorEl.classList.remove('hidden');
                        confirmBtn.disabled = false;
                        confirmBtn.textContent = 'Verify';
                        input.value = '';
                        input.focus();
                    }
                } catch (e) {
                    errorEl.textContent = 'Verification failed';
                    errorEl.classList.remove('hidden');
                    confirmBtn.disabled = false;
                    confirmBtn.textContent = 'Verify';
                }
            };

            cancelBtn.onclick = () => {
                cleanup();
                resolve(false);
            };

            confirmBtn.onclick = handleConfirm;
            input.onkeydown = (e) => {
                if (e.key === 'Enter') handleConfirm();
            };

            setTimeout(() => input.focus(), 100);
        });
    },

    // ============== App Lock ==============

    /**
     * Initialize app lock with given timeout.
     * @param {number} timeoutMinutes - Lock after N minutes of inactivity. 0 = disabled.
     */
    initAppLock(timeoutMinutes) {
        this._lockTimeoutMinutes = timeoutMinutes;
        this._isLocked = false;
        this._lastActivity = Date.now();

        // Clear existing timer
        if (this._lockTimer) {
            clearInterval(this._lockTimer);
            this._lockTimer = null;
        }

        if (timeoutMinutes <= 0) {
            this._removeLockOverlay();
            return;
        }

        // Track user activity
        const activityEvents = ['mousedown', 'keydown', 'touchstart', 'scroll'];
        const resetActivity = () => {
            this._lastActivity = Date.now();
        };

        // Remove old listeners if any
        if (this._activityHandler) {
            activityEvents.forEach(evt => {
                document.removeEventListener(evt, this._activityHandler);
            });
        }
        this._activityHandler = resetActivity;
        activityEvents.forEach(evt => {
            document.addEventListener(evt, this._activityHandler, { passive: true });
        });

        // Check inactivity every 15 seconds
        this._lockTimer = setInterval(() => {
            if (this._isLocked) return;
            if (!state.user || !state.token) return; // Not logged in

            const elapsed = (Date.now() - this._lastActivity) / 1000 / 60;
            if (elapsed >= this._lockTimeoutMinutes) {
                this.lockApp();
            }
        }, 15000);

        // Also lock on visibility change (tab hidden / app switched)
        if (!this._visibilityHandler) {
            this._visibilityHandler = () => {
                if (document.hidden && this._lockTimeoutMinutes > 0 && state.user && state.token) {
                    // Start a short timer when app goes to background
                    this._backgroundTimer = setTimeout(() => {
                        this.lockApp();
                    }, Math.min(this._lockTimeoutMinutes * 60000, 60000)); // At most 1 min or lock timeout
                } else if (!document.hidden) {
                    if (this._backgroundTimer) {
                        clearTimeout(this._backgroundTimer);
                        this._backgroundTimer = null;
                    }
                }
            };
            document.addEventListener('visibilitychange', this._visibilityHandler);
        }

        console.log('[Biometric] App lock initialized:', timeoutMinutes, 'min');
    },

    /**
     * Lock the app UI, requiring biometric to unlock.
     */
    lockApp() {
        if (this._isLocked) return;
        if (!state.user || !state.token) return;

        this._isLocked = true;
        console.log('[Biometric] App locked');

        this._showLockOverlay();
    },

    /**
     * Show the lock overlay UI.
     */
    _showLockOverlay() {
        // Remove existing if any
        this._removeLockOverlay();

        const overlay = document.createElement('div');
        overlay.id = 'biometric-lock-overlay';
        overlay.className = 'biometric-lock-overlay';
        overlay.innerHTML = `
            <div class="biometric-lock-content">
                <div class="lock-icon">🔒</div>
                <h2>VibeMessenger</h2>
                <p class="lock-subtitle">Locked</p>
                <button class="btn primary lock-unlock-btn" id="biometric-unlock-btn">
                    <span class="unlock-icon">👆</span> Unlock
                </button>
                <div class="lock-error hidden" id="biometric-lock-error"></div>
                <button class="btn lock-logout-btn" id="biometric-lock-logout">Logout</button>
            </div>
        `;
        document.body.appendChild(overlay);

        // Force overlay on top of everything
        overlay.style.zIndex = '100000';

        document.getElementById('biometric-unlock-btn').onclick = () => this.unlockApp();
        document.getElementById('biometric-lock-logout').onclick = () => {
            this._removeLockOverlay();
            this._isLocked = false;
            if (typeof logout === 'function') logout();
        };

        // Auto-trigger biometric on show
        setTimeout(() => this.unlockApp(), 300);
    },

    /**
     * Attempt to unlock the app via biometric.
     */
    async unlockApp() {
        const errorEl = document.getElementById('biometric-lock-error');
        const unlockBtn = document.getElementById('biometric-unlock-btn');

        if (!errorEl || !unlockBtn) return;

        errorEl.classList.add('hidden');
        unlockBtn.disabled = true;
        unlockBtn.innerHTML = '<span class="unlock-icon">⏳</span> Verifying...';

        const result = await this.verifyBiometric();

        if (result.success) {
            this._isLocked = false;
            this._lastActivity = Date.now();
            this._removeLockOverlay();
            console.log('[Biometric] App unlocked');
            return;
        }

        // Failed
        unlockBtn.disabled = false;
        unlockBtn.innerHTML = '<span class="unlock-icon">👆</span> Unlock';

        if (result.error && result.error !== 'Verification was cancelled or timed out') {
            errorEl.textContent = result.error;
            errorEl.classList.remove('hidden');
        }
    },

    _removeLockOverlay() {
        const existing = document.getElementById('biometric-lock-overlay');
        if (existing) existing.remove();
    },

    /**
     * Get current lock timeout setting from localStorage.
     */
    getLockTimeout() {
        return parseInt(localStorage.getItem('biometric_lock_timeout') || '0', 10);
    },

    /**
     * Save lock timeout setting.
     */
    setLockTimeout(minutes) {
        localStorage.setItem('biometric_lock_timeout', String(minutes));
        this.initAppLock(minutes);
    },

    // ============== Credential Management ==============

    /**
     * Get list of registered credentials for current user.
     */
    async listCredentials() {
        const res = await api('/webauthn/credentials');
        if (!res.ok) return [];
        return await res.json();
    },

    /**
     * Rename a credential.
     */
    async renameCredential(credentialId, newName) {
        const res = await api(`/webauthn/credentials/${credentialId}`, {
            method: 'PUT',
            body: JSON.stringify({ device_name: newName }),
        });
        return res.ok;
    },

    /**
     * Delete a credential.
     */
    async deleteCredential(credentialId) {
        const res = await api(`/webauthn/credentials/${credentialId}`, {
            method: 'DELETE',
        });
        return res.ok;
    },

    /**
     * Get WebAuthn status for current user.
     */
    async getStatus() {
        const res = await api('/webauthn/status');
        if (!res.ok) return { enabled: false, credential_count: 0, credentials: [] };
        return await res.json();
    },

    /**
     * Check if a username has passkeys registered (public, for login screen).
     */
    async checkAvailable(username) {
        try {
            const res = await fetch(API_URL + `/webauthn/check/${encodeURIComponent(username)}`);
            if (!res.ok) return false;
            const data = await res.json();
            return data.available === true;
        } catch (e) {
            return false;
        }
    },

    // ============== Settings UI Helpers ==============

    /**
     * Render the passkeys management section in settings.
     * Called from showSettings().
     */
    async renderSettingsSection() {
        const container = document.getElementById('biometric-settings-content');
        if (!container) return;

        const available = await this.isAvailable();
        const status = await this.getStatus();

        let html = '';

        if (!available) {
            html = `
                <p class="biometric-not-available">
                    Biometric authentication is not available on this device/browser.
                </p>
            `;
            container.innerHTML = html;
            return;
        }

        // Register new passkey button
        html += `
            <button class="btn primary biometric-add-btn" onclick="BiometricAuth.showRegisterDialog()">
                <span>👆</span> Add Passkey
            </button>
        `;

        // List existing credentials
        if (status.credentials && status.credentials.length > 0) {
            html += '<div class="biometric-credentials-list">';
            for (const cred of status.credentials) {
                const lastUsed = cred.last_used_at
                    ? new Date(cred.last_used_at).toLocaleDateString()
                    : 'Never';
                html += `
                    <div class="biometric-credential-item" data-id="${cred.id}">
                        <div class="credential-info">
                            <span class="credential-icon">🔑</span>
                            <div class="credential-details">
                                <div class="credential-name">${this._escapeHtml(cred.device_name)}</div>
                                <div class="credential-meta">Last used: ${lastUsed}</div>
                            </div>
                        </div>
                        <div class="credential-actions">
                            <button class="icon-btn" onclick="BiometricAuth.showRenameDialog('${cred.id}', '${this._escapeHtml(cred.device_name)}')" title="Rename">✏️</button>
                            <button class="icon-btn" onclick="BiometricAuth.showDeleteDialog('${cred.id}', '${this._escapeHtml(cred.device_name)}')" title="Delete">🗑️</button>
                        </div>
                    </div>
                `;
            }
            html += '</div>';
        }

        // App lock settings (only show if passkeys exist)
        if (status.enabled) {
            const currentTimeout = this.getLockTimeout();
            html += `
                <div class="biometric-lock-settings">
                    <h4>App Lock</h4>
                    <p class="biometric-lock-description">Lock the app after a period of inactivity</p>
                    <div class="biometric-lock-options">
                        <button class="lock-option ${currentTimeout === 0 ? 'active' : ''}" onclick="BiometricAuth.setLockTimeoutUI(0)">Off</button>
                        <button class="lock-option ${currentTimeout === 1 ? 'active' : ''}" onclick="BiometricAuth.setLockTimeoutUI(1)">1 min</button>
                        <button class="lock-option ${currentTimeout === 5 ? 'active' : ''}" onclick="BiometricAuth.setLockTimeoutUI(5)">5 min</button>
                        <button class="lock-option ${currentTimeout === 15 ? 'active' : ''}" onclick="BiometricAuth.setLockTimeoutUI(15)">15 min</button>
                        <button class="lock-option ${currentTimeout === 30 ? 'active' : ''}" onclick="BiometricAuth.setLockTimeoutUI(30)">30 min</button>
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;
    },

    setLockTimeoutUI(minutes) {
        this.setLockTimeout(minutes);
        // Re-render to update active state
        this.renderSettingsSection();
        showLocalMessage('biometric-message', `App lock ${minutes > 0 ? `set to ${minutes} min` : 'disabled'}`, 'success');
    },

    /**
     * Show dialog to register a new passkey.
     */
    async showRegisterDialog() {
        const available = await this.isAvailable();
        if (!available) {
            await showAlert('Biometric authentication is not supported on this device.', 'Not Available', '⚠️');
            return;
        }

        // Prompt for device name
        const name = await this._promptInput(
            'Enter a name for this passkey',
            'Register Passkey',
            this._getDefaultDeviceName(),
        );

        if (!name) return; // Cancelled

        // Show loading
        showLocalMessage('biometric-message', 'Registering passkey...', 'info');

        const result = await this.registerPasskey(name);
        if (result.success) {
            showLocalMessage('biometric-message', 'Passkey registered successfully! ✓', 'success');
            this.renderSettingsSection();
        } else {
            showLocalMessage('biometric-message', result.error || 'Registration failed', 'error');
        }
    },

    /**
     * Show dialog to rename a credential.
     */
    async showRenameDialog(credentialId, currentName) {
        const newName = await this._promptInput(
            'Enter new name for this passkey',
            'Rename Passkey',
            currentName,
        );

        if (!newName || newName === currentName) return;

        const ok = await this.renameCredential(credentialId, newName);
        if (ok) {
            showLocalMessage('biometric-message', 'Passkey renamed ✓', 'success');
            this.renderSettingsSection();
        } else {
            showLocalMessage('biometric-message', 'Failed to rename passkey', 'error');
        }
    },

    /**
     * Show dialog to delete a credential.
     */
    async showDeleteDialog(credentialId, deviceName) {
        const confirmed = await showConfirm(
            `Remove passkey "${deviceName}"? You won't be able to use it for login or verification.`,
            'Remove Passkey',
            'Remove',
            'Cancel',
        );

        if (!confirmed) return;

        const ok = await this.deleteCredential(credentialId);
        if (ok) {
            showLocalMessage('biometric-message', 'Passkey removed ✓', 'success');
            this.renderSettingsSection();

            // If no more credentials, disable app lock
            const status = await this.getStatus();
            if (!status.enabled) {
                this.setLockTimeout(0);
            }
        } else {
            showLocalMessage('biometric-message', 'Failed to remove passkey', 'error');
        }
    },

    /**
     * Get a default device name based on User-Agent.
     */
    _getDefaultDeviceName() {
        const ua = navigator.userAgent;
        if (/Windows/.test(ua)) return 'Windows Hello';
        if (/iPhone|iPad/.test(ua)) return 'Face ID / Touch ID';
        if (/Macintosh/.test(ua)) return 'Touch ID (Mac)';
        if (/Android/.test(ua)) return 'Android Biometrics';
        if (/Linux/.test(ua)) return 'Linux Passkey';
        return 'Passkey';
    },

    /**
     * Prompt user for text input.
     */
    _promptInput(message, title, defaultValue = '') {
        return new Promise((resolve) => {
            const overlay = document.createElement('div');
            overlay.className = 'biometric-prompt-overlay';
            overlay.innerHTML = `
                <div class="biometric-prompt-dialog">
                    <h3>${title}</h3>
                    <p>${message}</p>
                    <input type="text" class="biometric-prompt-input" value="${this._escapeHtml(defaultValue)}" maxlength="100">
                    <div class="modal-actions">
                        <button class="btn biometric-prompt-cancel">Cancel</button>
                        <button class="btn primary biometric-prompt-ok">OK</button>
                    </div>
                </div>
            `;
            document.body.appendChild(overlay);

            const input = overlay.querySelector('.biometric-prompt-input');
            const okBtn = overlay.querySelector('.biometric-prompt-ok');
            const cancelBtn = overlay.querySelector('.biometric-prompt-cancel');

            const cleanup = () => overlay.remove();

            okBtn.onclick = () => {
                const val = input.value.trim();
                cleanup();
                resolve(val || null);
            };

            cancelBtn.onclick = () => {
                cleanup();
                resolve(null);
            };

            input.onkeydown = (e) => {
                if (e.key === 'Enter') okBtn.click();
                if (e.key === 'Escape') cancelBtn.click();
            };

            setTimeout(() => {
                input.focus();
                input.select();
            }, 100);
        });
    },

    _escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    // ============== Login Screen Integration ==============

    /**
     * Initialize biometric login button on the login screen.
     * Called when login screen is shown and username field has a value.
     */
    async updateLoginButton() {
        const container = document.getElementById('biometric-login-container');
        if (!container) return;

        const available = await this.isAvailable();
        if (!available) {
            container.classList.add('hidden');
            return;
        }

        // Check last logged-in username
        const lastUsername = localStorage.getItem('biometric_last_username') || '';
        const usernameInput = document.getElementById('login-username');
        const username = usernameInput ? usernameInput.value.trim() : '';
        const checkUsername = username || lastUsername;

        if (!checkUsername) {
            container.classList.add('hidden');
            return;
        }

        // Check if this user has passkeys
        const hasPasskeys = await this.checkAvailable(checkUsername);

        if (hasPasskeys) {
            container.classList.remove('hidden');
            // Pre-fill username if from remembered value
            if (!username && lastUsername && usernameInput) {
                usernameInput.value = lastUsername;
            }
        } else {
            container.classList.add('hidden');
        }
    },

    /**
     * Handle biometric login button click.
     */
    async handleBiometricLogin() {
        const usernameInput = document.getElementById('login-username');
        const username = usernameInput ? usernameInput.value.trim() : '';
        const errorDiv = document.getElementById('auth-error');

        const btn = document.getElementById('biometric-login-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Verifying...';
        }

        const result = await this.authenticateWithPasskey(username);

        if (btn) {
            btn.disabled = false;
            btn.textContent = '👆 Sign in with Biometrics';
        }

        if (result.success) {
            // Save username for next time
            localStorage.setItem('biometric_last_username', result.data.user.username);
            // Use the same auth success handler as password login
            await handleAuthSuccess(result.data);
        } else {
            if (errorDiv && result.error !== 'Authentication was cancelled or timed out') {
                errorDiv.textContent = result.error || 'Biometric login failed';
                errorDiv.classList.remove('hidden');
                setTimeout(() => errorDiv.classList.add('hidden'), 5000);
            }
        }
    },

    /**
     * Save username after successful login (for biometric login hint).
     */
    rememberUsername(username) {
        if (username) {
            localStorage.setItem('biometric_last_username', username);
        }
    },

    // ============== Initialization ==============

    /**
     * Initialize biometric features on app startup.
     * Called after successful login/auto-login.
     */
    async init() {
        const available = await this.isAvailable();
        if (!available) {
            console.log('[Biometric] Not available on this device');
            return;
        }

        // Initialize app lock if configured
        const lockTimeout = this.getLockTimeout();
        if (lockTimeout > 0) {
            this.initAppLock(lockTimeout);
        }

        console.log('[Biometric] Module initialized');
    },
};

// Make globally available
window.BiometricAuth = BiometricAuth;
