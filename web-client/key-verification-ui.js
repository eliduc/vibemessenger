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

/**
 * VibeMessenger Key Verification - UI Module
 * Key-verification UI. КАО#286: user-facing strings translated RU→EN
 * (this module was missed by the v3.11.38 RU→EN sweep).
 */

const KeyVerificationUI = (function() {
    'use strict';

    let currentVerificationData = null;

    /**
     * Открывает модальное окно верификации ключей
     * @param {string} theirUserId - ID собеседника
     * @param {string} theirUsername - Имя собеседника
     */
    async function openKeyVerification(theirUserId, theirUsername) {
        try {
            // Получаем identity keys
            const myIdentityKey = await getMyIdentityKey();
            const theirIdentityKey = await getTheirIdentityKey(theirUserId);

            if (!myIdentityKey || !theirIdentityKey) {
                showToast('Failed to retrieve encryption keys');
                return;
            }

            const myUserId = state.user.id;

            // Генерируем Safety Number
            const safetyNumber = await VibeCryptoVerification.generateSafetyNumber(
                myIdentityKey,
                theirIdentityKey,
                myUserId,
                theirUserId
            );

            // Генерируем эмодзи
            const emojis = VibeCryptoVerification.generateEmojiFingerprint(safetyNumber);

            // Форматируем цифры
            const numberBlocks = VibeCryptoVerification.formatSafetyNumber(safetyNumber);

            // Сохраняем данные для использования
            currentVerificationData = {
                myUserId,
                theirUserId,
                theirUsername,
                safetyNumber,
                emojis,
                numberBlocks
            };

            // Проверяем статус верификации
            const status = VibeCryptoVerification.getVerificationStatus(myUserId, theirUserId);

            // Показываем модалку
            showVerificationModal(theirUsername, emojis, numberBlocks, safetyNumber, status.verified);

        } catch (error) {
            console.error('Error opening key verification:', error);
            showToast('Error opening verification');
        }
    }

    /**
     * Показывает модальное окно верификации
     */
    function showVerificationModal(username, emojis, numberBlocks, safetyNumber, isVerified) {
        const modal = document.getElementById('key-verification-modal');
        if (!modal) {
            createVerificationModal();
        }

        // Заполняем данные
        document.getElementById('verification-username').textContent = username;

        // Эмодзи fingerprint
        const emojiContainer = document.getElementById('emoji-fingerprint');
        emojiContainer.innerHTML = emojis.map(e => `<span class="emoji">${e}</span>`).join('');

        // Safety Number
        const numberContainer = document.getElementById('safety-number-display');
        numberContainer.innerHTML = numberBlocks.map(b => `<span class="safety-number-block">${b}</span>`).join('');

        // QR Code
        generateQRCode(safetyNumber);

        // Статус верификации
        updateVerificationStatus(isVerified);

        // Чекбокс
        document.getElementById('verify-checkbox').checked = isVerified;
        document.getElementById('btn-mark-verified').disabled = isVerified;

        // Показываем модалку
        const modalEl = document.getElementById('key-verification-modal');
        modalEl.classList.remove('hidden');
        modalEl.style.display = 'flex';
    }

    /**
     * Создаёт HTML модального окна верификации
     */
    function createVerificationModal() {
        const modalHTML = `
        <div id="key-verification-modal" class="modal hidden" onclick="KeyVerificationUI.close()">
            <div class="modal-content" onclick="event.stopPropagation()">
                <div class="modal-header">
                    <h3>Key Verification</h3>
                    <button class="modal-close" onclick="KeyVerificationUI.close()">✕</button>
                </div>

                <div class="modal-body">
                    <p class="verification-instructions">
                        Compare these symbols with <strong id="verification-username">user</strong>
                    </p>

                    <!-- Emoji Fingerprint -->
                    <div class="emoji-fingerprint" id="emoji-fingerprint">
                        <!-- Эмодзи будут добавлены динамически -->
                    </div>

                    <!-- Safety Number -->
                    <div class="safety-number-container">
                        <div class="safety-number-label">Safety Number</div>
                        <div class="safety-number" id="safety-number-display">
                            <!-- Цифры будут добавлены динамически -->
                        </div>
                    </div>

                    <!-- QR Code -->
                    <div class="qr-code-container" id="qr-code-container">
                        <canvas id="verification-qr-canvas"></canvas>
                        <span class="qr-code-label">Scan to compare</span>
                    </div>

                    <!-- Verification Status -->
                    <div class="verification-status" id="verification-status">
                        <span id="verification-status-icon">⚠️</span>
                        <span id="verification-status-text">Not verified</span>
                    </div>

                    <!-- Checkbox -->
                    <div class="verify-checkbox-container" onclick="if(event.target === this) document.getElementById('verify-checkbox').click()">
                        <input type="checkbox" id="verify-checkbox" onchange="KeyVerificationUI.onCheckboxChange(this)" style="appearance:auto;-webkit-appearance:auto;width:20px;height:20px;min-width:20px;accent-color:#667eea;">
                        <label for="verify-checkbox">I verified the keys and they match</label>
                    </div>

                    <!-- Button -->
                    <button class="btn-verify" id="btn-mark-verified" onclick="KeyVerificationUI.markAsVerified()" disabled>
                        ✓ Mark as verified
                    </button>
                </div>
            </div>
        </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }

    /**
     * Генерирует QR-код
     */
    function generateQRCode(safetyNumber) {
        const canvas = document.getElementById('verification-qr-canvas');
        if (!canvas) return;

        const qrData = VibeCryptoVerification.generateQRData(
            safetyNumber,
            currentVerificationData.myUserId,
            currentVerificationData.theirUserId
        );

        const size = 130; // Компактный размер

        // Используем qrcode-generator (глобальная функция qrcode)
        if (typeof qrcode === 'function') {
            try {
                const qr = qrcode(0, 'M');
                qr.addData(qrData);
                qr.make();
                
                const ctx = canvas.getContext('2d');
                const modules = qr.getModuleCount();
                const cellSize = size / (modules + 2);
                canvas.width = size;
                canvas.height = size;
                
                ctx.fillStyle = '#ffffff';
                ctx.fillRect(0, 0, size, size);
                ctx.fillStyle = '#000000';
                
                for (let row = 0; row < modules; row++) {
                    for (let col = 0; col < modules; col++) {
                        if (qr.isDark(row, col)) {
                            ctx.fillRect(
                                (col + 1) * cellSize,
                                (row + 1) * cellSize,
                                cellSize,
                                cellSize
                            );
                        }
                    }
                }
                return; // Успех, выходим
            } catch (e) {
                console.error('QR generation error:', e);
            }
        }
        
        // Fallback - визуальный паттерн на основе safetyNumber
        drawFallbackPattern(canvas, safetyNumber, size);
    }

    /**
     * Рисует fallback паттерн если QR библиотека недоступна
     */
    function drawFallbackPattern(canvas, safetyNumber, size) {
        const ctx = canvas.getContext('2d');
        canvas.width = size;
        canvas.height = size;
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, size, size);

        // Визуальный паттерн на основе safetyNumber
        ctx.fillStyle = '#000000';
        const cellSize = 10;
        const offsetX = (size - 10 * cellSize) / 2;
        const offsetY = (size - 6 * cellSize) / 2;
        
        for (let i = 0; i < 60; i++) {
            const digit = parseInt(safetyNumber[i]);
            if (digit % 2 === 0) {
                const x = (i % 10) * cellSize + offsetX;
                const y = Math.floor(i / 10) * cellSize + offsetY;
                ctx.fillRect(x, y, cellSize - 1, cellSize - 1);
            }
        }
    }

    /**
     * Обновляет статус верификации в UI
     */
    function updateVerificationStatus(isVerified) {
        const statusEl = document.getElementById('verification-status');
        const iconEl = document.getElementById('verification-status-icon');
        const textEl = document.getElementById('verification-status-text');

        if (isVerified) {
            statusEl.className = 'verification-status verified';
            iconEl.textContent = '✓';
            textEl.textContent = 'Keys verified';
        } else {
            statusEl.className = 'verification-status unverified';
            iconEl.textContent = '⚠️';
            textEl.textContent = 'Not verified';
        }
    }

    /**
     * Обработчик изменения чекбокса
     */
    function onCheckboxChange(checkbox) {
        const btn = document.getElementById('btn-mark-verified');
        btn.disabled = !checkbox.checked;
    }

    /**
     * Отмечает ключи как проверенные
     */
    function markAsVerified() {
        if (!currentVerificationData) return;

        VibeCryptoVerification.saveVerificationStatus(
            currentVerificationData.myUserId,
            currentVerificationData.theirUserId,
            true
        );

        updateVerificationStatus(true);
        document.getElementById('btn-mark-verified').disabled = true;
        document.getElementById('verify-checkbox').disabled = true;

        // v3.11.5: Dismiss banner AND mark key as trusted (not just hide)
        if (typeof dismissIdentityKeyBanner === 'function') {
            dismissIdentityKeyBanner(currentVerificationData.theirUserId);
        } else if (typeof hideIdentityKeyChangedBanner === 'function') {
            hideIdentityKeyChangedBanner();
        }

        showToast('Keys marked as verified ✓');
        
        // v3.11.6: Auto-close modal after short delay
        setTimeout(() => close(), 1000);
    }

    /**
     * Закрывает модальное окно
     */
    function close() {
        const modal = document.getElementById('key-verification-modal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
        currentVerificationData = null;
    }

    /**
     * Получает мой identity key
     */
    async function getMyIdentityKey() {
        try {
            const response = await fetch(`${API_URL}/keys/identity/me`, {
                headers: {
                    'Authorization': `Bearer ${state.token}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                return data.identity_key;
            }
        } catch (e) {
            console.error('Error getting my identity key:', e);
        }
        return null;
    }

    /**
     * Получает identity key собеседника
     */
    async function getTheirIdentityKey(userId) {
        try {
            const response = await fetch(`${API_URL}/keys/identity/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${state.token}`
                }
            });
            if (response.ok) {
                const data = await response.json();
                return data.identity_key;
            }
        } catch (e) {
            console.error('Error getting their identity key:', e);
        }
        return null;
    }

    /**
     * Добавляет кнопку верификации в профиль пользователя
     */
    function addVerifyButtonToProfile() {
        const actionsDiv = document.querySelector('.user-profile-actions');
        if (!actionsDiv) return;

        // Проверяем что кнопка ещё не добавлена
        if (document.getElementById('profile-verify-btn')) return;

        const btn = document.createElement('button');
        btn.id = 'profile-verify-btn';
        btn.className = 'btn';
        btn.innerHTML = '🔐 Verify keys';
        btn.onclick = () => {
            const userId = state.currentProfileUserId;
            const username = document.getElementById('profile-name').textContent;
            openKeyVerification(userId, username);
        };

        actionsDiv.appendChild(btn);
    }

    // Public API
    return {
        open: openKeyVerification,
        close,
        markAsVerified,
        onCheckboxChange,
        addVerifyButtonToProfile,
        getCurrentData: () => currentVerificationData
    };
})();

// Экспорт для глобального использования
if (typeof window !== 'undefined') {
    window.KeyVerificationUI = KeyVerificationUI;
}
