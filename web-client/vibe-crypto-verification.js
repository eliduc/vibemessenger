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
 * VibeMessenger Key Verification - Crypto Module
 * Генерация Safety Number и Emoji Fingerprint
 */

const VibeCryptoVerification = (function() {
    'use strict';

    // 64 различимых эмодзи для fingerprint (6 из них = 36 бит энтропии)
    const EMOJI_SET = [
        // Животные (16)
        '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
        '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🦄',
        // Цветы и природа (8)
        '🌸', '🌺', '🌻', '🌹', '🌴', '🌵', '🍀', '🌈',
        // Фрукты (8)
        '🍎', '🍊', '🍋', '🍇', '🍓', '🍒', '🥝', '🍑',
        // Космос и погода (8)
        '⭐', '🌙', '☀️', '🔥', '❄️', '💧', '🌊', '⚡',
        // Музыка и игры (8)
        '🎸', '🎹', '🎺', '🥁', '🎯', '🎱', '🎲', '🎪',
        // Транспорт (8)
        '🚀', '✈️', '🚁', '⛵', '🚂', '🚗', '🏍️', '🚲',
        // Предметы (8)
        '💎', '👑', '🎭', '🎨', '🔮', '🔐', '⚔️', '🛡️'
    ];

    /**
     * Генерирует Safety Number из двух identity keys
     * @param {string} myIdentityKeyBase64 - Мой identity key (base64)
     * @param {string} theirIdentityKeyBase64 - Identity key собеседника (base64)
     * @param {string} myUserId - Мой user ID
     * @param {string} theirUserId - User ID собеседника
     * @returns {Promise<string>} - 60-значный Safety Number
     */
    async function generateSafetyNumber(myIdentityKeyBase64, theirIdentityKeyBase64, myUserId, theirUserId) {
        try {
            // Декодируем ключи из base64
            const myKey = base64ToArrayBuffer(myIdentityKeyBase64);
            const theirKey = base64ToArrayBuffer(theirIdentityKeyBase64);

            // Сортируем для симметричности (оба видят одинаковый номер)
            let sortedKeys, sortedIds;
            
            if (myUserId < theirUserId) {
                sortedKeys = concatenateArrayBuffers(myKey, theirKey);
                sortedIds = myUserId + theirUserId;
            } else {
                sortedKeys = concatenateArrayBuffers(theirKey, myKey);
                sortedIds = theirUserId + myUserId;
            }

            // Добавляем user IDs к данным
            const idsBuffer = new TextEncoder().encode(sortedIds);
            const dataToHash = concatenateArrayBuffers(sortedKeys, idsBuffer);

            // КАО#263 (#19): SHA-512 (64 bytes) + 12 NON-overlapping 4-byte windows → each a 5-digit
            // group. The previous code used only ~13 of 32 SHA-256 bytes via consecutive OVERLAPPING
            // pairs, materially weakening the fingerprint's collision resistance. (Safety numbers change
            // with this algorithm update — pairs re-verify once.)
            const hashBuffer = await crypto.subtle.digest('SHA-512', dataToHash);
            const hashArray = new Uint8Array(hashBuffer);  // 64 bytes

            let safetyNumber = '';
            for (let g = 0; g < 12; g++) {
                const o = g * 4;  // distinct, non-overlapping 4-byte window (uses 48 of 64 bytes)
                const value = ((hashArray[o] * 16777216) + (hashArray[o + 1] * 65536)
                              + (hashArray[o + 2] * 256) + hashArray[o + 3]) % 100000;
                safetyNumber += value.toString().padStart(5, '0');
            }

            return safetyNumber;  // exactly 60 digits
        } catch (error) {
            console.error('Error generating safety number:', error);
            throw error;
        }
    }

    /**
     * Генерирует эмодзи fingerprint из Safety Number
     * @param {string} safetyNumber - 60-значный Safety Number
     * @returns {string[]} - Массив из 6 эмодзи
     */
    function generateEmojiFingerprint(safetyNumber) {
        const emojis = [];
        
        // Берём 6 секций по 10 цифр
        for (let i = 0; i < 6; i++) {
            const chunk = safetyNumber.substring(i * 10, (i + 1) * 10);
            const value = parseInt(chunk, 10);
            const index = value % EMOJI_SET.length;
            emojis.push(EMOJI_SET[index]);
        }
        
        return emojis;
    }

    /**
     * Форматирует Safety Number для отображения (12 блоков по 5 цифр)
     * @param {string} safetyNumber - 60-значный Safety Number
     * @returns {string} - Форматированная строка
     */
    function formatSafetyNumber(safetyNumber) {
        const blocks = [];
        for (let i = 0; i < 60; i += 5) {
            blocks.push(safetyNumber.substring(i, i + 5));
        }
        return blocks;
    }

    /**
     * Генерирует данные для QR-кода
     * @param {string} safetyNumber - Safety Number
     * @param {string} myUserId - Мой user ID
     * @param {string} theirUserId - User ID собеседника
     * @returns {string} - JSON строка для QR
     */
    function generateQRData(safetyNumber, myUserId, theirUserId) {
        return JSON.stringify({
            version: 1,
            safetyNumber: safetyNumber,
            users: [myUserId, theirUserId].sort()
        });
    }

    /**
     * Проверяет QR-код
     * @param {string} qrData - Данные из QR-кода
     * @param {string} expectedSafetyNumber - Ожидаемый Safety Number
     * @returns {boolean} - Совпадает ли
     */
    function verifyQRCode(qrData, expectedSafetyNumber) {
        try {
            const data = JSON.parse(qrData);
            return data.safetyNumber === expectedSafetyNumber;
        } catch (e) {
            return false;
        }
    }

    // === Вспомогательные функции ===

    function base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function concatenateArrayBuffers(buffer1, buffer2) {
        const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
        tmp.set(new Uint8Array(buffer1), 0);
        tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
        return tmp.buffer;
    }

    // Локальное хранилище верификаций
    const VERIFIED_STORAGE_KEY = 'vibe_verified_keys';

    function saveVerificationStatus(myUserId, theirUserId, verified) {
        try {
            const storage = JSON.parse(localStorage.getItem(VERIFIED_STORAGE_KEY) || '{}');
            const key = [myUserId, theirUserId].sort().join('_');
            storage[key] = {
                verified: verified,
                timestamp: Date.now()
            };
            localStorage.setItem(VERIFIED_STORAGE_KEY, JSON.stringify(storage));
        } catch (e) {
            console.error('Error saving verification status:', e);
        }
    }

    function getVerificationStatus(myUserId, theirUserId) {
        try {
            const storage = JSON.parse(localStorage.getItem(VERIFIED_STORAGE_KEY) || '{}');
            const key = [myUserId, theirUserId].sort().join('_');
            return storage[key] || { verified: false, timestamp: null };
        } catch (e) {
            return { verified: false, timestamp: null };
        }
    }

    /**
     * Сбрасывает статус верификации для пары пользователей
     * Вызывается при KEY_RESET (смене ключей)
     */
    function clearVerificationStatus(myUserId, theirUserId) {
        try {
            const storage = JSON.parse(localStorage.getItem(VERIFIED_STORAGE_KEY) || '{}');
            const key = [myUserId, theirUserId].sort().join('_');
            if (storage[key]) {
                delete storage[key];
                localStorage.setItem(VERIFIED_STORAGE_KEY, JSON.stringify(storage));
                console.log('[Verification] Cleared verification status for', key);
                return true;
            }
            return false;
        } catch (e) {
            console.error('Error clearing verification status:', e);
            return false;
        }
    }

    // Public API
    return {
        generateSafetyNumber,
        generateEmojiFingerprint,
        formatSafetyNumber,
        generateQRData,
        verifyQRCode,
        saveVerificationStatus,
        getVerificationStatus,
        clearVerificationStatus,
        EMOJI_SET
    };
})();

// Экспорт для глобального использования
if (typeof window !== 'undefined') {
    window.VibeCryptoVerification = VibeCryptoVerification;
}
