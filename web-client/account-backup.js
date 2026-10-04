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
 * VibeMessenger Account Backup Module v1.8
 * Экспорт и импорт данных аккаунта: E2EE ключи + чаты + настройки
 * 
 * v1.8 - Custom confirm dialog, refresh keys_just_reset flag after restore
 * v1.7 - Smart key import: skip if keys already exist (safe reset E2EE + restore flow)
 * v1.6 - Убрана блокировка при конфликте ключей (импорт заменяет ключи)
 * v1.5 - Полная поддержка VibeCrypto IndexedDB структуры (identity, prekeys, sessions, groupSessions)
 * v1.4 - Пропуск импорта E2EE ключей если VibeCrypto.importKeys недоступен
 * v1.3 - Исправлен импорт ключей при отсутствии IndexedDB stores
 * v1.2 - Синхронизация версии с CSS
 * v1.1 - Исправлено закрытие модалки при выделении текста
 * v1.0 - Объединённый backup (заменяет key-backup.js)
 * 
 * Safe Reset E2EE Flow:
 * 1. Create backup (saves plaintext messages + old keys)
 * 2. Reset E2EE (generates new keys)
 * 3. Restore backup → messages restored, NEW keys preserved (old keys skipped)
 * 4. Verification banner shows for all chats (keys_just_reset flag refreshed)
 * 
 * Включает:
 * - E2EE ключи (identity, signed prekey, sessions)
 * - Чаты и сообщения (из localStorage)
 * - Настройки (muted, blocked)
 * - Self-encryption key (для multi-device)
 * 
 * Использует:
 * - Web Crypto API для AES-256-GCM шифрования
 * - PBKDF2 для деривации ключа из пароля
 * - IndexedDB для доступа к хранилищу ключей VibeCrypto
 */

const AccountBackup = {
    // Версия формата backup файла
    VERSION: 2,
    
    // Параметры PBKDF2
    PBKDF2_ITERATIONS: 310000,  // OWASP рекомендация для SHA-256
    SALT_LENGTH: 32,
    
    /**
     * Создаёт резервную копию аккаунта
     * @param {string} passphrase - Пароль для шифрования
     * @returns {Promise<{success: boolean, filename?: string, error?: string, stats?: object}>}
     */
    async createBackup(passphrase) {
        try {
            if (!passphrase || passphrase.length < 8) {
                return { success: false, error: 'Пароль должен быть не менее 8 символов' };
            }
            
            // Собираем все данные аккаунта
            const accountData = await this.collectAccountData();
            if (!accountData) {
                return { success: false, error: 'Не удалось собрать данные аккаунта' };
            }
            
            // Статистика
            const stats = {
                hasKeys: !!accountData.e2ee?.identity,
                prekeysCount: accountData.e2ee?.prekeys?.length || 0,
                sessionsCount: accountData.e2ee?.sessions?.length || 0,
                chatsCount: Object.keys(accountData.chats || {}).length,
                messagesCount: Object.values(accountData.chats || {}).reduce((sum, chat) => sum + (chat.messages?.length || 0), 0),
                hasSelfKey: !!accountData.selfEncryptionKey,
                mutedCount: accountData.settings?.muted?.length || 0,
                blockedCount: accountData.settings?.blocked?.length || 0
            };
            
            // Шифруем данные
            const encrypted = await this.encryptData(JSON.stringify(accountData), passphrase);
            
            // Формируем backup файл
            const backup = {
                version: this.VERSION,
                created_at: new Date().toISOString(),
                app: 'VibeMessenger',
                type: 'account_backup',
                kdf: 'pbkdf2-sha256',
                kdf_params: {
                    iterations: this.PBKDF2_ITERATIONS,
                    salt: encrypted.salt
                },
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext,
                // Незашифрованные метаданные для информации
                metadata: {
                    user_id: accountData.userId,
                    username: accountData.username,
                    has_e2ee: stats.hasKeys,
                    chats_count: stats.chatsCount,
                    messages_count: stats.messagesCount
                }
            };
            
            // Скачиваем файл
            const dateStr = new Date().toISOString().slice(0, 10);
            const filename = `vibemessenger-backup-${dateStr}.vmbackup`;
            this.downloadBackup(backup, filename);
            
            // Сохраняем дату последнего backup
            localStorage.setItem('lastAccountBackup', new Date().toISOString());
            
            return { success: true, filename, stats };
        } catch (error) {
            console.error('AccountBackup.createBackup error:', error);
            return { success: false, error: error.message };
        }
    },
    
    /**
     * Восстанавливает аккаунт из резервной копии
     * @param {File} file - Файл backup
     * @param {string} passphrase - Пароль для расшифровки
     * @returns {Promise<{success: boolean, imported?: object, error?: string, stats?: object}>}
     */
    async restoreBackup(file, passphrase) {
        try {
            // Читаем файл
            const content = await this.readFile(file);
            let backup;
            
            try {
                backup = JSON.parse(content);
            } catch {
                return { success: false, error: 'Неверный формат файла backup' };
            }
            
            // Проверяем версию
            if (!backup.version) {
                return { success: false, error: 'Файл не является backup VibeMessenger' };
            }
            
            // Support old format (version 1 - keys only)
            if (backup.version === 1) {
                console.log('[AccountBackup] Migrating from v1 (keys only) format');
            } else if (backup.version > this.VERSION) {
                return { success: false, error: 'File created by newer version of the app' };
            }
            
            // Check structure
            if (!backup.ciphertext || !backup.nonce || !backup.kdf_params?.salt) {
                return { success: false, error: 'Corrupted backup file' };
            }
            
            // Расшифровываем
            const decrypted = await this.decryptData(
                backup.ciphertext,
                backup.nonce,
                backup.kdf_params.salt,
                backup.kdf_params.iterations || this.PBKDF2_ITERATIONS,
                passphrase
            );
            
            if (!decrypted) {
                return { success: false, error: 'Неверный пароль или повреждённый файл' };
            }
            
            let accountData;
            try {
                accountData = JSON.parse(decrypted);
            } catch {
                return { success: false, error: 'Расшифрованные данные повреждены' };
            }
            
            // Миграция старого формата (только ключи)
            if (backup.version === 1) {
                accountData = {
                    e2ee: accountData,  // В v1 весь объект - это ключи
                    chats: {},
                    settings: {}
                };
            }
            
            // Проверяем user_id если есть
            if (typeof state !== 'undefined' && state.user && accountData.userId) {
                if (accountData.userId !== state.user.id) {
                    // КАО#081 (SER#26): refuse to restore a backup that belongs to a different account
                    console.warn('[AccountBackup] Refusing restore — backup user', accountData.userId, '!= current', state.user.id);
                    throw new Error('This backup belongs to a different account and cannot be restored here.');
                }
            }
            
            // v1.7: Check if E2EE keys already exist - if yes, skip key import (preserve new keys after reset)
            let skipKeyImport = false;
            if (accountData.e2ee?.identity) {
                const existingKeys = await this.collectE2EEKeys();
                if (existingKeys?.identity?.publicKey) {
                    if (accountData.e2ee.identity.publicKey !== existingKeys.identity.publicKey) {
                        // Different keys exist - keep current keys, restore only messages
                        console.log('[AccountBackup] Existing E2EE keys detected, skipping key import (preserving current keys)');
                        skipKeyImport = true;
                    } else {
                        // Same keys - no need to import
                        console.log('[AccountBackup] Same E2EE keys already exist, skipping key import');
                        skipKeyImport = true;
                    }
                }
            }
            
            // Импортируем данные
            await this.importAccountData(accountData, { skipKeyImport });
            
            // Статистика импорта
            const stats = {
                importedKeys: !skipKeyImport && !!accountData.e2ee?.identity,
                skippedKeys: skipKeyImport,
                importedPrekeys: skipKeyImport ? 0 : (accountData.e2ee?.prekeys?.length || 0),
                importedSessions: skipKeyImport ? 0 : (accountData.e2ee?.sessions?.length || 0),
                importedChats: Object.keys(accountData.chats || {}).length,
                importedMessages: Object.values(accountData.chats || {}).reduce((sum, chat) => sum + (chat.messages?.length || 0), 0),
                importedSelfKey: !!accountData.selfEncryptionKey && !localStorage.getItem('vibe_self_encryption_key'),
                importedMuted: accountData.settings?.muted?.length || 0,
                importedBlocked: accountData.settings?.blocked?.length || 0
            };
            
            return {
                success: true,
                imported: accountData,
                stats,
                message: 'Account data restored. Reload the page.'
            };
        } catch (error) {
            console.error('AccountBackup.restoreBackup error:', error);
            return { success: false, error: error.message };
        }
    },
    
    /**
     * Собирает все данные аккаунта
     */
    async collectAccountData() {
        try {
            const userId = (typeof state !== 'undefined' && state.user) ? state.user.id : null;
            const username = (typeof state !== 'undefined' && state.user) ? state.user.username : null;
            
            const accountData = {
                exportedAt: new Date().toISOString(),
                userId: userId,
                username: username
            };
            
            // 1. E2EE ключи
            const e2eeKeys = await this.collectE2EEKeys();
            if (e2eeKeys) {
                accountData.e2ee = e2eeKeys;
            }
            
            // 2. Чаты из localStorage/state
            accountData.chats = this.collectChats(userId);
            
            // 3. Self-encryption key
            const selfKey = localStorage.getItem('vibe_self_encryption_key');
            if (selfKey) {
                accountData.selfEncryptionKey = selfKey;
            }
            
            // 4. Настройки
            accountData.settings = this.collectSettings(userId);
            
            // 5. Кэш расшифрованных сообщений (опционально)
            // Не включаем - слишком большой объём и можно восстановить
            
            return accountData;
        } catch (error) {
            console.error('collectAccountData error:', error);
            return null;
        }
    },
    
    /**
     * Собирает E2EE ключи из VibeCrypto IndexedDB
     * Структура: identity, prekeys (signed + onetime), sessions, groupSessions
     */
    async collectE2EEKeys() {
        try {
            return new Promise((resolve) => {
                const request = indexedDB.open('VibeCrypto');
                
                request.onerror = () => {
                    console.warn('[AccountBackup] Cannot open VibeCrypto DB');
                    resolve(null);
                };
                
                request.onsuccess = async (event) => {
                    const db = event.target.result;
                    const keys = {};
                    
                    try {
                        // 1. Identity (id='me')
                        if (db.objectStoreNames.contains('identity')) {
                            const identity = await this.getAllFromStore(db, 'identity');
                            const me = identity.find(i => i.id === 'me');
                            if (me) {
                                keys.identity = me;
                            }
                        }
                        
                        // 2. Prekeys (signed + onetime)
                        if (db.objectStoreNames.contains('prekeys')) {
                            keys.prekeys = await this.getAllFromStore(db, 'prekeys');
                        }
                        
                        // 3. Sessions (Double Ratchet)
                        if (db.objectStoreNames.contains('sessions')) {
                            keys.sessions = await this.getAllFromStore(db, 'sessions');
                        }
                        
                        // 4. Group sessions
                        if (db.objectStoreNames.contains('groupSessions')) {
                            keys.groupSessions = await this.getAllFromStore(db, 'groupSessions');
                        }
                        
                        db.close();
                        
                        // Если нет identity, считаем что ключей нет
                        if (!keys.identity) {
                            resolve(null);
                            return;
                        }
                        
                        resolve(keys);
                    } catch (e) {
                        console.error('[AccountBackup] collectE2EEKeys error:', e);
                        db.close();
                        resolve(null);
                    }
                };
            });
        } catch (error) {
            console.error('collectE2EEKeys error:', error);
            return null;
        }
    },
    
    /**
     * Получает все записи из IndexedDB store
     */
    getAllFromStore(db, storeName) {
        return new Promise((resolve, reject) => {
            try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                const request = store.getAll();
                request.onsuccess = () => resolve(request.result || []);
                request.onerror = () => resolve([]);
            } catch (e) {
                resolve([]);
            }
        });
    },
    
    /**
     * Собирает чаты из localStorage/state
     */
    collectChats(userId) {
        try {
            // Пробуем из state (если доступен)
            if (typeof state !== 'undefined' && state.chats) {
                return JSON.parse(JSON.stringify(state.chats));  // Deep copy
            }
            
            // Fallback: из localStorage
            const key = userId ? `chats_${userId}` : 'chats';
            const chatsJson = localStorage.getItem(key);
            if (chatsJson) {
                return JSON.parse(chatsJson);
            }
            
            return {};
        } catch (error) {
            console.error('collectChats error:', error);
            return {};
        }
    },
    
    /**
     * Собирает настройки пользователя
     */
    collectSettings(userId) {
        const settings = {};
        
        try {
            // Muted chats
            const mutedKey = userId ? `mutedChats_${userId}` : 'mutedChats';
            const muted = localStorage.getItem(mutedKey);
            if (muted) {
                settings.muted = JSON.parse(muted);
            }
            
            // Blocked users
            const blockedKey = userId ? `blockedUsers_${userId}` : 'blockedUsers';
            const blocked = localStorage.getItem(blockedKey);
            if (blocked) {
                settings.blocked = JSON.parse(blocked);
            }
            
            // Deleted chats timestamps
            const deletedKey = userId ? `deletedChats_${userId}` : 'deletedChats';
            const deleted = localStorage.getItem(deletedKey);
            if (deleted) {
                settings.deletedChats = JSON.parse(deleted);
            }
            
            // Theme preference
            const theme = localStorage.getItem('theme');
            if (theme) {
                settings.theme = theme;
            }
            
            // Notification settings
            const notifSettings = localStorage.getItem('notificationSettings');
            if (notifSettings) {
                settings.notifications = JSON.parse(notifSettings);
            }
        } catch (error) {
            console.error('collectSettings error:', error);
        }
        
        return settings;
    },
    
    /**
     * Импортирует все данные аккаунта
     * @param {object} accountData - Data to import
     * @param {object} options - Import options
     * @param {boolean} options.skipKeyImport - Skip E2EE key import (preserve existing keys)
     */
    async importAccountData(accountData, options = {}) {
        const { skipKeyImport = false } = options;
        const userId = (typeof state !== 'undefined' && state.user) ? state.user.id : accountData.userId;
        
        // 1. Импорт E2EE ключей (skip if keys already exist)
        if (accountData.e2ee && !skipKeyImport) {
            await this.importE2EEKeys(accountData.e2ee);
        } else if (skipKeyImport) {
            console.log('[AccountBackup] Skipping E2EE key import, preserving current keys');
            // v1.8: Refresh the "keys just reset" flag so verification banner shows after restore
            // This ensures user sees the verification prompt for all restored chats
            const existingResetFlag = localStorage.getItem('vibe_keys_just_reset');
            if (existingResetFlag) {
                // Refresh the timestamp so banner shows for another 5 minutes
                localStorage.setItem('vibe_keys_just_reset', Date.now().toString());
                console.log('[AccountBackup] Refreshed keys_just_reset flag for verification banner');
            }
        }
        
        // 2. Импорт чатов
        if (accountData.chats && Object.keys(accountData.chats).length > 0) {
            this.importChats(accountData.chats, userId);
        }
        
        // 3. Импорт self-encryption key (only if not exists)
        if (accountData.selfEncryptionKey) {
            const existingSelfKey = localStorage.getItem('vibe_self_encryption_key');
            if (!existingSelfKey) {
                localStorage.setItem('vibe_self_encryption_key', accountData.selfEncryptionKey);
            } else {
                console.log('[AccountBackup] Self-encryption key already exists, skipping');
            }
        }
        
        // 4. Импорт настроек
        if (accountData.settings) {
            this.importSettings(accountData.settings, userId);
        }
    },
    
    /**
     * Импортирует E2EE ключи в VibeCrypto IndexedDB
     * Структура: identity, prekeys (signed + onetime), sessions, groupSessions
     */
    async importE2EEKeys(keys) {
        try {
            if (!keys || !keys.identity) {
                console.warn('[AccountBackup] No identity key to import');
                return false;
            }
            
            return new Promise((resolve, reject) => {
                // Открываем БД с текущей версией
                const checkRequest = indexedDB.open('VibeCrypto');
                
                checkRequest.onerror = () => reject(new Error('Cannot open VibeCrypto DB'));
                
                checkRequest.onsuccess = async (event) => {
                    const db = event.target.result;
                    const currentVersion = db.version;
                    const hasAllStores = 
                        db.objectStoreNames.contains('identity') &&
                        db.objectStoreNames.contains('prekeys') &&
                        db.objectStoreNames.contains('sessions') &&
                        db.objectStoreNames.contains('groupSessions');
                    db.close();
                    
                    if (!hasAllStores) {
                        // Нужно создать stores - upgrade версию
                        await this.upgradeVibeCryptoDB(currentVersion);
                    }
                    
                    // Теперь импортируем данные
                    const importRequest = indexedDB.open('VibeCrypto');
                    
                    importRequest.onerror = () => reject(new Error('Cannot open VibeCrypto DB for import'));
                    
                    importRequest.onsuccess = async (e) => {
                        const importDb = e.target.result;
                        
                        try {
                            // 1. Import identity
                            if (keys.identity) {
                                await this.putToStore(importDb, 'identity', keys.identity);
                            }
                            
                            // 2. Import prekeys
                            if (keys.prekeys && keys.prekeys.length > 0) {
                                for (const prekey of keys.prekeys) {
                                    await this.putToStore(importDb, 'prekeys', prekey);
                                }
                            }
                            
                            // 3. Import sessions
                            if (keys.sessions && keys.sessions.length > 0) {
                                for (const session of keys.sessions) {
                                    await this.putToStore(importDb, 'sessions', session);
                                }
                            }
                            
                            // 4. Import group sessions
                            if (keys.groupSessions && keys.groupSessions.length > 0) {
                                for (const groupSession of keys.groupSessions) {
                                    await this.putToStore(importDb, 'groupSessions', groupSession);
                                }
                            }
                            
                            importDb.close();
                            console.log('[AccountBackup] E2EE keys imported successfully');
                            resolve(true);
                        } catch (e) {
                            importDb.close();
                            reject(e);
                        }
                    };
                };
            });
        } catch (error) {
            console.error('importE2EEKeys error:', error);
            return false;
        }
    },
    
    /**
     * Upgrade VibeCrypto DB если нужны stores
     */
    async upgradeVibeCryptoDB(currentVersion) {
        return new Promise((resolve, reject) => {
            const upgradeRequest = indexedDB.open('VibeCrypto', currentVersion + 1);
            
            upgradeRequest.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('identity')) {
                    db.createObjectStore('identity', { keyPath: 'id' });
                }
                if (!db.objectStoreNames.contains('prekeys')) {
                    const store = db.createObjectStore('prekeys', { keyPath: 'id' });
                    store.createIndex('type', 'type', { unique: false });
                }
                if (!db.objectStoreNames.contains('sessions')) {
                    db.createObjectStore('sessions', { keyPath: 'recipientId' });
                }
                if (!db.objectStoreNames.contains('groupSessions')) {
                    db.createObjectStore('groupSessions', { keyPath: 'groupId' });
                }
            };
            
            upgradeRequest.onsuccess = (e) => {
                e.target.result.close();
                resolve();
            };
            
            upgradeRequest.onerror = () => reject(new Error('Cannot upgrade VibeCrypto DB'));
        });
    },
    
    /**
     * Записывает объект в IndexedDB store
     */
    putToStore(db, storeName, data) {
        return new Promise((resolve, reject) => {
            try {
                const tx = db.transaction(storeName, 'readwrite');
                const store = tx.objectStore(storeName);
                const request = store.put(data);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            } catch (e) {
                reject(e);
            }
        });
    },
    
    /**
     * Импортирует чаты
     */
    importChats(chats, userId) {
        try {
            // Merge с существующими чатами
            const key = userId ? `chats_${userId}` : 'chats';
            let existingChats = {};
            
            try {
                const existing = localStorage.getItem(key);
                if (existing) {
                    existingChats = JSON.parse(existing);
                }
            } catch (e) {}
            
            // Merge: новые сообщения добавляются, существующие не перезаписываются
            for (const [chatId, chatData] of Object.entries(chats)) {
                if (!existingChats[chatId]) {
                    existingChats[chatId] = chatData;
                } else {
                    // Merge сообщений
                    const existingMsgIds = new Set(existingChats[chatId].messages?.map(m => m.id) || []);
                    const newMessages = chatData.messages?.filter(m => !existingMsgIds.has(m.id)) || [];
                    if (newMessages.length > 0) {
                        existingChats[chatId].messages = [
                            ...(existingChats[chatId].messages || []),
                            ...newMessages
                        ].sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
                    }
                }
            }
            
            localStorage.setItem(key, JSON.stringify(existingChats));
            
            // Обновляем state если доступен
            if (typeof state !== 'undefined') {
                state.chats = existingChats;
            }
        } catch (error) {
            console.error('importChats error:', error);
        }
    },
    
    /**
     * Импортирует настройки
     */
    importSettings(settings, userId) {
        try {
            if (settings.muted) {
                const key = userId ? `mutedChats_${userId}` : 'mutedChats';
                localStorage.setItem(key, JSON.stringify(settings.muted));
            }
            
            if (settings.blocked) {
                const key = userId ? `blockedUsers_${userId}` : 'blockedUsers';
                localStorage.setItem(key, JSON.stringify(settings.blocked));
            }
            
            if (settings.deletedChats) {
                const key = userId ? `deletedChats_${userId}` : 'deletedChats';
                localStorage.setItem(key, JSON.stringify(settings.deletedChats));
            }
            
            if (settings.theme) {
                localStorage.setItem('theme', settings.theme);
            }
            
            if (settings.notifications) {
                localStorage.setItem('notificationSettings', JSON.stringify(settings.notifications));
            }
        } catch (error) {
            console.error('importSettings error:', error);
        }
    },
    
    /**
     * Шифрует данные с помощью AES-256-GCM
     */
    async encryptData(plaintext, passphrase) {
        // Генерируем соль
        const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
        
        // Деривация ключа из пароля
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(passphrase),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        // Генерируем nonce
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        
        // Шифруем
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            new TextEncoder().encode(plaintext)
        );
        
        return {
            salt: this.arrayToBase64(salt),
            nonce: this.arrayToBase64(nonce),
            ciphertext: this.arrayToBase64(new Uint8Array(ciphertext))
        };
    },
    
    /**
     * Расшифровывает данные
     */
    async decryptData(ciphertextB64, nonceB64, saltB64, iterations, passphrase) {
        try {
            const salt = this.base64ToArray(saltB64);
            const nonce = this.base64ToArray(nonceB64);
            const ciphertext = this.base64ToArray(ciphertextB64);
            
            // Деривация ключа
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(passphrase),
                'PBKDF2',
                false,
                ['deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            // Расшифровываем
            const plaintext = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce },
                key,
                ciphertext
            );
            
            return new TextDecoder().decode(plaintext);
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    },
    
    /**
     * Скачивает backup файл
     */
    downloadBackup(data, filename) {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },
    
    /**
     * Читает файл как текст
     */
    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(new Error('Не удалось прочитать файл'));
            reader.readAsText(file);
        });
    },
    
    /**
     * Вспомогательные функции конвертации
     */
    arrayToBase64(array) {
        return btoa(String.fromCharCode.apply(null, array));
    },
    
    base64ToArray(base64) {
        const binary = atob(base64);
        const array = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            array[i] = binary.charCodeAt(i);
        }
        return array;
    },
    
    /**
     * Получает дату последнего backup
     */
    getLastBackupDate() {
        // Проверяем новый ключ, потом старый для совместимости
        const date = localStorage.getItem('lastAccountBackup') || localStorage.getItem('lastKeyBackup');
        return date ? new Date(date) : null;
    },
    
    /**
     * Проверяет наличие данных для backup
     */
    async hasDataToBackup() {
        const keys = await this.collectE2EEKeys();
        const userId = (typeof state !== 'undefined' && state.user) ? state.user.id : null;
        const chats = this.collectChats(userId);
        
        return keys !== null || Object.keys(chats).length > 0;
    }
};

// UI функции для интеграции с Settings
const AccountBackupUI = {
    /**
     * Показывает модальное окно создания backup
     */
    showCreateBackupModal() {
        const modal = document.getElementById('account-backup-modal');
        if (!modal) {
            this.createModal();
        }
        
        document.getElementById('account-backup-modal').classList.remove('hidden');
        document.getElementById('account-backup-modal').style.display = 'flex';
        document.getElementById('backup-mode-create').classList.remove('hidden');
        document.getElementById('backup-mode-restore').classList.add('hidden');
        document.getElementById('backup-password').value = '';
        document.getElementById('backup-password-confirm').value = '';
        document.getElementById('backup-result').classList.add('hidden');
        document.getElementById('password-strength').innerHTML = '';
    },
    
    /**
     * Показывает модальное окно восстановления
     */
    showRestoreBackupModal() {
        const modal = document.getElementById('account-backup-modal');
        if (!modal) {
            this.createModal();
        }
        
        document.getElementById('account-backup-modal').classList.remove('hidden');
        document.getElementById('account-backup-modal').style.display = 'flex';
        document.getElementById('backup-mode-create').classList.add('hidden');
        document.getElementById('backup-mode-restore').classList.remove('hidden');
        document.getElementById('restore-password').value = '';
        document.getElementById('restore-file').value = '';
        document.getElementById('backup-result').classList.add('hidden');
    },
    
    /**
     * Закрывает модальное окно
     */
    closeModal() {
        const modal = document.getElementById('account-backup-modal');
        if (modal) {
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }
    },
    
    /**
     * Creates modal window
     */
    createModal() {
        const modal = document.createElement('div');
        modal.id = 'account-backup-modal';
        modal.className = 'modal hidden';
        modal.innerHTML = `
            <div class="modal-content account-backup-modal-content">
                <div class="modal-header">
                    <h3>💾 Account Backup</h3>
                    <button class="close-btn" onclick="AccountBackupUI.closeModal()">&times;</button>
                </div>
                
                <!-- Create Backup Mode -->
                <div id="backup-mode-create" class="backup-mode">
                    <p class="backup-description">
                        Create an encrypted backup of your account.<br>
                        Includes: E2EE keys, chat history and settings.
                    </p>
                    
                    <div class="backup-warning">
                        <p><span class="warning-icon">⚠️</span> Remember the password! Cannot restore data without it.</p>
                    </div>
                    
                    <div class="backup-form">
                        <div class="form-group">
                            <label for="backup-password">Encryption password</label>
                            <input type="password" id="backup-password" 
                                   placeholder="Minimum 8 characters"
                                   minlength="8" autocomplete="new-password">
                        </div>
                        <div class="form-group">
                            <label for="backup-password-confirm">Confirm password</label>
                            <input type="password" id="backup-password-confirm" 
                                   placeholder="Repeat password"
                                   minlength="8" autocomplete="new-password">
                        </div>
                        
                        <div class="password-strength" id="password-strength"></div>
                        
                        <button class="btn btn-primary backup-btn" onclick="AccountBackupUI.doCreateBackup()">
                            <span class="btn-icon">📤</span> Create backup
                        </button>
                    </div>
                </div>
                
                <!-- Restore Backup Mode -->
                <div id="backup-mode-restore" class="backup-mode hidden">
                    <p class="backup-description">
                        Restore account data from backup.<br>
                        Will restore: encryption keys, chats and settings.
                    </p>
                    
                    <div class="backup-form">
                        <div class="form-group">
                            <label for="restore-file">Backup file</label>
                            <input type="file" id="restore-file" accept=".vmbackup,.vmbak,.json">
                            <small>Select .vmbackup file</small>
                        </div>
                        <div class="form-group">
                            <label for="restore-password">Backup password</label>
                            <input type="password" id="restore-password" 
                                   placeholder="Enter backup password"
                                   autocomplete="current-password">
                        </div>
                        
                        <button class="btn btn-primary restore-btn" onclick="AccountBackupUI.doRestoreBackup()">
                            <span class="btn-icon">📥</span> Restore
                        </button>
                    </div>
                </div>
                
                <!-- Result -->
                <div id="backup-result" class="backup-result hidden">
                    <div class="result-icon"></div>
                    <div class="result-message"></div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Click handler outside modal
        // Use mousedown instead of click to avoid closing when selecting text
        modal.addEventListener('mousedown', (e) => {
            if (e.target === modal) {
                AccountBackupUI.closeModal();
            }
        });
        
        // Password strength indicator
        document.getElementById('backup-password').addEventListener('input', (e) => {
            this.updatePasswordStrength(e.target.value);
        });
        
        // Escape для закрытия
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                AccountBackupUI.closeModal();
            }
        });
    },
    
    /**
     * Обновляет индикатор силы пароля
     */
    updatePasswordStrength(password) {
        const indicator = document.getElementById('password-strength');
        if (!indicator) return;
        
        let strength = 0;
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        
        const labels = ['Слабый', 'Средний', 'Хороший', 'Сильный', 'Отличный'];
        const colors = ['#ff4444', '#ff8800', '#ffcc00', '#88cc00', '#00cc44'];
        
        if (password.length === 0) {
            indicator.innerHTML = '';
        } else {
            const level = Math.min(strength, 4);
            indicator.innerHTML = `
                <div class="strength-bar" style="width: ${(level + 1) * 20}%; background: ${colors[level]}"></div>
                <span style="color: ${colors[level]}">${labels[level]}</span>
            `;
        }
    },
    
    /**
     * Выполняет создание backup
     */
    async doCreateBackup() {
        const password = document.getElementById('backup-password').value;
        const confirm = document.getElementById('backup-password-confirm').value;
        
        if (password !== confirm) {
            this.showResult(false, 'Пароли не совпадают');
            return;
        }
        
        if (password.length < 8) {
            this.showResult(false, 'Пароль должен быть не менее 8 символов');
            return;
        }
        
        // Показываем индикатор загрузки
        const btn = document.querySelector('.backup-btn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Creating backup...';
        btn.disabled = true;
        
        try {
            const result = await AccountBackup.createBackup(password);
            
            if (result.success) {
                let message = `✅ Backup created: ${result.filename}`;
                if (result.stats) {
                    message += `<br><small>Chats: ${result.stats.chatsCount}, messages: ${result.stats.messagesCount}`;
                    if (result.stats.hasKeys) message += ', E2EE keys ✓';
                    message += '</small>';
                }
                this.showResult(true, message);
                this.updateLastBackupDisplay();
            } else {
                this.showResult(false, result.error);
            }
        } catch (error) {
            this.showResult(false, error.message);
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    },
    
    /**
     * Executes backup restoration
     */
    async doRestoreBackup() {
        const fileInput = document.getElementById('restore-file');
        const password = document.getElementById('restore-password').value;
        
        if (!fileInput.files || fileInput.files.length === 0) {
            this.showResult(false, 'Select backup file');
            return;
        }
        
        if (!password) {
            this.showResult(false, 'Enter backup password');
            return;
        }
        
        // Show loading indicator
        const btn = document.querySelector('.restore-btn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Restoring...';
        btn.disabled = true;
        
        try {
            const result = await AccountBackup.restoreBackup(fileInput.files[0], password);
            
            if (result.success) {
                let message = '✅ Data restored!';
                if (result.stats) {
                    message += `<br><small>Chats: ${result.stats.importedChats}, messages: ${result.stats.importedMessages}`;
                    if (result.stats.importedKeys) {
                        message += ', E2EE keys ✓';
                    } else if (result.stats.skippedKeys) {
                        message += ', keys preserved ✓';
                    }
                    message += '</small>';
                }
                this.showResult(true, message);
                
                // Suggest page reload using custom dialog
                setTimeout(async () => {
                    // Use showConfirm if available, fallback to native confirm
                    if (typeof showConfirm === 'function') {
                        const reload = await showConfirm(
                            'Reload page to apply restored data?',
                            'Data Restored',
                            'Reload',
                            'Later'
                        );
                        if (reload) {
                            location.reload();
                        }
                    } else if (confirm('Data restored. Reload page to apply changes?')) {
                        location.reload();
                    }
                }, 1500);
            } else {
                this.showResult(false, result.error);
            }
        } catch (error) {
            this.showResult(false, error.message);
        } finally {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    },
    
    /**
     * Показывает результат операции
     */
    showResult(success, message) {
        const resultDiv = document.getElementById('backup-result');
        resultDiv.classList.remove('hidden');
        resultDiv.innerHTML = `
            <div class="result-icon">${success ? '✅' : '❌'}</div>
            <div class="result-message ${success ? 'success' : 'error'}">${message}</div>
        `;
    },
    
    /**
     * Обновляет отображение даты последнего backup в Settings
     */
    updateLastBackupDisplay() {
        const lastBackupEl = document.getElementById('last-backup-date');
        if (lastBackupEl) {
            const date = AccountBackup.getLastBackupDate();
            if (date) {
                lastBackupEl.textContent = date.toLocaleString();
            } else {
                lastBackupEl.textContent = 'Never';
            }
        }
    },
    
    /**
     * Инициализация при загрузке страницы
     */
    init() {
        this.updateLastBackupDisplay();
    }
};

// Совместимость со старым кодом
const KeyBackup = AccountBackup;
const KeyBackupUI = AccountBackupUI;

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', () => {
    AccountBackupUI.init();
});

// Экспорт для использования в других модулях
if (typeof window !== 'undefined') {
    window.AccountBackup = AccountBackup;
    window.AccountBackupUI = AccountBackupUI;
    // Совместимость со старым кодом
    window.KeyBackup = AccountBackup;
    window.KeyBackupUI = AccountBackupUI;
}
