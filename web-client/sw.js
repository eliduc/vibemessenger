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

// Service Worker for Push Notifications and Offline Support
// v3.2.4 - Updated cache for E2EE decrypted messages storage
const CACHE_NAME = 'messenger-v27';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/style.css',
    // '/vibe-crypto.js', // Don't cache - use versioned URL
    // '/app.js', // Don't cache - use versioned URL
    '/manifest.json',
    '/icon-192.png',
    '/icon-512.png'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    console.log('Service Worker installing, caching assets...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
            .catch((err) => {
                console.error('Cache addAll failed:', err);
                self.skipWaiting();
            })
    );
});

// Activate event - clean old caches
self.addEventListener('activate', (event) => {
    console.log('Service Worker activated');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => {
                        console.log('Deleting old cache:', name);
                        return caches.delete(name);
                    })
            );
        }).then(() => clients.claim())
    );
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Skip API requests and WebSocket - always go to network
    if (url.pathname.startsWith('/api/') || 
        url.pathname.startsWith('/ws') ||
        event.request.method !== 'GET') {
        return;
    }
    
    // For static assets - cache first, then network
    event.respondWith(
        caches.match(event.request)
            .then((cachedResponse) => {
                if (cachedResponse) {
                    // Return cached version, but also fetch fresh in background
                    event.waitUntil(
                        fetch(event.request)
                            .then((networkResponse) => {
                                if (networkResponse && networkResponse.status === 200) {
                                    caches.open(CACHE_NAME).then((cache) => {
                                        cache.put(event.request, networkResponse);
                                    });
                                }
                            })
                            .catch(() => {})
                    );
                    return cachedResponse;
                }
                
                // Not in cache - fetch from network
                return fetch(event.request)
                    .then((networkResponse) => {
                        // Cache successful responses
                        if (networkResponse && networkResponse.status === 200) {
                            const responseClone = networkResponse.clone();
                            caches.open(CACHE_NAME).then((cache) => {
                                cache.put(event.request, responseClone);
                            });
                        }
                        return networkResponse;
                    })
                    .catch(() => {
                        // Offline and not in cache - return offline page for navigation
                        if (event.request.mode === 'navigate') {
                            return caches.match('/index.html');
                        }
                        return new Response('Offline', { status: 503 });
                    });
            })
    );
});

// Push event - receive push notification
self.addEventListener('push', (event) => {
    console.log('Push received:', event);
    
    let data = {
        title: 'Secure Messenger',
        body: 'New notification',
        icon: '/icon-192.png',
        badge: '/badge-96.png',
        tag: 'messenger-notification',
        data: {}
    };
    
    if (event.data) {
        try {
            const payload = event.data.json();
            data = { ...data, ...payload };
        } catch (e) {
            data.body = event.data.text();
        }
    }
    
    const options = {
        body: data.body,
        icon: data.icon || '/icon-192.png',
        badge: data.badge || '/badge-96.png',
        tag: data.tag || 'messenger-notification',
        vibrate: [200, 100, 200, 100, 200],
        requireInteraction: data.type === 'call',
        actions: data.type === 'call' ? [
            { action: 'answer', title: '✓ Answer' },
            { action: 'reject', title: '✕ Reject' }
        ] : [],
        data: data.data || {}
    };
    
    // Check if any window is focused before showing notification
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                // For calls, always show notification
                if (data.type === 'call') {
                    console.log('Showing call notification');
                    return self.registration.showNotification(data.title, options);
                }
                
                // For messages, check if app is visible and focused
                let isAppActive = false;
                for (const client of clientList) {
                    // Check if window is visible (not minimized, not hidden tab)
                    if (client.visibilityState === 'visible') {
                        isAppActive = true;
                        break;
                    }
                }
                
                // Show notification if app is NOT active (minimized, hidden, or closed)
                if (!isAppActive) {
                    console.log('Showing notification - app not visible');
                    return self.registration.showNotification(data.title, options);
                } else {
                    console.log('Skipping notification - app is visible');
                    return Promise.resolve();
                }
            })
    );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
    console.log('Notification clicked:', event.action);
    event.notification.close();
    
    const data = event.notification.data || {};
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            // Try to focus existing window
            for (const client of clientList) {
                if (client.url.includes(self.location.origin) && 'focus' in client) {
                    client.focus();
                    // Send action to client
                    client.postMessage({
                        type: 'notification-click',
                        action: event.action,
                        data: data
                    });
                    return;
                }
            }
            // Open new window if none exists
            if (clients.openWindow) {
                return clients.openWindow('/');
            }
        })
    );
});

// Notification close event
self.addEventListener('notificationclose', (event) => {
    console.log('Notification closed');
});

// Push subscription change event - handles VAPID key changes
self.addEventListener('pushsubscriptionchange', (event) => {
    console.log('Push subscription changed, attempting to resubscribe...');
    
    event.waitUntil(
        (async () => {
            try {
                // Get the old subscription's application server key if available
                const oldSubscription = event.oldSubscription;
                const applicationServerKey = oldSubscription?.options?.applicationServerKey;
                
                if (!applicationServerKey) {
                    console.warn('No application server key available for resubscription');
                    // Notify main app to handle resubscription
                    const clients = await self.clients.matchAll({ type: 'window' });
                    for (const client of clients) {
                        client.postMessage({
                            type: 'push-subscription-expired',
                            reason: 'no-key'
                        });
                    }
                    return;
                }
                
                // Try to create a new subscription with the same key
                const newSubscription = await self.registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: applicationServerKey
                });
                
                console.log('New push subscription created:', newSubscription.endpoint);
                
                // Get auth token from IndexedDB or notify app
                // Since SW can't easily access localStorage, notify the main app
                const clients = await self.clients.matchAll({ type: 'window' });
                
                if (clients.length > 0) {
                    // App is open - let it handle the server update
                    for (const client of clients) {
                        client.postMessage({
                            type: 'push-subscription-changed',
                            subscription: newSubscription.toJSON()
                        });
                    }
                } else {
                    // App not open - store for later sync
                    // This is a limitation - user needs to open app to complete resubscription
                    console.warn('App not open, subscription update pending');
                }
            } catch (err) {
                console.error('Failed to resubscribe:', err);
                // Notify main app about the failure
                const clients = await self.clients.matchAll({ type: 'window' });
                for (const client of clients) {
                    client.postMessage({
                        type: 'push-subscription-expired',
                        reason: 'resubscribe-failed',
                        error: err.message
                    });
                }
            }
        })()
    );
});
