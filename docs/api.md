# API Documentation

## Base URL

```
http://your-server:8000/api/v1
```

## Authentication

All authenticated endpoints require Bearer token:

```
Authorization: Bearer <access_token>
```

---

## Auth Endpoints

### Register

```http
POST /auth/register
Content-Type: application/json

{
  "username": "alice",
  "password": "SecurePass123",
  "display_name": "Alice Smith",  // optional
  "device_id": "uuid"             // optional
}
```

**Response (201):**
```json
{
  "user": {
    "id": "uuid",
    "username": "alice",
    "display_name": "Alice Smith",
    "is_verified": false,
    "last_seen": null,
    "created_at": "2024-01-15T10:00:00Z"
  },
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "abc...",
    "token_type": "bearer",
    "expires_in": 1800
  }
}
```

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "username": "alice",
  "password": "SecurePass123",
  "device_id": "uuid"  // optional
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "abc..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "new_abc...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Logout

```http
POST /auth/logout?all_devices=false
Authorization: Bearer <token>
Content-Type: application/json

{
  "refresh_token": "abc..."  // optional
}
```

### Get Current User

```http
GET /auth/me
Authorization: Bearer <token>
```

---

## Keys Endpoints

### Upload Key Bundle

```http
POST /keys/bundle
Authorization: Bearer <token>
Content-Type: application/json

{
  "identity_key": "base64...",
  "signed_prekey_id": 1,
  "signed_prekey": "base64...",
  "signed_prekey_signature": "base64...",
  "one_time_prekeys": [
    {"id": 1, "key": "base64..."},
    {"id": 2, "key": "base64..."}
  ]
}
```

**Response (201):**
```json
{
  "status": "ok",
  "prekeys_count": 100
}
```

### Get User's Key Bundle

```http
GET /keys/bundle/{user_id}
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "identity_key": "base64...",
  "signed_prekey_id": 1,
  "signed_prekey": "base64...",
  "signed_prekey_signature": "base64...",
  "one_time_prekey": {"id": 1, "key": "base64..."}  // or null
}
```

> Note: One-time prekey is consumed (removed) on each request.

### Add One-Time Prekeys

```http
POST /keys/bundle/prekeys
Authorization: Bearer <token>
Content-Type: application/json

[
  {"id": 101, "key": "base64..."},
  {"id": 102, "key": "base64..."}
]
```

### Get Bundle Status

```http
GET /keys/bundle/status/me
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "has_bundle": true,
  "prekeys_remaining": 42,
  "signed_prekey_id": 1,
  "needs_replenishment": false
}
```

---

## Messages Endpoints

### Send Message

```http
POST /messages/send
Authorization: Bearer <token>
Content-Type: application/json

{
  "recipient_id": "uuid",
  "message_type": "text",
  "encrypted_payload": "base64...",
  "client_message_id": "uuid",  // optional, for deduplication
  "file_id": "uuid",            // optional, for file messages
  "expires_in_seconds": 86400   // optional, for disappearing messages
}
```

**Response (201):**
```json
{
  "id": "uuid",
  "sender_id": "uuid",
  "recipient_id": "uuid",
  "message_type": "text",
  "encrypted_payload": "base64...",
  "file_id": null,
  "status": "delivered",
  "client_message_id": "uuid",
  "created_at": "2024-01-15T10:00:00Z",
  "delivered_at": "2024-01-15T10:00:01Z",
  "expires_at": null
}
```

### Get Pending Messages

```http
GET /messages/pending?limit=100
Authorization: Bearer <token>
```

**Response (200):**
```json
[
  {
    "id": "uuid",
    "sender_id": "uuid",
    "message_type": "text",
    "encrypted_payload": "base64...",
    "created_at": "2024-01-15T10:00:00Z"
  }
]
```

### Acknowledge Messages

```http
POST /messages/ack
Authorization: Bearer <token>
Content-Type: application/json

{
  "message_ids": ["uuid1", "uuid2"],
  "status": "delivered"  // or "read"
}
```

### Get Message History

```http
GET /messages/history/{contact_id}?limit=50&before_id=uuid
Authorization: Bearer <token>
```

**Response (200):**
```json
[
  {
    "id": "uuid",
    "sender_id": "uuid",
    "recipient_id": "uuid",
    "message_type": "text",
    "encrypted_payload": "base64...",
    "status": "read",
    "created_at": "2024-01-15T10:00:00Z"
  }
]
```

### Send Typing Indicator

```http
POST /messages/typing/{contact_id}
Authorization: Bearer <token>
```

---

## WebSocket Protocol

### Connection

```
ws://server:8000/ws?token=<access_token>
```

### Message Format

```json
{
  "type": "message_type",
  "payload": {},
  "request_id": "optional_for_request_response"
}
```

### Client → Server Messages

#### Ping
```json
{"type": "ping"}
```

#### Send Message
```json
{
  "type": "send_message",
  "payload": {
    "recipient_id": "uuid",
    "encrypted_payload": "base64..."
  },
  "request_id": "123"
}
```

#### Acknowledge Message
```json
{
  "type": "ack_message",
  "payload": {
    "message_ids": ["uuid"],
    "status": "read"
  }
}
```

#### Typing Indicator
```json
{
  "type": "typing",
  "payload": {
    "contact_id": "uuid"
  }
}
```

### Server → Client Messages

#### Pong
```json
{"type": "pong"}
```

#### New Message
```json
{
  "type": "new_message",
  "payload": {
    "id": "uuid",
    "sender_id": "uuid",
    "encrypted_payload": "base64...",
    "created_at": "2024-01-15T10:00:00Z"
  }
}
```

#### Message Sent Confirmation
```json
{
  "type": "message_sent",
  "payload": {
    "message_id": "uuid",
    "client_message_id": "uuid",
    "status": "delivered"
  },
  "request_id": "123"
}
```

#### Message Status Update
```json
{
  "type": "message_status",
  "payload": {
    "message_id": "uuid",
    "status": "read",
    "timestamp": "2024-01-15T10:00:00Z"
  }
}
```

#### User Online/Offline
```json
{
  "type": "user_online",
  "payload": {"user_id": "uuid"}
}
```

#### User Typing
```json
{
  "type": "user_typing",
  "payload": {"user_id": "uuid"}
}
```

#### Error
```json
{
  "type": "error",
  "payload": {"error": "Error message"},
  "request_id": "123"
}
```

---

## Encrypted Payload Format

Messages are encrypted using Double Ratchet protocol:

```json
{
  "header": {
    "dh": "base64_dh_public_key",
    "pn": 0,
    "n": 5
  },
  "ciphertext": "base64_encrypted_content",
  "nonce": "base64_12_bytes",
  "mac": "base64_16_bytes"
}
```

Then base64 encoded for transport.

---

## Error Responses

```json
{
  "error": "Error description"
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Invalid/expired token |
| 403 | Forbidden - Access denied |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

---

## Rate Limits

- **REST API**: 100 requests per minute
- **WebSocket**: 50 messages per minute
- **File upload**: 10 uploads per hour

---

## Message Types

| Type | Description |
|------|-------------|
| `text` | Text message |
| `file` | File attachment |
| `image` | Image (with preview) |
| `voice` | Voice message |
| `key_exchange` | Initial key exchange message |
| `receipt` | Delivery/read receipt |
