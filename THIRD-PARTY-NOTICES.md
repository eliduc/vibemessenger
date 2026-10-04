# Third-party notices and licence audit

VibeMessenger itself is licensed **AGPL-3.0-only** (see [`LICENSE`](LICENSE)). This file records
every third-party component it depends on, that component's declared licence, and why the AGPL
choice is compatible with all of them.

The Python figures below were not transcribed by hand. They were read from
`importlib.metadata` inside the running production container, so they describe the versions
actually installed and shipped, not what a requirements file hoped for.

---

## 1. Vendored third-party source (checked into this repository)

These two files are *not* VibeMessenger's code. They keep their original licences and their
copyright notices must be preserved. They were deliberately **excluded** when the AGPL notice was
applied to the rest of the tree.

| File | Upstream | Licence |
| --- | --- | --- |
| `web-client/pq-kem.js` | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) v0.2.1 and `@noble/hashes` — ML-KEM-768 (FIPS 203) | MIT © 2024 / © 2022 Paul Miller (paulmillr.com) |
| `web-client/qrcode.min.js` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | MIT © 2009 Kazuhiko Arase |

Every other `.js`, `.py`, `.dart`, `.css` and `.sql` file in this repository is first-party work
and carries the AGPL notice at the top.

### Trademark note

"QR Code" is a registered trademark of DENSO WAVE INCORPORATED. This is a trademark matter only
and places no condition on the use or redistribution of the code above. (It is the reason the
PyPI `qrcode` package carries a stray `License :: Other/Proprietary License` classifier alongside
its actual BSD licence — the classifier is misleading metadata; the shipped `LICENSE` file is
plain 3-clause BSD from Lincoln Loop.)

---

## 2. Server dependencies (Python, as installed in production)

Grouped by declared SPDX licence.

| Licence | Packages |
| --- | --- |
| **MIT** | aiosqlite, annotated-doc, annotated-types, anyio, argon2-cffi, argon2-cffi-bindings, attrs, cbor2, charset-normalizer, Deprecated, ecdsa, fastapi, h11, http_ece, httptools, iniconfig, limits, pluggy, pydantic, pydantic-settings, pydantic_core, PyOTP, pytest, pytest-cov, python-jose, PyYAML, six, slowapi, SQLAlchemy, typing-inspection, urllib3, uvloop, watchfiles |
| **Apache-2.0** | aiofiles, aiosignal, asyncpg, coverage, frozenlist, multidict, propcache, pyOpenSSL, pytest-asyncio, python-multipart, requests, rsa, yarl |
| **BSD-3-Clause** | click, httpcore, httpx, idna, psutil, pyasn1_modules, pycparser, python-dotenv, qrcode, starlette, uvicorn, webauthn, websockets |
| **BSD-2-Clause** | pyasn1, Pygments, wrapt |
| **MPL-2.0** | certifi, py-vapid, pywebpush |
| **PSF-2.0** | aiohappyeyeballs, typing_extensions |
| **Apache-2.0 AND MIT** | aiohttp |
| **Apache-2.0 OR BSD-2-Clause** | packaging |
| **Apache-2.0 OR BSD-3-Clause** | cryptography |
| **MIT AND PSF-2.0** | greenlet |
| **MIT-0** | cffi |
| **MIT-CMU** (HPND) | pillow |

### MPL-2.0 obligation (the only non-permissive licence in the tree)

`pywebpush`, `py-vapid` and `certifi` are under the Mozilla Public License 2.0. MPL-2.0 is
*file-level* ("weak") copyleft: by §1.10 and §3.3 only the MPL-covered files themselves must stay
under MPL, and a Larger Work that merely uses them may be licensed under other terms. VibeMessenger
does not modify any of those files — it installs them unmodified from PyPI.

Per MPL-2.0 §3.2, recipients of a build that includes these packages (i.e. the Docker image) are
entitled to their source, which is available at:

- pywebpush — https://github.com/web-push-libs/pywebpush
- py-vapid — https://github.com/web-push-libs/vapid
- certifi — https://github.com/certifi/python-certifi

MPL-2.0 §1.12 additionally designates GNU AGPL v3 a "Secondary Licence", so combining MPL-covered
files with this AGPL-licensed work is explicitly permitted by the MPL itself.

---

## 3. Mobile client dependencies (Flutter/Dart)

The Flutter client under `client/` is an unfinished secondary target — the shipped product is the
web client plus the FastAPI server. Its declared dependencies (`client/pubspec.yaml`) are
`provider`, `flutter_riverpod`, `dio`, `web_socket_channel`, `cryptography`, `pointycastle`,
`flutter_secure_storage`, `sqflite`, `path`, `hive`, `hive_flutter`, `cupertino_icons`,
`flutter_svg`, `cached_network_image`, `flutter_webrtc`, `firebase_core`, `firebase_messaging`,
`flutter_local_notifications`, `uuid`, `intl`, `logger`, `equatable`, `freezed_annotation`,
`json_annotation` and `permission_handler`.

On pub.dev these are published under MIT, BSD-3-Clause or Apache-2.0, and the Flutter SDK itself
is BSD-3-Clause — all permissive and all AGPL-compatible. **This group was not verified from
installed package metadata**, because no Flutter SDK or pub cache exists on the machine where this
audit was run; it rests on the published licences rather than on a local measurement. Re-check with
`flutter pub deps` before relying on it for anything consequential.

Note that Firebase Cloud Messaging is a *hosted Google service*. Its client libraries are
permissively licensed, but using the service is governed by Google's terms, which is a service
agreement, not a software licence, and does not interact with this project's licence.

---

## 4. Infrastructure (separate programs, no licence propagation)

PostgreSQL 15 (PostgreSQL Licence), nginx (BSD-2-Clause), Docker / Docker Compose (Apache-2.0),
and the `python:3.11-slim` Debian base image (PSF plus the mixed licences of the Debian base
system, which includes GPL-licensed utilities). These run as separate processes that VibeMessenger
talks to over sockets; they are mere aggregation and do not place conditions on this project's own
licence. The Debian base layer's own GPL obligations attach to anyone redistributing that *image*,
not to this source repository.

---

## 5. Conclusion of the audit

- **No component is under GPL, LGPL, AGPL, SSPL, EUPL, CDDL, EPL or a Commons Clause rider.**
  A repository-wide search for those strings returns nothing.
- The strictest licence present anywhere is **MPL-2.0**, and its copyleft is file-scoped, so it
  does not reach VibeMessenger's own code.
- Consequently **no dependency dictates this project's licence** — the choice was free, and
  AGPL-3.0-only was selected as the strictest licence available rather than as one that was forced.
- Every licence listed above is one-way compatible with AGPL-3.0: permissive terms may be
  incorporated into a copyleft work, not the reverse. Nothing here had to be dropped or replaced.

This is a technical inventory of declared licences, not legal advice. If VibeMessenger is ever
distributed commercially or relicensed, have a lawyer review it — in particular the copyright
holder line in each file header, which only the rights holder can state authoritatively.
