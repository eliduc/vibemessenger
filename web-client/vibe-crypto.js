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
 * VibeMessenger E2EE Cryptography Module
 * 
 * Implements Signal Protocol for end-to-end encryption:
 * - X3DH (Extended Triple Diffie-Hellman) for key agreement
 * - Double Ratchet for forward secrecy
 * - Sender Keys for group messaging
 * 
 * @version 2.0.0 - PQXDH (post-quantum hybrid key exchange)
 * @license AGPL-3.0-only (see the notice at the top of this file and ../LICENSE)
 */

(function(global) {
    'use strict';

    // ============================================================================
    // SECTION 1: TweetNaCl - Minimal NaCl crypto library
    // https://tweetnacl.js.org/ - Public domain
    // Provides: X25519, Ed25519, random bytes
    // ============================================================================

    var nacl = (function() {
        'use strict';

        var gf = function(init) {
            var i, r = new Float64Array(16);
            if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
            return r;
        };

        var randombytes = function(x, n) {
            var i, v = new Uint8Array(n);
            crypto.getRandomValues(v);
            for (i = 0; i < n; i++) x[i] = v[i];
        };

        var _0 = new Uint8Array(16);
        var _9 = new Uint8Array(32); _9[0] = 9;

        var gf0 = gf(),
            gf1 = gf([1]),
            _121665 = gf([0xdb41, 1]),
            D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
            D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
            X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
            Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
            I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

        function ts64(x, i, h, l) {
            x[i]   = (h >> 24) & 0xff;
            x[i+1] = (h >> 16) & 0xff;
            x[i+2] = (h >>  8) & 0xff;
            x[i+3] = h & 0xff;
            x[i+4] = (l >> 24)  & 0xff;
            x[i+5] = (l >> 16)  & 0xff;
            x[i+6] = (l >>  8)  & 0xff;
            x[i+7] = l & 0xff;
        }

        function vn(x, xi, y, yi, n) {
            var i, d = 0;
            for (i = 0; i < n; i++) d |= x[xi+i]^y[yi+i];
            return (1 & ((d - 1) >>> 8)) - 1;
        }

        function crypto_verify_32(x, xi, y, yi) {
            return vn(x,xi,y,yi,32);
        }

        function set25519(r, a) {
            var i;
            for (i = 0; i < 16; i++) r[i] = a[i]|0;
        }

        function car25519(o) {
            var i, v, c = 1;
            for (i = 0; i < 16; i++) {
                v = o[i] + c + 65535;
                c = Math.floor(v / 65536);
                o[i] = v - c * 65536;
            }
            o[0] += c-1 + 37 * (c-1);
        }

        function sel25519(p, q, b) {
            var t, c = ~(b-1);
            for (var i = 0; i < 16; i++) {
                t = c & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        function pack25519(o, n) {
            var i, j, b;
            var m = gf(), t = gf();
            for (i = 0; i < 16; i++) t[i] = n[i];
            car25519(t);
            car25519(t);
            car25519(t);
            for (j = 0; j < 2; j++) {
                m[0] = t[0] - 0xffed;
                for (i = 1; i < 15; i++) {
                    m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
                    m[i-1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
                b = (m[15]>>16) & 1;
                m[14] &= 0xffff;
                sel25519(t, m, 1-b);
            }
            for (i = 0; i < 16; i++) {
                o[2*i] = t[i] & 0xff;
                o[2*i+1] = t[i]>>8;
            }
        }

        function neq25519(a, b) {
            var c = new Uint8Array(32), d = new Uint8Array(32);
            pack25519(c, a);
            pack25519(d, b);
            return crypto_verify_32(c, 0, d, 0);
        }

        function par25519(a) {
            var d = new Uint8Array(32);
            pack25519(d, a);
            return d[0] & 1;
        }

        function unpack25519(o, n) {
            var i;
            for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
            o[15] &= 0x7fff;
        }

        function A(o, a, b) {
            for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
        }

        function Z(o, a, b) {
            for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
        }

        function M(o, a, b) {
            var v, c,
                t0 = 0,  t1 = 0,  t2 = 0,  t3 = 0,  t4 = 0,  t5 = 0,  t6 = 0,  t7 = 0,
                t8 = 0,  t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
                t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
                t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0,
                b0 = b[0],
                b1 = b[1],
                b2 = b[2],
                b3 = b[3],
                b4 = b[4],
                b5 = b[5],
                b6 = b[6],
                b7 = b[7],
                b8 = b[8],
                b9 = b[9],
                b10 = b[10],
                b11 = b[11],
                b12 = b[12],
                b13 = b[13],
                b14 = b[14],
                b15 = b[15];

            v = a[0];
            t0 += v * b0;
            t1 += v * b1;
            t2 += v * b2;
            t3 += v * b3;
            t4 += v * b4;
            t5 += v * b5;
            t6 += v * b6;
            t7 += v * b7;
            t8 += v * b8;
            t9 += v * b9;
            t10 += v * b10;
            t11 += v * b11;
            t12 += v * b12;
            t13 += v * b13;
            t14 += v * b14;
            t15 += v * b15;
            v = a[1];
            t1 += v * b0;
            t2 += v * b1;
            t3 += v * b2;
            t4 += v * b3;
            t5 += v * b4;
            t6 += v * b5;
            t7 += v * b6;
            t8 += v * b7;
            t9 += v * b8;
            t10 += v * b9;
            t11 += v * b10;
            t12 += v * b11;
            t13 += v * b12;
            t14 += v * b13;
            t15 += v * b14;
            t16 += v * b15;
            v = a[2];
            t2 += v * b0;
            t3 += v * b1;
            t4 += v * b2;
            t5 += v * b3;
            t6 += v * b4;
            t7 += v * b5;
            t8 += v * b6;
            t9 += v * b7;
            t10 += v * b8;
            t11 += v * b9;
            t12 += v * b10;
            t13 += v * b11;
            t14 += v * b12;
            t15 += v * b13;
            t16 += v * b14;
            t17 += v * b15;
            v = a[3];
            t3 += v * b0;
            t4 += v * b1;
            t5 += v * b2;
            t6 += v * b3;
            t7 += v * b4;
            t8 += v * b5;
            t9 += v * b6;
            t10 += v * b7;
            t11 += v * b8;
            t12 += v * b9;
            t13 += v * b10;
            t14 += v * b11;
            t15 += v * b12;
            t16 += v * b13;
            t17 += v * b14;
            t18 += v * b15;
            v = a[4];
            t4 += v * b0;
            t5 += v * b1;
            t6 += v * b2;
            t7 += v * b3;
            t8 += v * b4;
            t9 += v * b5;
            t10 += v * b6;
            t11 += v * b7;
            t12 += v * b8;
            t13 += v * b9;
            t14 += v * b10;
            t15 += v * b11;
            t16 += v * b12;
            t17 += v * b13;
            t18 += v * b14;
            t19 += v * b15;
            v = a[5];
            t5 += v * b0;
            t6 += v * b1;
            t7 += v * b2;
            t8 += v * b3;
            t9 += v * b4;
            t10 += v * b5;
            t11 += v * b6;
            t12 += v * b7;
            t13 += v * b8;
            t14 += v * b9;
            t15 += v * b10;
            t16 += v * b11;
            t17 += v * b12;
            t18 += v * b13;
            t19 += v * b14;
            t20 += v * b15;
            v = a[6];
            t6 += v * b0;
            t7 += v * b1;
            t8 += v * b2;
            t9 += v * b3;
            t10 += v * b4;
            t11 += v * b5;
            t12 += v * b6;
            t13 += v * b7;
            t14 += v * b8;
            t15 += v * b9;
            t16 += v * b10;
            t17 += v * b11;
            t18 += v * b12;
            t19 += v * b13;
            t20 += v * b14;
            t21 += v * b15;
            v = a[7];
            t7 += v * b0;
            t8 += v * b1;
            t9 += v * b2;
            t10 += v * b3;
            t11 += v * b4;
            t12 += v * b5;
            t13 += v * b6;
            t14 += v * b7;
            t15 += v * b8;
            t16 += v * b9;
            t17 += v * b10;
            t18 += v * b11;
            t19 += v * b12;
            t20 += v * b13;
            t21 += v * b14;
            t22 += v * b15;
            v = a[8];
            t8 += v * b0;
            t9 += v * b1;
            t10 += v * b2;
            t11 += v * b3;
            t12 += v * b4;
            t13 += v * b5;
            t14 += v * b6;
            t15 += v * b7;
            t16 += v * b8;
            t17 += v * b9;
            t18 += v * b10;
            t19 += v * b11;
            t20 += v * b12;
            t21 += v * b13;
            t22 += v * b14;
            t23 += v * b15;
            v = a[9];
            t9 += v * b0;
            t10 += v * b1;
            t11 += v * b2;
            t12 += v * b3;
            t13 += v * b4;
            t14 += v * b5;
            t15 += v * b6;
            t16 += v * b7;
            t17 += v * b8;
            t18 += v * b9;
            t19 += v * b10;
            t20 += v * b11;
            t21 += v * b12;
            t22 += v * b13;
            t23 += v * b14;
            t24 += v * b15;
            v = a[10];
            t10 += v * b0;
            t11 += v * b1;
            t12 += v * b2;
            t13 += v * b3;
            t14 += v * b4;
            t15 += v * b5;
            t16 += v * b6;
            t17 += v * b7;
            t18 += v * b8;
            t19 += v * b9;
            t20 += v * b10;
            t21 += v * b11;
            t22 += v * b12;
            t23 += v * b13;
            t24 += v * b14;
            t25 += v * b15;
            v = a[11];
            t11 += v * b0;
            t12 += v * b1;
            t13 += v * b2;
            t14 += v * b3;
            t15 += v * b4;
            t16 += v * b5;
            t17 += v * b6;
            t18 += v * b7;
            t19 += v * b8;
            t20 += v * b9;
            t21 += v * b10;
            t22 += v * b11;
            t23 += v * b12;
            t24 += v * b13;
            t25 += v * b14;
            t26 += v * b15;
            v = a[12];
            t12 += v * b0;
            t13 += v * b1;
            t14 += v * b2;
            t15 += v * b3;
            t16 += v * b4;
            t17 += v * b5;
            t18 += v * b6;
            t19 += v * b7;
            t20 += v * b8;
            t21 += v * b9;
            t22 += v * b10;
            t23 += v * b11;
            t24 += v * b12;
            t25 += v * b13;
            t26 += v * b14;
            t27 += v * b15;
            v = a[13];
            t13 += v * b0;
            t14 += v * b1;
            t15 += v * b2;
            t16 += v * b3;
            t17 += v * b4;
            t18 += v * b5;
            t19 += v * b6;
            t20 += v * b7;
            t21 += v * b8;
            t22 += v * b9;
            t23 += v * b10;
            t24 += v * b11;
            t25 += v * b12;
            t26 += v * b13;
            t27 += v * b14;
            t28 += v * b15;
            v = a[14];
            t14 += v * b0;
            t15 += v * b1;
            t16 += v * b2;
            t17 += v * b3;
            t18 += v * b4;
            t19 += v * b5;
            t20 += v * b6;
            t21 += v * b7;
            t22 += v * b8;
            t23 += v * b9;
            t24 += v * b10;
            t25 += v * b11;
            t26 += v * b12;
            t27 += v * b13;
            t28 += v * b14;
            t29 += v * b15;
            v = a[15];
            t15 += v * b0;
            t16 += v * b1;
            t17 += v * b2;
            t18 += v * b3;
            t19 += v * b4;
            t20 += v * b5;
            t21 += v * b6;
            t22 += v * b7;
            t23 += v * b8;
            t24 += v * b9;
            t25 += v * b10;
            t26 += v * b11;
            t27 += v * b12;
            t28 += v * b13;
            t29 += v * b14;
            t30 += v * b15;

            t0  += 38 * t16;
            t1  += 38 * t17;
            t2  += 38 * t18;
            t3  += 38 * t19;
            t4  += 38 * t20;
            t5  += 38 * t21;
            t6  += 38 * t22;
            t7  += 38 * t23;
            t8  += 38 * t24;
            t9  += 38 * t25;
            t10 += 38 * t26;
            t11 += 38 * t27;
            t12 += 38 * t28;
            t13 += 38 * t29;
            t14 += 38 * t30;

            c = 1;
            v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
            v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
            v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
            v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
            v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
            v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
            v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
            v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
            v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
            v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
            v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
            v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
            v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
            v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
            v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
            v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
            t0 += c-1 + 37 * (c-1);

            c = 1;
            v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
            v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
            v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
            v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
            v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
            v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
            v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
            v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
            v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
            v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
            v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
            v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
            v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
            v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
            v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
            v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
            t0 += c-1 + 37 * (c-1);

            o[ 0] = t0;
            o[ 1] = t1;
            o[ 2] = t2;
            o[ 3] = t3;
            o[ 4] = t4;
            o[ 5] = t5;
            o[ 6] = t6;
            o[ 7] = t7;
            o[ 8] = t8;
            o[ 9] = t9;
            o[10] = t10;
            o[11] = t11;
            o[12] = t12;
            o[13] = t13;
            o[14] = t14;
            o[15] = t15;
        }

        function S(o, a) {
            M(o, a, a);
        }

        function inv25519(o, i) {
            var c = gf();
            var a;
            for (a = 0; a < 16; a++) c[a] = i[a];
            for (a = 253; a >= 0; a--) {
                S(c, c);
                if(a !== 2 && a !== 4) M(c, c, i);
            }
            for (a = 0; a < 16; a++) o[a] = c[a];
        }

        function pow2523(o, i) {
            var c = gf();
            var a;
            for (a = 0; a < 16; a++) c[a] = i[a];
            for (a = 250; a >= 0; a--) {
                S(c, c);
                if(a !== 1) M(c, c, i);
            }
            for (a = 0; a < 16; a++) o[a] = c[a];
        }

        function crypto_scalarmult(q, n, p) {
            var z = new Uint8Array(32);
            var x = new Float64Array(80), r, i;
            var a = gf(), b = gf(), c = gf(),
                d = gf(), e = gf(), f = gf();
            for (i = 0; i < 31; i++) z[i] = n[i];
            z[31]=(n[31]&127)|64;
            z[0]&=248;
            unpack25519(x,p);
            for (i = 0; i < 16; i++) {
                b[i]=x[i];
                d[i]=a[i]=c[i]=0;
            }
            a[0]=d[0]=1;
            for (i=254; i>=0; --i) {
                r=(z[i>>>3]>>>(i&7))&1;
                sel25519(a,b,r);
                sel25519(c,d,r);
                A(e,a,c);
                Z(a,a,c);
                A(c,b,d);
                Z(b,b,d);
                S(d,e);
                S(f,a);
                M(a,c,a);
                M(c,b,e);
                A(e,a,c);
                Z(a,a,c);
                S(b,a);
                Z(c,d,f);
                M(a,c,_121665);
                A(a,a,d);
                M(c,c,a);
                M(a,d,f);
                M(d,b,x);
                S(b,e);
                sel25519(a,b,r);
                sel25519(c,d,r);
            }
            for (i = 0; i < 16; i++) {
                x[i+16]=a[i];
                x[i+32]=c[i];
                x[i+48]=b[i];
                x[i+64]=d[i];
            }
            var x32 = x.subarray(32);
            var x16 = x.subarray(16);
            inv25519(x32,x32);
            M(x16,x16,x32);
            pack25519(q,x16);
            return 0;
        }

        function crypto_scalarmult_base(q, n) {
            return crypto_scalarmult(q, n, _9);
        }

        // Ed25519 signing
        var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

        function modL(r, x) {
            var carry, i, j, k;
            for (i = 63; i >= 32; --i) {
                carry = 0;
                for (j = i - 32, k = i - 12; j < k; ++j) {
                    x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                    carry = Math.floor((x[j] + 128) / 256);
                    x[j] -= carry * 256;
                }
                x[j] += carry;
                x[i] = 0;
            }
            carry = 0;
            for (j = 0; j < 32; j++) {
                x[j] += carry - (x[31] >> 4) * L[j];
                carry = x[j] >> 8;
                x[j] &= 255;
            }
            for (j = 0; j < 32; j++) x[j] -= carry * L[j];
            for (i = 0; i < 32; i++) {
                x[i+1] += x[i] >> 8;
                r[i] = x[i] & 255;
            }
        }

        function reduce(r) {
            var x = new Float64Array(64), i;
            for (i = 0; i < 64; i++) x[i] = r[i];
            for (i = 0; i < 64; i++) r[i] = 0;
            modL(r, x);
        }

        function crypto_hash(out, m, n) {
            var h = new Uint8Array(64);
            var x = new Uint8Array(256);
            var i, b = n;

            for (i = 0; i < 64; i++) h[i] = 0;
            
            // SHA-512 constants
            var K = [
                0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
                0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
                0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
                0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
                0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
                0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
                0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
                0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
                0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
                0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
                0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
                0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
                0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
                0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
                0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
                0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
                0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
                0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
                0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
                0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
                0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
                0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
                0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
                0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
                0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
                0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
                0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
                0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
                0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
                0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
                0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
                0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
                0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
                0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
                0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
                0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
                0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
                0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
                0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
                0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
            ];

            // Initial hash values
            var H = [
                0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
                0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
                0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
                0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
            ];

            function hashBlock(w, H, K) {
                var a = [H[0], H[1]], b = [H[2], H[3]], c = [H[4], H[5]], d = [H[6], H[7]];
                var e = [H[8], H[9]], f = [H[10], H[11]], g = [H[12], H[13]], h = [H[14], H[15]];
                
                for (var j = 16; j < 80; j++) {
                    // Simplified - using standard operations
                    var s0h = ((w[j*2-30] >>> 1) | (w[j*2-29] << 31)) ^ ((w[j*2-30] >>> 8) | (w[j*2-29] << 24)) ^ (w[j*2-30] >>> 7);
                    var s0l = ((w[j*2-29] >>> 1) | (w[j*2-30] << 31)) ^ ((w[j*2-29] >>> 8) | (w[j*2-30] << 24)) ^ ((w[j*2-29] >>> 7) | (w[j*2-30] << 25));
                    var s1h = ((w[j*2-4] >>> 19) | (w[j*2-3] << 13)) ^ ((w[j*2-3] >>> 29) | (w[j*2-4] << 3)) ^ (w[j*2-4] >>> 6);
                    var s1l = ((w[j*2-3] >>> 19) | (w[j*2-4] << 13)) ^ ((w[j*2-4] >>> 29) | (w[j*2-3] << 3)) ^ ((w[j*2-3] >>> 6) | (w[j*2-4] << 26));
                    
                    var lo = w[j*2-13] + s0l + w[j*2-31] + s1l;
                    var hi = w[j*2-14] + s0h + w[j*2-32] + s1h + (lo < 0 ? 1 : 0);
                    w[j*2] = hi >>> 0;
                    w[j*2+1] = lo >>> 0;
                }
            }

            // Use SubtleCrypto for SHA-512 (fallback to simplified)
            return crypto.subtle.digest('SHA-512', m.slice(0, n)).then(function(hash) {
                var arr = new Uint8Array(hash);
                for (var i = 0; i < 64; i++) out[i] = arr[i];
                return 0;
            });
        }

        // Synchronous SHA-512 using SubtleCrypto workaround
        var sha512Pending = null;
        function sha512(out, m, n) {
            return crypto.subtle.digest('SHA-512', m.slice(0, n)).then(function(hash) {
                var arr = new Uint8Array(hash);
                for (var i = 0; i < 64; i++) out[i] = arr[i];
            });
        }

        function add(p, q) {
            var a = gf(), b = gf(), c = gf(),
                d = gf(), e = gf(), f = gf(),
                g = gf(), h = gf(), t = gf();

            Z(a, p[1], p[0]);
            Z(t, q[1], q[0]);
            M(a, a, t);
            A(b, p[0], p[1]);
            A(t, q[0], q[1]);
            M(b, b, t);
            M(c, p[3], q[3]);
            M(c, c, D2);
            M(d, p[2], q[2]);
            A(d, d, d);
            Z(e, b, a);
            Z(f, d, c);
            A(g, d, c);
            A(h, b, a);

            M(p[0], e, f);
            M(p[1], h, g);
            M(p[2], g, f);
            M(p[3], e, h);
        }

        function cswap(p, q, b) {
            var i;
            for (i = 0; i < 4; i++) {
                sel25519(p[i], q[i], b);
            }
        }

        function pack(r, p) {
            var tx = gf(), ty = gf(), zi = gf();
            inv25519(zi, p[2]);
            M(tx, p[0], zi);
            M(ty, p[1], zi);
            pack25519(r, ty);
            r[31] ^= par25519(tx) << 7;
        }

        function scalarmult(p, q, s) {
            var b, i;
            set25519(p[0], gf0);
            set25519(p[1], gf1);
            set25519(p[2], gf1);
            set25519(p[3], gf0);
            for (i = 255; i >= 0; --i) {
                b = (s[(i/8)|0] >> (i&7)) & 1;
                cswap(p, q, b);
                add(q, p);
                add(p, p);
                cswap(p, q, b);
            }
        }

        function scalarbase(p, s) {
            var q = [gf(), gf(), gf(), gf()];
            set25519(q[0], X);
            set25519(q[1], Y);
            set25519(q[2], gf1);
            M(q[3], X, Y);
            scalarmult(p, q, s);
        }

        var crypto_sign_BYTES = 64,
            crypto_sign_PUBLICKEYBYTES = 32,
            crypto_sign_SECRETKEYBYTES = 64,
            crypto_sign_SEEDBYTES = 32;

        async function crypto_sign_keypair(pk, sk, seeded) {
            var d = new Uint8Array(64);
            var p = [gf(), gf(), gf(), gf()];
            var i;

            if (!seeded) randombytes(sk, 32);
            await sha512(d, sk, 32);
            d[0] &= 248;
            d[31] &= 127;
            d[31] |= 64;

            scalarbase(p, d);
            pack(pk, p);

            for (i = 0; i < 32; i++) sk[i+32] = pk[i];
            return 0;
        }

        async function crypto_sign(sm, m, n, sk) {
            var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
            var i, j, x = new Float64Array(64);
            var p = [gf(), gf(), gf(), gf()];

            await sha512(d, sk, 32);
            d[0] &= 248;
            d[31] &= 127;
            d[31] |= 64;

            var smlen = n + 64;
            for (i = 0; i < n; i++) sm[64 + i] = m[i];
            for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

            await sha512(r, sm.subarray(32), n + 32);
            reduce(r);
            scalarbase(p, r);
            pack(sm, p);

            for (i = 0; i < 32; i++) sm[i+32] = sk[i+32];
            await sha512(h, sm, n + 64);
            reduce(h);

            for (i = 0; i < 64; i++) x[i] = 0;
            for (i = 0; i < 32; i++) x[i] = r[i];
            for (i = 0; i < 32; i++) {
                for (j = 0; j < 32; j++) {
                    x[i+j] += h[i] * d[j];
                }
            }

            modL(sm.subarray(32), x);
            return smlen;
        }

        function unpackneg(r, p) {
            var t = gf(), chk = gf(), num = gf(),
                den = gf(), den2 = gf(), den4 = gf(),
                den6 = gf();

            set25519(r[2], gf1);
            unpack25519(r[1], p);
            S(num, r[1]);
            M(den, num, D);
            Z(num, num, r[2]);
            A(den, r[2], den);

            S(den2, den);
            S(den4, den2);
            M(den6, den4, den2);
            M(t, den6, num);
            M(t, t, den);

            pow2523(t, t);
            M(t, t, num);
            M(t, t, den);
            M(t, t, den);
            M(r[0], t, den);

            S(chk, r[0]);
            M(chk, chk, den);
            if (neq25519(chk, num)) M(r[0], r[0], I);

            S(chk, r[0]);
            M(chk, chk, den);
            if (neq25519(chk, num)) return -1;

            if (par25519(r[0]) === (p[31]>>7)) Z(r[0], gf0, r[0]);

            M(r[3], r[0], r[1]);
            return 0;
        }

        async function crypto_sign_open(m, sm, n, pk) {
            var i;
            var t = new Uint8Array(32), h = new Uint8Array(64);
            var p = [gf(), gf(), gf(), gf()],
                q = [gf(), gf(), gf(), gf()];

            if (n < 64) return -1;

            if (unpackneg(q, pk)) return -1;

            for (i = 0; i < n; i++) m[i] = sm[i];
            for (i = 0; i < 32; i++) m[i+32] = pk[i];
            await sha512(h, m, n);
            reduce(h);
            scalarmult(p, q, h);

            scalarbase(q, sm.subarray(32));
            add(p, q);
            pack(t, p);

            n -= 64;
            if (crypto_verify_32(sm, 0, t, 0)) {
                for (i = 0; i < n; i++) m[i] = 0;
                return -1;
            }

            for (i = 0; i < n; i++) m[i] = sm[i + 64];
            return n;
        }

        // Public API
        return {
            // Random bytes
            randomBytes: function(n) {
                var b = new Uint8Array(n);
                randombytes(b, n);
                return b;
            },

            // X25519 key exchange
            box: {
                keyPair: function() {
                    var pk = new Uint8Array(32);
                    var sk = new Uint8Array(32);
                    randombytes(sk, 32);
                    crypto_scalarmult_base(pk, sk);
                    return {publicKey: pk, secretKey: sk};
                },
                keyPair_fromSecretKey: function(secretKey) {
                    var pk = new Uint8Array(32);
                    crypto_scalarmult_base(pk, secretKey);
                    return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
                },
                sharedKey: function(theirPublicKey, mySecretKey) {
                    var q = new Uint8Array(32);
                    crypto_scalarmult(q, mySecretKey, theirPublicKey);
                    return q;
                }
            },

            // Ed25519 signing
            sign: {
                keyPair: async function() {
                    var pk = new Uint8Array(32);
                    var sk = new Uint8Array(64);
                    await crypto_sign_keypair(pk, sk, false);
                    return {publicKey: pk, secretKey: sk};
                },
                keyPair_fromSeed: async function(seed) {
                    var pk = new Uint8Array(32);
                    var sk = new Uint8Array(64);
                    for (var i = 0; i < 32; i++) sk[i] = seed[i];
                    await crypto_sign_keypair(pk, sk, true);
                    return {publicKey: pk, secretKey: sk};
                },
                detached: async function(msg, secretKey) {
                    var signedMsg = new Uint8Array(64 + msg.length);
                    await crypto_sign(signedMsg, msg, msg.length, secretKey);
                    var sig = new Uint8Array(64);
                    for (var i = 0; i < 64; i++) sig[i] = signedMsg[i];
                    return sig;
                },
                detached_verify: async function(msg, sig, publicKey) {
                    var sm = new Uint8Array(64 + msg.length);
                    var m = new Uint8Array(64 + msg.length);
                    var i;
                    for (i = 0; i < 64; i++) sm[i] = sig[i];
                    for (i = 0; i < msg.length; i++) sm[i+64] = msg[i];
                    return (await crypto_sign_open(m, sm, sm.length, publicKey)) >= 0;
                }
            }
        };
    })();

    // ============================================================================
    // SECTION 2: Utility Functions
    // ============================================================================

    const Utils = {
        // Convert Uint8Array to base64
        toBase64: function(bytes) {
            let binary = '';
            for (let i = 0; i < bytes.length; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        },

        // Convert base64 to Uint8Array
        fromBase64: function(base64) {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        },

        // Convert Uint8Array to hex
        toHex: function(bytes) {
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        },

        // Convert hex to Uint8Array
        fromHex: function(hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            }
            return bytes;
        },

        // Convert string to Uint8Array (UTF-8)
        stringToBytes: function(str) {
            return new TextEncoder().encode(str);
        },

        // Convert Uint8Array to string (UTF-8)
        bytesToString: function(bytes) {
            return new TextDecoder().decode(bytes);
        },

        // Concatenate multiple Uint8Arrays
        concat: function(...arrays) {
            const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
            const result = new Uint8Array(totalLength);
            let offset = 0;
            for (const arr of arrays) {
                result.set(arr, offset);
                offset += arr.length;
            }
            return result;
        },

        // Compare two Uint8Arrays
        equal: function(a, b) {
            if (a.length !== b.length) return false;
            for (let i = 0; i < a.length; i++) {
                if (a[i] !== b[i]) return false;
            }
            return true;
        },

        // Generate random bytes
        randomBytes: function(length) {
            return nacl.randomBytes(length);
        },

        // Generate UUID v4
        generateUUID: function() {
            const bytes = nacl.randomBytes(16);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            const hex = Utils.toHex(bytes);
            return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
        }
    };

    // ============================================================================
    // SECTION 3: AES-256-GCM Encryption (using Web Crypto API)
    // ============================================================================

    const AesGcm = {
        NONCE_LENGTH: 12,  // 96 bits for GCM
        TAG_LENGTH: 16,    // 128 bits auth tag

        /**
         * Encrypt data with AES-256-GCM
         * @param {Uint8Array} plaintext - Data to encrypt
         * @param {Uint8Array} key - 32-byte key
         * @param {Uint8Array} [aad] - Additional authenticated data
         * @returns {Promise<{ciphertext: Uint8Array, nonce: Uint8Array}>}
         */
        encrypt: async function(plaintext, key, aad) {
            const nonce = Utils.randomBytes(this.NONCE_LENGTH);
            
            const cryptoKey = await crypto.subtle.importKey(
                'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
            );

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: nonce, additionalData: aad || new Uint8Array(0) },
                cryptoKey,
                plaintext
            );

            return {
                ciphertext: new Uint8Array(encrypted),
                nonce: nonce
            };
        },

        /**
         * Decrypt data with AES-256-GCM
         * @param {Uint8Array} ciphertext - Encrypted data (includes auth tag)
         * @param {Uint8Array} nonce - 12-byte nonce
         * @param {Uint8Array} key - 32-byte key
         * @param {Uint8Array} [aad] - Additional authenticated data
         * @returns {Promise<Uint8Array>}
         */
        decrypt: async function(ciphertext, nonce, key, aad) {
            const cryptoKey = await crypto.subtle.importKey(
                'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
            );

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce, additionalData: aad || new Uint8Array(0) },
                cryptoKey,
                ciphertext
            );

            return new Uint8Array(decrypted);
        },

        /**
         * Encrypt to base64 string (for easy transport)
         */
        encryptToBase64: async function(plaintext, key, aad) {
            const result = await this.encrypt(plaintext, key, aad);
            // Format: nonce (12 bytes) + ciphertext
            const combined = Utils.concat(result.nonce, result.ciphertext);
            return Utils.toBase64(combined);
        },

        /**
         * Decrypt from base64 string
         */
        decryptFromBase64: async function(base64, key, aad) {
            const combined = Utils.fromBase64(base64);
            const nonce = combined.slice(0, this.NONCE_LENGTH);
            const ciphertext = combined.slice(this.NONCE_LENGTH);
            return this.decrypt(ciphertext, nonce, key, aad);
        }
    };

    // ============================================================================
    // SECTION 4: HKDF Key Derivation (using Web Crypto API)
    // ============================================================================

    const HKDF = {
        /**
         * Derive key using HKDF-SHA256
         * @param {Uint8Array} inputKeyMaterial - Input key material
         * @param {Uint8Array} salt - Salt (optional, use empty if not available)
         * @param {Uint8Array} info - Context info
         * @param {number} length - Output length in bytes
         * @returns {Promise<Uint8Array>}
         */
        derive: async function(inputKeyMaterial, salt, info, length) {
            const baseKey = await crypto.subtle.importKey(
                'raw', inputKeyMaterial, 'HKDF', false, ['deriveBits']
            );

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: 'HKDF',
                    hash: 'SHA-256',
                    salt: salt || new Uint8Array(32),
                    info: info || new Uint8Array(0)
                },
                baseKey,
                length * 8
            );

            return new Uint8Array(derivedBits);
        },

        /**
         * Derive 32-byte key (most common case)
         */
        deriveKey: async function(ikm, salt, info) {
            return this.derive(ikm, salt, info, 32);
        },

        /**
         * Derive root key and chain key for Double Ratchet
         * @returns {Promise<{rootKey: Uint8Array, chainKey: Uint8Array}>}
         */
        deriveRootAndChainKey: async function(rootKey, dhOutput) {
            const input = Utils.concat(rootKey, dhOutput);
            const derived = await this.derive(input, null, Utils.stringToBytes('DoubleRatchet'), 64);
            return {
                rootKey: derived.slice(0, 32),
                chainKey: derived.slice(32, 64)
            };
        }
    };

    // ============================================================================
    // SECTION 5: HMAC-SHA256
    // ============================================================================

    const HMAC = {
        /**
         * Compute HMAC-SHA256
         * @param {Uint8Array} key - HMAC key
         * @param {Uint8Array} data - Data to authenticate
         * @returns {Promise<Uint8Array>}
         */
        compute: async function(key, data) {
            const cryptoKey = await crypto.subtle.importKey(
                'raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
            );
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
            return new Uint8Array(signature);
        }
    };

    // ============================================================================
    // SECTION 6: X3DH Protocol (Extended Triple Diffie-Hellman)
    // ============================================================================

    const X3DH = {
        /**
         * Generate identity key pair (long-term)
         * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
         */
        generateIdentityKeyPair: function() {
            return nacl.box.keyPair();
        },

        /**
         * Generate signed pre-key with Ed25519 signature
         * @param {number} id - Pre-key ID
         * @param {Object} identityKeyPair - Identity key pair for signing
         * @returns {Promise<Object>}
         */
        generateSignedPreKey: async function(id, identitySigningKey) {
            const keyPair = nacl.box.keyPair();
            const signature = await nacl.sign.detached(keyPair.publicKey, identitySigningKey.secretKey);
            
            return {
                id: id,
                keyPair: keyPair,
                signature: signature,
                createdAt: Date.now()
            };
        },

        /**
         * Generate one-time pre-keys
         * @param {number} startId - Starting ID
         * @param {number} count - Number of keys to generate
         * @returns {Array<Object>}
         */
        generateOneTimePreKeys: function(startId, count) {
            const keys = [];
            for (let i = 0; i < count; i++) {
                keys.push({
                    id: startId + i,
                    keyPair: nacl.box.keyPair()
                });
            }
            return keys;
        },

        /**
         * Initiate X3DH / PQXDH session (Alice's side)
         * Computes shared secret from recipient's key bundle.
         * v3.11.0: If recipient has pq_kem_public_key, performs hybrid PQXDH
         * (X25519 + ML-KEM-768) for quantum-resistant key agreement.
         * 
         * @param {Object} ourIdentity - Our identity key pair
         * @param {Object} theirBundle - Recipient's public key bundle
         * @returns {Promise<Object>} - {sharedSecret, ephemeralPublic, usedOneTimePreKeyId, pqKemCiphertext?}
         */
        initiateSession: async function(ourIdentity, theirBundle, peerId) {
            // Generate ephemeral key pair
            const ephemeralKeyPair = nacl.box.keyPair();
            
            // Parse their public keys
            const theirIdentityKey = Utils.fromBase64(theirBundle.identity_key);
            const theirSignedPreKey = Utils.fromBase64(theirBundle.signed_prekey);
            
            console.log('[X3DH-INIT] Starting session initiation');
            console.log('[X3DH-INIT] Our IK pub:', Utils.toBase64(ourIdentity.publicKey).slice(0,16) + '...');
            console.log('[X3DH-INIT] Their IK:', theirBundle.identity_key.slice(0,16) + '...');
            console.log('[X3DH-INIT] Their SPK:', theirBundle.signed_prekey.slice(0,16) + '...');
            console.log('[X3DH-INIT] Ephemeral pub:', Utils.toBase64(ephemeralKeyPair.publicKey).slice(0,16) + '...');
            
            // v3.11.8: Verify signed prekey signature before using it
            // This prevents a malicious server from substituting its own SPK
            if (theirBundle.signing_public_key && theirBundle.signed_prekey_signature) {
                const signingKey = Utils.fromBase64(theirBundle.signing_public_key);
                const signature = Utils.fromBase64(theirBundle.signed_prekey_signature);
                const verified = await nacl.sign.detached_verify(theirSignedPreKey, signature, signingKey);
                if (!verified) {
                    console.error('[X3DH-INIT] CRITICAL: Signed prekey signature verification FAILED!');
                    throw new Error('SPK signature verification failed — possible key tampering');
                }
                console.log('[X3DH-INIT] SPK signature verified ✓');
            } else {
                // КАО#261 (#5): fail-CLOSED. A bundle without a signing key + SPK signature cannot be
                // authenticated, and silently accepting it lets a malicious server substitute its own
                // signed prekey (MITM) — defeating the whole point of the SPK signature. Current servers
                // always include signing_public_key (v3.11.8+), so reject the unauthenticated bundle.
                console.error('[X3DH-INIT] Bundle missing signing_public_key/signature — refusing unauthenticated SPK');
                throw new Error('Key bundle is not signed (missing signing key) — cannot establish a secure session');
            }
            
            // DH1: IK_A <-> SPK_B
            const dh1 = nacl.box.sharedKey(theirSignedPreKey, ourIdentity.secretKey);
            
            // DH2: EK_A <-> IK_B
            const dh2 = nacl.box.sharedKey(theirIdentityKey, ephemeralKeyPair.secretKey);
            
            // DH3: EK_A <-> SPK_B
            const dh3 = nacl.box.sharedKey(theirSignedPreKey, ephemeralKeyPair.secretKey);
            
            // Combine DH outputs
            let dhConcat = Utils.concat(dh1, dh2, dh3);
            let usedOtpId = null;
            
            // DH4: EK_A <-> OPK_B (if available)
            if (theirBundle.one_time_prekey) {
                const theirOtpKey = Utils.fromBase64(theirBundle.one_time_prekey.key);
                const dh4 = nacl.box.sharedKey(theirOtpKey, ephemeralKeyPair.secretKey);
                dhConcat = Utils.concat(dhConcat, dh4);
                usedOtpId = theirBundle.one_time_prekey.id;
                console.log('[X3DH-INIT] Using OTP id:', usedOtpId);
            } else {
                console.log('[X3DH-INIT] No OTP in bundle');
            }
            
            // v3.11.0: PQ-KEM encapsulation (ML-KEM-768) if recipient supports it
            let pqKemCiphertext = null;
            let isPQXDH = false;
            
            // КАО#303: pq_kem_public_key is NOT covered by any signature (unlike the SPK), so a malicious
            // server could simply STRIP it and silently drop both sides back to classic X3DH — losing
            // post-quantum protection with no warning ("harvest now, decrypt later"). Signing it would be
            // a bundle-format change, so instead pin PQ support per contact on first sight (TOFU): once a
            // peer has published a PQ key, a later bundle without one is treated as a downgrade attack.
            // A peer that never had PQ still works exactly as before (no regression for legacy accounts).
            const _pqPeerId = peerId || theirBundle.user_id || null;
            const _pqPinKey = _pqPeerId ? ('vibe_pq_seen_' + _pqPeerId) : null;
            let _pqWasSeen = false;
            try { _pqWasSeen = !!(_pqPinKey && localStorage.getItem(_pqPinKey) === '1'); } catch (e) {}

            // КАО#309: only a key we can actually USE counts as "this peer supports PQ". The first version
            // pinned on the mere PRESENCE of the (unsigned, unvalidated) field and pinned BEFORE using it,
            // so a hostile server could send one junk byte: the pin was set, encapsulate() then threw, and
            // from that moment every future bundle — including honest ones — was rejected as a downgrade,
            // permanently locking the contact out with no way to clear the pin.
            let _pqOffered = false;
            if (theirBundle.pq_kem_public_key) {
                try {
                    const expected = (typeof PQKEM !== 'undefined' && PQKEM.PUBLIC_KEY_SIZE) || 1184;
                    _pqOffered = Utils.fromBase64(theirBundle.pq_kem_public_key).length === expected;
                    if (!_pqOffered) console.warn('[PQXDH-INIT] PQ key present but wrong size — ignoring it');
                } catch (e) {
                    console.warn('[PQXDH-INIT] PQ key present but undecodable — ignoring it');
                }
            }
            if (!_pqOffered && _pqWasSeen) {
                console.error('[PQXDH-INIT] CRITICAL: bundle for', _pqPeerId, 'lost its usable PQ key — downgrade refused');
                throw new Error('Post-quantum key missing for a contact that previously had one — possible downgrade attack');
            }

            if (_pqOffered && typeof PQKEM !== 'undefined' && PQKEM.isAvailable()) {
                console.log('[PQXDH-INIT] Performing ML-KEM-768 encapsulation');
                const theirPqKey = Utils.fromBase64(theirBundle.pq_kem_public_key);
                const kemResult = PQKEM.encapsulate(theirPqKey);

                // Append PQ shared secret to DH concatenation
                dhConcat = Utils.concat(dhConcat, kemResult.sharedSecret);
                pqKemCiphertext = kemResult.ciphertext;
                isPQXDH = true;

                // КАО#309: pin only now — the peer demonstrably has a working PQ key.
                try { if (_pqPinKey) localStorage.setItem(_pqPinKey, '1'); } catch (e) {}

                console.log('[PQXDH-INIT] KEM ciphertext:', pqKemCiphertext.length, 'bytes');
                console.log('[PQXDH-INIT] Hybrid key material:', dhConcat.length, 'bytes');
            } else {
                console.log('[X3DH-INIT] Classic X3DH (no usable PQ key in bundle)');
            }
            
            // Derive shared secret with HKDF
            const hkdfInfo = isPQXDH ? 'PQXDH' : 'X3DH';
            const sharedSecret = await HKDF.deriveKey(
                dhConcat,
                null,
                Utils.stringToBytes(hkdfInfo)
            );
            
            console.log('[' + (isPQXDH ? 'PQXDH' : 'X3DH') + '-INIT] Shared secret:', Utils.toBase64(sharedSecret).slice(0,16) + '...');
            
            return {
                sharedSecret: sharedSecret,
                ephemeralKeyPair: ephemeralKeyPair,  // Return full key pair for Double Ratchet
                usedOneTimePreKeyId: usedOtpId,
                pqKemCiphertext: pqKemCiphertext,  // v3.11.0: null for classic X3DH
                isPQXDH: isPQXDH                    // v3.11.0: protocol indicator
            };
        },

        /**
         * Process incoming X3DH / PQXDH session (Bob's side)
         * v3.11.0: If pqKemCiphertext is provided, performs ML-KEM-768 decapsulation
         * for hybrid quantum-resistant key agreement.
         * 
         * @param {Object} ourIdentity - Our identity key pair
         * @param {Object} ourSignedPreKey - Our signed pre-key
         * @param {Object|null} ourOneTimePreKey - Our one-time pre-key (if used)
         * @param {Uint8Array} theirIdentityKey - Their identity public key
         * @param {Uint8Array} theirEphemeralKey - Their ephemeral public key
         * @param {Uint8Array|null} pqKemCiphertext - v3.11.0: PQ KEM ciphertext (if PQXDH)
         * @param {Object|null} ourPqKemKeyPair - v3.11.0: Our PQ KEM key pair
         * @returns {Promise<Uint8Array>} - Shared secret
         */
        processSession: async function(ourIdentity, ourSignedPreKey, ourOneTimePreKey, theirIdentityKey, theirEphemeralKey, pqKemCiphertext, ourPqKemKeyPair) {
            console.log('[X3DH-PROC] Processing incoming session');
            console.log('[X3DH-PROC] Our IK pub:', Utils.toBase64(ourIdentity.publicKey).slice(0,16) + '...');
            console.log('[X3DH-PROC] Our SPK pub:', Utils.toBase64(ourSignedPreKey.keyPair.publicKey).slice(0,16) + '...');
            console.log('[X3DH-PROC] Their IK:', Utils.toBase64(theirIdentityKey).slice(0,16) + '...');
            console.log('[X3DH-PROC] Their EK:', Utils.toBase64(theirEphemeralKey).slice(0,16) + '...');
            
            // DH1: SPK_B <-> IK_A
            const dh1 = nacl.box.sharedKey(theirIdentityKey, ourSignedPreKey.keyPair.secretKey);
            
            // DH2: IK_B <-> EK_A
            const dh2 = nacl.box.sharedKey(theirEphemeralKey, ourIdentity.secretKey);
            
            // DH3: SPK_B <-> EK_A
            const dh3 = nacl.box.sharedKey(theirEphemeralKey, ourSignedPreKey.keyPair.secretKey);
            
            // Combine DH outputs
            let dhConcat = Utils.concat(dh1, dh2, dh3);
            
            // DH4 if one-time pre-key was used
            if (ourOneTimePreKey) {
                const dh4 = nacl.box.sharedKey(theirEphemeralKey, ourOneTimePreKey.keyPair.secretKey);
                dhConcat = Utils.concat(dhConcat, dh4);
                console.log('[X3DH-PROC] Using our OTP');
            } else {
                console.log('[X3DH-PROC] No OTP used');
            }
            
            // v3.11.0: PQ-KEM decapsulation (ML-KEM-768) if ciphertext provided
            let isPQXDH = false;
            
            if (pqKemCiphertext && ourPqKemKeyPair && typeof PQKEM !== 'undefined' && PQKEM.isAvailable()) {
                console.log('[PQXDH-PROC] Performing ML-KEM-768 decapsulation');
                const pqSharedSecret = PQKEM.decapsulate(pqKemCiphertext, ourPqKemKeyPair.secretKey);
                dhConcat = Utils.concat(dhConcat, pqSharedSecret);
                isPQXDH = true;
                console.log('[PQXDH-PROC] Hybrid key material:', dhConcat.length, 'bytes');
            } else if (pqKemCiphertext) {
                console.error('[PQXDH-PROC] PQ ciphertext received but PQ-KEM unavailable or no key pair!');
                throw new Error('PQ-KEM decapsulation failed: missing key or library');
            }
            
            // Derive shared secret
            const hkdfInfo = isPQXDH ? 'PQXDH' : 'X3DH';
            const sharedSecret = await HKDF.deriveKey(
                dhConcat,
                null,
                Utils.stringToBytes(hkdfInfo)
            );
            
            console.log('[' + (isPQXDH ? 'PQXDH' : 'X3DH') + '-PROC] Shared secret:', Utils.toBase64(sharedSecret).slice(0,16) + '...');
            
            return sharedSecret;
        }
    };

    // ============================================================================
    // SECTION 7: Double Ratchet Algorithm
    // ============================================================================

    /**
     * Double Ratchet Session
     * Provides forward secrecy and break-in recovery
     */
    class DoubleRatchetSession {
        constructor() {
            // DH Ratchet state
            this.dhSendingKeyPair = null;
            this.dhReceivingKey = null;
            
            // Root key (updated with each DH ratchet)
            this.rootKey = null;
            
            // Symmetric chain keys
            this.sendingChainKey = null;
            this.receivingChainKey = null;
            
            // Message counters
            this.sendingMessageNumber = 0;
            this.receivingMessageNumber = 0;
            this.previousSendingChainLength = 0;
            
            // Skipped message keys for out-of-order delivery
            this.skippedKeys = new Map();  // "pubKey:msgNum" -> messageKey
            this.skippedKeyTimes = new Map();  // КАО#262 (#27): "pubKey:msgNum" -> created-at ms, for age pruning
            this.MAX_SKIP = 1000;
            this.SKIP_KEY_MAX_AGE = 7 * 24 * 60 * 60 * 1000;  // 7 days
        }

        /**
         * Initialize as sender (Alice - initiates conversation)
         * @param {Uint8Array} sharedSecret - X3DH shared secret
         * @param {Uint8Array} recipientSignedPreKey - Bob's signed prekey public
         * @param {Object} ephemeralKeyPair - Ephemeral key pair from X3DH (for first DH ratchet)
         */
        async initSender(sharedSecret, recipientSignedPreKey, ephemeralKeyPair) {
            console.log('[DR] initSender starting');
            console.log('[DR] sharedSecret:', Utils.toBase64(sharedSecret).slice(0,16) + '...');
            console.log('[DR] recipientSPK:', Utils.toBase64(recipientSignedPreKey).slice(0,16) + '...');
            console.log('[DR] ephemeral pub:', Utils.toBase64(ephemeralKeyPair.publicKey).slice(0,16) + '...');
            
            this.rootKey = sharedSecret;
            this.dhReceivingKey = recipientSignedPreKey;
            
            // Use ephemeral key pair from X3DH as first DH sending key
            // This ensures DH ratchet consistency with receiver
            this.dhSendingKeyPair = ephemeralKeyPair;
            
            // Perform initial DH ratchet
            await this._dhRatchetSend();
            
            console.log('[DR] initSender complete, sendingChainKey:', Utils.toBase64(this.sendingChainKey).slice(0,16) + '...');
        }

        /**
         * Initialize as receiver (Bob - receives first message)
         */
        async initReceiver(sharedSecret, ourSignedPreKeyPair) {
            console.log('[DR] initReceiver starting');
            console.log('[DR] sharedSecret:', Utils.toBase64(sharedSecret).slice(0,16) + '...');
            console.log('[DR] our SPK pub:', Utils.toBase64(ourSignedPreKeyPair.publicKey).slice(0,16) + '...');
            
            this.rootKey = sharedSecret;
            this.dhSendingKeyPair = ourSignedPreKeyPair;
            // No receiving key yet - will be set when first message arrives
        }

        /**
         * Encrypt a message
         * @param {Uint8Array} plaintext
         * @returns {Promise<Object>} - {header, ciphertext}
         */
        async encrypt(plaintext) {
            // Derive message key from sending chain
            const {chainKey, messageKey} = await this._ratchetChainKey(this.sendingChainKey);
            this.sendingChainKey = chainKey;
            
            // Create header
            const header = {
                dh: Utils.toBase64(this.dhSendingKeyPair.publicKey),
                pn: this.previousSendingChainLength,
                n: this.sendingMessageNumber
            };
            
            this.sendingMessageNumber++;
            
            // Encrypt with message key
            const headerBytes = Utils.stringToBytes(JSON.stringify(header));
            const encrypted = await AesGcm.encrypt(plaintext, messageKey, headerBytes);
            
            return {
                header: header,
                ciphertext: Utils.toBase64(encrypted.ciphertext),
                nonce: Utils.toBase64(encrypted.nonce)
            };
        }

        /**
         * Decrypt a message
         * IMPORTANT: This method is ATOMIC - session state is only updated on successful decryption
         * @param {Object} message - {header, ciphertext, nonce}
         * @returns {Promise<Uint8Array>}
         */
        async decrypt(message) {
            const header = message.header;
            const theirDhKey = Utils.fromBase64(header.dh);
            
            console.log('[DR] Decrypt - header.n:', header.n, 'header.pn:', header.pn);
            console.log('[DR] dhReceivingKey exists:', !!this.dhReceivingKey);
            console.log('[DR] receivingMessageNumber:', this.receivingMessageNumber);
            
            // Try skipped keys first (doesn't modify critical state)
            const skipId = `${header.dh}:${header.n}`;
            if (this.skippedKeys.has(skipId)) {
                console.log('[DR] Using skipped key');
                const messageKey = this.skippedKeys.get(skipId);
                // Try decrypt BEFORE modifying state
                const plaintext = await this._decryptWithKey(message, messageKey);
                // Only delete key after successful decryption
                this.skippedKeys.delete(skipId);
                this.skippedKeyTimes.delete(skipId);  // КАО#262 (#27)
                return plaintext;
            }
            
            // Save current state for rollback on failure
            const savedState = {
                dhSendingKeyPair: this.dhSendingKeyPair,
                dhReceivingKey: this.dhReceivingKey,
                rootKey: this.rootKey,
                sendingChainKey: this.sendingChainKey,
                receivingChainKey: this.receivingChainKey,
                sendingMessageNumber: this.sendingMessageNumber,
                receivingMessageNumber: this.receivingMessageNumber,
                previousSendingChainLength: this.previousSendingChainLength,
                skippedKeys: new Map(this.skippedKeys),
                skippedKeyTimes: new Map(this.skippedKeyTimes)  // КАО#262 (#27)
            };
            
            try {
                // Check if DH ratchet is needed
                if (!this.dhReceivingKey || !Utils.equal(theirDhKey, this.dhReceivingKey)) {
                    console.log('[DR] DH ratchet needed');
                    // Skip messages in previous receiving chain
                    await this._skipMessages(header.pn);
                    // Perform DH ratchet
                    await this._dhRatchetReceive(theirDhKey);
                    console.log('[DR] DH ratchet completed');
                }
                
                // Skip any messages before this one in current chain
                await this._skipMessages(header.n);
                
                // Derive message key
                console.log('[DR] Deriving message key, receivingChainKey exists:', !!this.receivingChainKey);
                const {chainKey, messageKey} = await this._ratchetChainKey(this.receivingChainKey);
                
                // Try decryption BEFORE updating chain state
                console.log('[DR] Attempting decryption...');
                const plaintext = await this._decryptWithKey(message, messageKey);
                
                // Decryption successful - now commit state changes
                this.receivingChainKey = chainKey;
                this.receivingMessageNumber++;
                console.log('[DR] Decryption successful, state committed');
                
                return plaintext;
                
            } catch (error) {
                // Decryption failed - rollback state
                console.log('[DR] Decryption failed, rolling back state:', error.message);
                this.dhSendingKeyPair = savedState.dhSendingKeyPair;
                this.dhReceivingKey = savedState.dhReceivingKey;
                this.rootKey = savedState.rootKey;
                this.sendingChainKey = savedState.sendingChainKey;
                this.receivingChainKey = savedState.receivingChainKey;
                this.sendingMessageNumber = savedState.sendingMessageNumber;
                this.receivingMessageNumber = savedState.receivingMessageNumber;
                this.previousSendingChainLength = savedState.previousSendingChainLength;
                this.skippedKeys = savedState.skippedKeys;
                this.skippedKeyTimes = savedState.skippedKeyTimes;  // КАО#262 (#27)

                throw error;
            }
        }

        /**
         * Decrypt with specific message key
         */
        async _decryptWithKey(message, messageKey) {
            const header = message.header;
            const headerBytes = Utils.stringToBytes(JSON.stringify(header));
            const ciphertext = Utils.fromBase64(message.ciphertext);
            const nonce = Utils.fromBase64(message.nonce);
            
            return AesGcm.decrypt(ciphertext, nonce, messageKey, headerBytes);
        }

        /**
         * Perform DH ratchet step (sending)
         */
        async _dhRatchetSend() {
            console.log('[DR] _dhRatchetSend');
            console.log('[DR] dhReceivingKey:', Utils.toBase64(this.dhReceivingKey).slice(0,16) + '...');
            console.log('[DR] dhSendingKeyPair pub:', Utils.toBase64(this.dhSendingKeyPair.publicKey).slice(0,16) + '...');
            console.log('[DR] rootKey before:', Utils.toBase64(this.rootKey).slice(0,16) + '...');
            
            const dhOutput = nacl.box.sharedKey(this.dhReceivingKey, this.dhSendingKeyPair.secretKey);
            console.log('[DR] dhOutput:', Utils.toBase64(dhOutput).slice(0,16) + '...');
            
            const {rootKey, chainKey} = await HKDF.deriveRootAndChainKey(this.rootKey, dhOutput);
            this.rootKey = rootKey;
            this.sendingChainKey = chainKey;
            this.sendingMessageNumber = 0;
            
            console.log('[DR] rootKey after:', Utils.toBase64(this.rootKey).slice(0,16) + '...');
            console.log('[DR] sendingChainKey:', Utils.toBase64(this.sendingChainKey).slice(0,16) + '...');
        }

        /**
         * Perform DH ratchet step (receiving)
         */
        async _dhRatchetReceive(theirDhKey) {
            console.log('[DR] _dhRatchetReceive');
            console.log('[DR] theirDhKey:', Utils.toBase64(theirDhKey).slice(0,16) + '...');
            console.log('[DR] our dhSendingKeyPair pub:', Utils.toBase64(this.dhSendingKeyPair.publicKey).slice(0,16) + '...');
            console.log('[DR] rootKey before:', Utils.toBase64(this.rootKey).slice(0,16) + '...');
            
            this.previousSendingChainLength = this.sendingMessageNumber;
            this.sendingMessageNumber = 0;
            this.receivingMessageNumber = 0;
            
            this.dhReceivingKey = theirDhKey;
            
            // DH with their new key
            let dhOutput = nacl.box.sharedKey(theirDhKey, this.dhSendingKeyPair.secretKey);
            console.log('[DR] dhOutput:', Utils.toBase64(dhOutput).slice(0,16) + '...');
            
            let derived = await HKDF.deriveRootAndChainKey(this.rootKey, dhOutput);
            this.rootKey = derived.rootKey;
            this.receivingChainKey = derived.chainKey;
            
            console.log('[DR] rootKey after:', Utils.toBase64(this.rootKey).slice(0,16) + '...');
            console.log('[DR] receivingChainKey:', Utils.toBase64(this.receivingChainKey).slice(0,16) + '...');
            
            // Generate new DH key pair for sending
            this.dhSendingKeyPair = nacl.box.keyPair();
            
            // DH ratchet for sending
            await this._dhRatchetSend();
        }

        /**
         * Ratchet chain key to get message key
         */
        async _ratchetChainKey(chainKey) {
            // Message key = HMAC(chain_key, 0x01)
            const messageKey = await HMAC.compute(chainKey, new Uint8Array([0x01]));
            // Next chain key = HMAC(chain_key, 0x02)
            const nextChainKey = await HMAC.compute(chainKey, new Uint8Array([0x02]));
            return {chainKey: nextChainKey, messageKey: messageKey};
        }

        /**
         * Skip messages for out-of-order delivery
         */
        async _skipMessages(until) {
            if (!this.receivingChainKey) return;
            
            if (until - this.receivingMessageNumber > this.MAX_SKIP) {
                throw new Error('Too many skipped messages');
            }
            
            while (this.receivingMessageNumber < until) {
                const {chainKey, messageKey} = await this._ratchetChainKey(this.receivingChainKey);
                this.receivingChainKey = chainKey;
                
                const skipId = `${Utils.toBase64(this.dhReceivingKey)}:${this.receivingMessageNumber}`;
                this.skippedKeys.set(skipId, messageKey);
                this.skippedKeyTimes.set(skipId, Date.now());  // КАО#262 (#27): stamp for age pruning
                this.receivingMessageNumber++;
            }

            // Clean old skipped keys
            this._cleanSkippedKeys();
        }

        /**
         * Clean expired skipped keys
         */
        _cleanSkippedKeys() {
            // КАО#262 (#27): enforce SKIP_KEY_MAX_AGE (was defined but never applied) — forward secrecy:
            // a stale skipped message key shouldn't linger for weeks letting old captured ciphertext decrypt.
            const now = Date.now();
            for (const [skipId, ts] of this.skippedKeyTimes) {
                if (now - ts > this.SKIP_KEY_MAX_AGE) {
                    this.skippedKeys.delete(skipId);
                    this.skippedKeyTimes.delete(skipId);
                }
            }
            // Also bound total size (oldest-first eviction)
            if (this.skippedKeys.size > this.MAX_SKIP) {
                const toDelete = this.skippedKeys.size - this.MAX_SKIP;
                const keys = Array.from(this.skippedKeys.keys());
                for (let i = 0; i < toDelete; i++) {
                    this.skippedKeys.delete(keys[i]);
                    this.skippedKeyTimes.delete(keys[i]);
                }
            }
        }

        /**
         * Serialize session state for storage
         */
        toJSON() {
            return {
                dhSendingPublicKey: this.dhSendingKeyPair ? Utils.toBase64(this.dhSendingKeyPair.publicKey) : null,
                dhSendingSecretKey: this.dhSendingKeyPair ? Utils.toBase64(this.dhSendingKeyPair.secretKey) : null,
                dhReceivingKey: this.dhReceivingKey ? Utils.toBase64(this.dhReceivingKey) : null,
                rootKey: this.rootKey ? Utils.toBase64(this.rootKey) : null,
                sendingChainKey: this.sendingChainKey ? Utils.toBase64(this.sendingChainKey) : null,
                receivingChainKey: this.receivingChainKey ? Utils.toBase64(this.receivingChainKey) : null,
                sendingMessageNumber: this.sendingMessageNumber,
                receivingMessageNumber: this.receivingMessageNumber,
                previousSendingChainLength: this.previousSendingChainLength,
                skippedKeys: Object.fromEntries(
                    Array.from(this.skippedKeys.entries()).map(([k, v]) => [k, Utils.toBase64(v)])
                ),
                skippedKeyTimes: Object.fromEntries(this.skippedKeyTimes),  // КАО#262 (#27)
                protocolVersion: 2  // Version 2 = fixed ephemeral key handling
            };
        }

        /**
         * Restore session from storage
         */
        static fromJSON(data) {
            console.log('[DR] fromJSON - protocolVersion:', data.protocolVersion);
            
            // Check protocol version - reject old sessions
            if (!data.protocolVersion || data.protocolVersion < 2) {
                console.log('[DR] Rejecting old session (version', data.protocolVersion || 1, ')');
                return null;  // Return null to force session recreation
            }
            
            const session = new DoubleRatchetSession();
            
            if (data.dhSendingPublicKey && data.dhSendingSecretKey) {
                session.dhSendingKeyPair = {
                    publicKey: Utils.fromBase64(data.dhSendingPublicKey),
                    secretKey: Utils.fromBase64(data.dhSendingSecretKey)
                };
                console.log('[DR] Loaded dhSendingKeyPair pub:', data.dhSendingPublicKey.slice(0,16) + '...');
            }
            
            if (data.dhReceivingKey) {
                session.dhReceivingKey = Utils.fromBase64(data.dhReceivingKey);
                console.log('[DR] Loaded dhReceivingKey:', data.dhReceivingKey.slice(0,16) + '...');
            }
            
            if (data.rootKey) {
                session.rootKey = Utils.fromBase64(data.rootKey);
                console.log('[DR] Loaded rootKey:', data.rootKey.slice(0,16) + '...');
            }
            
            if (data.sendingChainKey) {
                session.sendingChainKey = Utils.fromBase64(data.sendingChainKey);
                console.log('[DR] Loaded sendingChainKey:', data.sendingChainKey.slice(0,16) + '...');
            }
            
            if (data.receivingChainKey) {
                session.receivingChainKey = Utils.fromBase64(data.receivingChainKey);
                console.log('[DR] Loaded receivingChainKey:', data.receivingChainKey.slice(0,16) + '...');
            }
            
            session.sendingMessageNumber = data.sendingMessageNumber || 0;
            session.receivingMessageNumber = data.receivingMessageNumber || 0;
            session.previousSendingChainLength = data.previousSendingChainLength || 0;
            console.log('[DR] Loaded msgNumbers - send:', session.sendingMessageNumber, 'recv:', session.receivingMessageNumber);
            
            if (data.skippedKeys) {
                for (const [k, v] of Object.entries(data.skippedKeys)) {
                    session.skippedKeys.set(k, Utils.fromBase64(v));
                }
            }
            // КАО#262 (#27): restore skipped-key timestamps; default missing ones to "now" so legacy
            // sessions still get age-pruned from this point forward rather than living forever.
            if (data.skippedKeyTimes) {
                for (const [k, v] of Object.entries(data.skippedKeyTimes)) {
                    session.skippedKeyTimes.set(k, v);
                }
            }
            const _nowTs = Date.now();
            for (const k of session.skippedKeys.keys()) {
                if (!session.skippedKeyTimes.has(k)) session.skippedKeyTimes.set(k, _nowTs);
            }

            return session;
        }
    }

    // ============================================================================
    // SECTION 8: Sender Keys (for Group Messaging)
    // ============================================================================

    /**
     * Sender Key for group messaging
     * Each participant has their own sender key that they distribute to group members
     */
    class SenderKeyState {
        constructor() {
            this.chainKey = null;
            this.signingKeyPair = null;
            this.iteration = 0;
        }

        /**
         * Generate new sender key state
         */
        static async generate() {
            const state = new SenderKeyState();
            state.chainKey = Utils.randomBytes(32);
            state.signingKeyPair = await nacl.sign.keyPair();
            state.iteration = 0;
            return state;
        }

        /**
         * Get message key and advance chain
         */
        async getMessageKey() {
            const messageKey = await HMAC.compute(this.chainKey, new Uint8Array([0x01]));
            this.chainKey = await HMAC.compute(this.chainKey, new Uint8Array([0x02]));
            this.iteration++;
            return messageKey;
        }

        /**
         * Export for distribution (public parts only)
         */
        toDistribution() {
            return {
                chainKey: Utils.toBase64(this.chainKey),
                signingPublicKey: Utils.toBase64(this.signingKeyPair.publicKey),
                iteration: this.iteration
            };
        }

        /**
         * Serialize for storage
         */
        toJSON() {
            return {
                chainKey: Utils.toBase64(this.chainKey),
                signingPublicKey: Utils.toBase64(this.signingKeyPair.publicKey),
                signingSecretKey: Utils.toBase64(this.signingKeyPair.secretKey),
                iteration: this.iteration
            };
        }

        static fromJSON(data) {
            const state = new SenderKeyState();
            state.chainKey = Utils.fromBase64(data.chainKey);
            state.signingKeyPair = {
                publicKey: Utils.fromBase64(data.signingPublicKey),
                secretKey: Utils.fromBase64(data.signingSecretKey)
            };
            state.iteration = data.iteration;
            return state;
        }
    }

    /**
     * Received sender key from group member
     */
    class ReceivedSenderKey {
        constructor(senderId, chainKey, signingPublicKey, iteration) {
            this.senderId = senderId;
            this.chainKey = chainKey;
            this.signingPublicKey = signingPublicKey;
            this.iteration = iteration;
            this.skippedKeys = {};  // КАО#190: iteration -> base64 messageKey, for out-of-order delivery
            // КАО#332: mirror the 1:1 ratchet's КАО#262 hygiene. Group skipped keys only ever shrank when
            // a key was actually CONSUMED, so keys for messages that never arrive (a lossy or hostile
            // server dropping every other message) accumulated forever, were persisted to IndexedDB, and
            // once 2000 piled up the budget hit zero and NO further out-of-order group message could be
            // recovered at all. Stamp each stashed key so it can be aged out and evicted oldest-first.
            this.skippedKeyTimes = {};        // iteration -> created-at ms
            this.MAX_SKIPPED = 2000;
            this.SKIP_KEY_MAX_AGE = 7 * 24 * 60 * 60 * 1000;  // 7 days, same as the 1:1 session
        }

        /** КАО#332: drop expired skipped keys and cap the store, oldest first. */
        pruneSkippedKeys(now) {
            if (!this.skippedKeys) this.skippedKeys = {};
            if (!this.skippedKeyTimes) this.skippedKeyTimes = {};
            const cutoff = (now || Date.now()) - this.SKIP_KEY_MAX_AGE;
            for (const iter of Object.keys(this.skippedKeys)) {
                const ts = this.skippedKeyTimes[iter];
                if (ts === undefined) { this.skippedKeyTimes[iter] = now || Date.now(); continue; }
                if (ts < cutoff) { delete this.skippedKeys[iter]; delete this.skippedKeyTimes[iter]; }
            }
            let iters = Object.keys(this.skippedKeys);
            if (iters.length > this.MAX_SKIPPED) {
                iters.sort((a, b) => (this.skippedKeyTimes[a] || 0) - (this.skippedKeyTimes[b] || 0));
                for (const iter of iters.slice(0, iters.length - this.MAX_SKIPPED)) {
                    delete this.skippedKeys[iter];
                    delete this.skippedKeyTimes[iter];
                }
            }
        }

        /**
         * Advance chain to target iteration
         */
        async advanceToIteration(targetIteration) {
            while (this.iteration < targetIteration) {
                this.chainKey = await HMAC.compute(this.chainKey, new Uint8Array([0x02]));
                this.iteration++;
            }
        }

        /**
         * Derive the message key for an iteration WITHOUT mutating this key's state.
         *
         * КАО#306 (supersedes the КАО#289 snapshot/rollback): the previous version advanced the ratchet
         * up-front and undid it in a catch. That left a real window — AES-GCM decryption spans several
         * event-loop turns, and any concurrent group operation (processGroupKeyDistribution /
         * encryptGroupMessage both call saveGroupSession synchronously) could serialise the ADVANCED
         * state into IndexedDB before the rollback ran, permanently poisoning the chain on disk.
         * Now nothing is mutated until the caller has actually authenticated the message: we return the
         * key plus a commit() that applies the new state, mirroring the 1:1 DoubleRatchetSession.
         * Returns {messageKey, commit}.
         */
        async prepareMessageKeyForIteration(iteration) {
            if (!this.skippedKeys) this.skippedKeys = {};

            // КАО#307: `iteration` comes straight off the wire and is NOT covered by the signature, so it
            // must be validated before any arithmetic. A non-integer (e.g. the string "5") made every
            // comparison below silently false-y: `"5" < this.iteration` is false, `"5" - 0 > MAX` is false,
            // and `currentIter < "5"` terminated at once, so a bogus key was derived and the chain was
            // advanced to `"5" + 1 === "51"` — corrupting state in a way no rollback could describe.
            if (!Number.isInteger(iteration) || iteration < 0) {
                throw new Error('Invalid group message iteration: ' + JSON.stringify(iteration));
            }

            // КАО#190 (out-of-order): serve a previously-stored key for an older iteration
            if (iteration < this.iteration) {
                const sk = this.skippedKeys[iteration];
                if (!sk) {
                    throw new Error('Cannot go back in chain (no skipped key for iteration ' + iteration + ')');
                }
                const messageKey = Utils.fromBase64(sk);
                // the skipped key is only consumed once the message actually authenticates
                return { messageKey, commit: () => {
                    delete this.skippedKeys[iteration];
                    if (this.skippedKeyTimes) delete this.skippedKeyTimes[iteration];  // КАО#332
                } };
            }

            // КАО#260 (#4): bound the forward chain-advance. `iteration` comes from the (attacker-
            // controllable) message header; a forged huge value would otherwise spin the HMAC loop
            // billions of times and hang the recipient (CPU DoS). A legitimate out-of-order gap is small.
            const MAX_FORWARD_SKIP = 2000;
            if (iteration - this.iteration > MAX_FORWARD_SKIP) {
                throw new Error('Group message iteration too far ahead (' + iteration + ' > ' + this.iteration + ' + ' + MAX_FORWARD_SKIP + ')');
            }

            // Clone chain key — all work happens on locals.
            let chainKey = new Uint8Array(this.chainKey);
            let currentIter = this.iteration;

            // Advance to target; КАО#190: stash message keys for skipped iterations so out-of-order
            // (or briefly-delayed) group messages still decrypt later. Bounded to avoid unbounded growth.
            const pendingSkipped = {};
            this.pruneSkippedKeys(Date.now());  // КАО#332: age out before measuring the budget
            let budget = this.MAX_SKIPPED - Object.keys(this.skippedKeys).length;
            while (currentIter < iteration) {
                if (budget > 0) {
                    pendingSkipped[currentIter] = Utils.toBase64(await HMAC.compute(chainKey, new Uint8Array([0x01])));
                    budget--;
                }
                chainKey = await HMAC.compute(chainKey, new Uint8Array([0x02]));
                currentIter++;
            }

            const messageKey = await HMAC.compute(chainKey, new Uint8Array([0x01]));
            const nextChainKey = await HMAC.compute(chainKey, new Uint8Array([0x02]));
            const nextIteration = iteration + 1;

            return {
                messageKey,
                commit: () => {
                    const now = Date.now();
                    Object.assign(this.skippedKeys, pendingSkipped);
                    if (!this.skippedKeyTimes) this.skippedKeyTimes = {};
                    for (const iter of Object.keys(pendingSkipped)) this.skippedKeyTimes[iter] = now;  // КАО#332
                    this.chainKey = nextChainKey;
                    this.iteration = nextIteration;
                    this.pruneSkippedKeys(now);
                }
            };
        }

        toJSON() {
            return {
                senderId: this.senderId,
                chainKey: Utils.toBase64(this.chainKey),
                signingPublicKey: Utils.toBase64(this.signingPublicKey),
                iteration: this.iteration,
                skippedKeys: this.skippedKeys || {},  // КАО#190: persist out-of-order keys
                skippedKeyTimes: this.skippedKeyTimes || {}  // КАО#332: keep the age stamps across reloads
            };
        }

        static fromJSON(data) {
            const k = new ReceivedSenderKey(
                data.senderId,
                Utils.fromBase64(data.chainKey),
                Utils.fromBase64(data.signingPublicKey),
                data.iteration
            );
            k.skippedKeys = data.skippedKeys || {};  // КАО#190
            // КАО#332: sessions written before this change have no stamps — treat them as "seen now" so a
            // reload cannot wipe still-valid skipped keys, then let normal ageing take over.
            k.skippedKeyTimes = data.skippedKeyTimes || {};
            const now = Date.now();
            for (const iter of Object.keys(k.skippedKeys)) {
                if (k.skippedKeyTimes[iter] === undefined) k.skippedKeyTimes[iter] = now;
            }
            return k;
        }
    }

    /**
     * Group Session Manager
     * Manages sender keys for a group chat
     */
    class GroupSession {
        constructor(groupId) {
            this.groupId = groupId;
            this.mySenderKey = null;  // SenderKeyState
            this.memberKeys = new Map();  // senderId -> ReceivedSenderKey
        }

        /**
         * Initialize our sender key for this group
         */
        async initialize() {
            this.mySenderKey = await SenderKeyState.generate();
            return this.mySenderKey.toDistribution();
        }

        /**
         * Add member's sender key
         */
        addMemberKey(senderId, distribution) {
            const existingKey = this.memberKeys.get(senderId);

            // КАО#308: decide by the SIGNING KEY, not by the iteration counter.
            // The old `existingKey.iteration > distribution.iteration` guard conflated two very different
            // situations:
            //   • a member RESET their E2EE keys → they publish a genuinely new sender key that restarts at
            //     iteration 0. The guard rejected it, so every message they sent afterwards failed forever
            //     ("no sender key"/bad key) with no way to recover short of clearing local storage.
            //   • a re-broadcast of the SAME key (the usual case) → rebuilding from the distribution threw
            //     away the live chain state, including the КАО#190 skippedKeys needed for out-of-order
            //     delivery, and fast-forwarded `iteration` past messages still in flight.
            if (existingKey) {
                const sameSender = Utils.toBase64(existingKey.signingPublicKey) === distribution.signingPublicKey;
                if (sameSender) {
                    // КАО#333: keeping the live state is right for an ordinary re-announce, but КАО#308
                    // made it UNCONDITIONAL and so removed the only way to resynchronise a chain that has
                    // drifted out of reach: if our stored iteration sits ahead of the sender's (they
                    // reinstalled and restarted the chain with the same key) every message is "cannot go
                    // back", and if they are more than MAX_FORWARD_SKIP ahead the advance is refused —
                    // both permanent, with no recovery path. Rebuild only in those unreachable cases.
                    const announced = distribution.iteration;
                    // КАО#346 (reverts half of КАО#333): resync FORWARD only. Allowing a rebuild when the
                    // announced iteration is BEHIND ours was exploitable: every group message carries the
                    // sender's authentic distribution for its own iteration, so a hostile server needs no
                    // forgery — just delivery reordering. Replaying an older genuine distribution rewound
                    // the receive chain and wiped skippedKeys, after which the server could re-send old
                    // ciphertexts under fresh message ids and they would verify, decrypt and render as new
                    // messages (including ones already deleted or expired). A backward move is
                    // indistinguishable from that replay, so it must never rewind state; a genuine
                    // reinstall publishes a NEW signing key and is handled by the КАО#308 branch below.
                    const unreachable = Number.isInteger(announced) && announced >= 0 &&
                        (announced - existingKey.iteration > 2000);
                    if (!unreachable) {
                        console.log('[GroupSession] Same sender key re-announced for', senderId, '— keeping live state');
                        return;
                    }
                    console.warn('[GroupSession] Sender chain for', senderId, 'is unreachable (ours',
                        existingKey.iteration, 'vs announced', announced, ') — resyncing from distribution');
                }
                console.log('[GroupSession] New signing key for', senderId, '— member reset their keys, replacing');
            }

            const key = new ReceivedSenderKey(
                senderId,
                Utils.fromBase64(distribution.chainKey),
                Utils.fromBase64(distribution.signingPublicKey),
                distribution.iteration
            );
            this.memberKeys.set(senderId, key);
        }

        /**
         * Encrypt message for group
         */
        async encrypt(plaintext) {
            if (!this.mySenderKey) {
                throw new Error('Sender key not initialized');
            }
            
            const messageKey = await this.mySenderKey.getMessageKey();
            const encrypted = await AesGcm.encrypt(plaintext, messageKey);

            // КАО#140 (SER#16): sign ciphertext so recipients can authenticate the sender (Ed25519)
            const signed = Utils.concat(encrypted.nonce, encrypted.ciphertext);
            const signature = await nacl.sign.detached(signed, this.mySenderKey.signingKeyPair.secretKey);  // КАО#140: nacl.sign.detached is async here

            return {
                iteration: this.mySenderKey.iteration - 1,  // Key was advanced after use
                ciphertext: Utils.toBase64(encrypted.ciphertext),
                nonce: Utils.toBase64(encrypted.nonce),
                signature: Utils.toBase64(signature)  // КАО#140
            };
        }

        /**
         * Decrypt message from group member.
         *
         * КАО#331: SERIALISED. prepare()→AES-GCM→commit() spans several event-loop turns, and nothing
         * upstream awaits us — the WS handler fires handleNewMessage() unawaited and
         * flushPendingGroupMessages() replays a whole buffer in an unawaited loop — so two decrypts for
         * the same group used to snapshot the SAME {chainKey, iteration}. The later one then wrote the
         * earlier one's ALREADY-CONSUMED message key back into skippedKeys (and persisted it), which both
         * leaks used group keys to disk and lets a re-sent ciphertext decrypt a second time. Queue the
         * work per group session so prepare→commit is atomic. `.then(run, run)` keeps the queue alive
         * after a rejected decrypt.
         */
        async decrypt(senderId, message) {
            const run = () => this._decryptSerialised(senderId, message);
            this._chain = (this._chain || Promise.resolve()).then(run, run);
            return this._chain;
        }

        async _decryptSerialised(senderId, message) {
            const senderKey = this.memberKeys.get(senderId);
            if (!senderKey) {
                throw new Error('No sender key for ' + senderId);
            }
            
            const ciphertext = Utils.fromBase64(message.ciphertext);
            const nonce = Utils.fromBase64(message.nonce);

            // КАО#140 (SER#16): verify per-sender Ed25519 signature BEFORE advancing the chain,
            // so a forged/tampered message can't desync the ratchet. Legacy msgs w/o signature accepted.
            if (senderKey.signingPublicKey) {
                // КАО#140 Round-2 hardening: REQUIRE a signature once the signing key is known — blocks a
                // strip-signature downgrade (deleting `signature` to bypass auth + still desync the ratchet).
                // (Pre-КАО#140 unsigned group messages are rejected; acceptable on stage.)
                if (!message.signature) {
                    throw new Error('Missing required group message signature for ' + senderId);
                }
                const signed = Utils.concat(nonce, ciphertext);
                const ok = await nacl.sign.detached_verify(signed, Utils.fromBase64(message.signature), senderKey.signingPublicKey);  // КАО#140: custom nacl uses detached_verify (async)
                if (!ok) {
                    throw new Error('Group message signature verification failed for ' + senderId);
                }
            }

            // КАО#289/#306: `message.iteration` is NOT covered by the signature above (which signs
            // nonce||ciphertext only), so it must never be able to move the receive ratchet unless the
            // message actually authenticates. prepareMessageKeyForIteration() therefore derives the key
            // from LOCAL copies and hands back a commit() — the state changes only after AES-GCM has
            // verified the tag. No half-advanced state ever exists, so a concurrent saveGroupSession()
            // cannot persist one either (which a rollback-after-the-fact could not prevent).
            const prepared = await senderKey.prepareMessageKeyForIteration(message.iteration);
            const plaintext = await AesGcm.decrypt(ciphertext, nonce, prepared.messageKey);
            prepared.commit();
            return plaintext;
        }

        /**
         * Get sender key distribution for new member
         */
        getDistribution() {
            if (!this.mySenderKey) return null;
            return this.mySenderKey.toDistribution();
        }

        toJSON() {
            return {
                groupId: this.groupId,
                mySenderKey: this.mySenderKey ? this.mySenderKey.toJSON() : null,
                memberKeys: Object.fromEntries(
                    Array.from(this.memberKeys.entries()).map(([k, v]) => [k, v.toJSON()])
                )
            };
        }

        static fromJSON(data) {
            const session = new GroupSession(data.groupId);
            if (data.mySenderKey) {
                session.mySenderKey = SenderKeyState.fromJSON(data.mySenderKey);
            }
            if (data.memberKeys) {
                for (const [k, v] of Object.entries(data.memberKeys)) {
                    session.memberKeys.set(k, ReceivedSenderKey.fromJSON(v));
                }
            }
            return session;
        }
    }

    // ============================================================================
    // SECTION 9: Key Storage (IndexedDB)
    // ============================================================================

    class CryptoStorage {
        constructor() {
            this.dbName = 'VibeCrypto';
            this.dbVersion = 1;
            this.db = null;
        }

        async init() {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open(this.dbName, this.dbVersion);
                
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    this.db = request.result;
                    resolve();
                };
                
                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    
                    // Identity keys store
                    if (!db.objectStoreNames.contains('identity')) {
                        db.createObjectStore('identity', { keyPath: 'id' });
                    }
                    
                    // Pre-keys store
                    if (!db.objectStoreNames.contains('prekeys')) {
                        const store = db.createObjectStore('prekeys', { keyPath: 'id' });
                        store.createIndex('type', 'type', { unique: false });
                    }
                    
                    // Sessions store (1:1 chats)
                    if (!db.objectStoreNames.contains('sessions')) {
                        db.createObjectStore('sessions', { keyPath: 'recipientId' });
                    }
                    
                    // Group sessions store
                    if (!db.objectStoreNames.contains('groupSessions')) {
                        db.createObjectStore('groupSessions', { keyPath: 'groupId' });
                    }
                };
            });
        }

        // Identity key operations
        async saveIdentityKeyPair(keyPair, signingKeyPair) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('identity', 'readwrite');
                const store = tx.objectStore('identity');
                const request = store.put({
                    id: 'me',
                    publicKey: Utils.toBase64(keyPair.publicKey),
                    secretKey: Utils.toBase64(keyPair.secretKey),
                    signingPublicKey: Utils.toBase64(signingKeyPair.publicKey),
                    signingSecretKey: Utils.toBase64(signingKeyPair.secretKey)
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getIdentityKeyPair() {
            const tx = this.db.transaction('identity', 'readonly');
            const store = tx.objectStore('identity');
            return new Promise((resolve, reject) => {
                const request = store.get('me');
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve({
                            keyPair: {
                                publicKey: Utils.fromBase64(request.result.publicKey),
                                secretKey: Utils.fromBase64(request.result.secretKey)
                            },
                            signingKeyPair: {
                                publicKey: Utils.fromBase64(request.result.signingPublicKey),
                                secretKey: Utils.fromBase64(request.result.signingSecretKey)
                            }
                        });
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        // Pre-key operations
        async saveSignedPreKey(preKey) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('prekeys', 'readwrite');
                const store = tx.objectStore('prekeys');
                const request = store.put({
                    id: `signed_${preKey.id}`,
                    type: 'signed',
                    keyId: preKey.id,
                    publicKey: Utils.toBase64(preKey.keyPair.publicKey),
                    secretKey: Utils.toBase64(preKey.keyPair.secretKey),
                    signature: Utils.toBase64(preKey.signature),
                    createdAt: preKey.createdAt
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getSignedPreKey(id) {
            const tx = this.db.transaction('prekeys', 'readonly');
            const store = tx.objectStore('prekeys');
            return new Promise((resolve, reject) => {
                const request = store.get(`signed_${id}`);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve({
                            id: request.result.keyId,
                            keyPair: {
                                publicKey: Utils.fromBase64(request.result.publicKey),
                                secretKey: Utils.fromBase64(request.result.secretKey)
                            },
                            signature: Utils.fromBase64(request.result.signature),
                            createdAt: request.result.createdAt
                        });
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        async saveOneTimePreKeys(preKeys) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('prekeys', 'readwrite');
                const store = tx.objectStore('prekeys');
                let completed = 0;
                
                for (const preKey of preKeys) {
                    const request = store.put({
                        id: `otp_${preKey.id}`,
                        type: 'onetime',
                        keyId: preKey.id,
                        publicKey: Utils.toBase64(preKey.keyPair.publicKey),
                        secretKey: Utils.toBase64(preKey.keyPair.secretKey)
                    });
                    request.onerror = () => reject(request.error);
                    request.onsuccess = () => {
                        completed++;
                        if (completed === preKeys.length) resolve();
                    };
                }
                
                if (preKeys.length === 0) resolve();
            });
        }

        async getOneTimePreKey(id) {
            const tx = this.db.transaction('prekeys', 'readonly');
            const store = tx.objectStore('prekeys');
            return new Promise((resolve, reject) => {
                const request = store.get(`otp_${id}`);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve({
                            id: request.result.keyId,
                            keyPair: {
                                publicKey: Utils.fromBase64(request.result.publicKey),
                                secretKey: Utils.fromBase64(request.result.secretKey)
                            }
                        });
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        async deleteOneTimePreKey(id) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('prekeys', 'readwrite');
                const store = tx.objectStore('prekeys');
                const request = store.delete(`otp_${id}`);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getOneTimePreKeyCount() {
            const tx = this.db.transaction('prekeys', 'readonly');
            const store = tx.objectStore('prekeys');
            const index = store.index('type');
            return new Promise((resolve, reject) => {
                const request = index.count('onetime');
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result);
            });
        }

        /**
         * v3.7.0: Save previous signed prekey (for rotation)
         */
        async savePreviousSignedPreKey(preKey) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('prekeys', 'readwrite');
                const store = tx.objectStore('prekeys');
                const request = store.put({
                    id: `prev_signed_${preKey.id}`,
                    type: 'previous_signed',
                    keyId: preKey.id,
                    publicKey: Utils.toBase64(preKey.keyPair.publicKey),
                    secretKey: Utils.toBase64(preKey.keyPair.secretKey),
                    signature: Utils.toBase64(preKey.signature),
                    createdAt: preKey.createdAt,
                    savedAt: new Date().toISOString()
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        /**
         * v3.7.0: Get previous signed prekey by ID
         */
        async getPreviousSignedPreKey(id) {
            const tx = this.db.transaction('prekeys', 'readonly');
            const store = tx.objectStore('prekeys');
            return new Promise((resolve, reject) => {
                const request = store.get(`prev_signed_${id}`);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve({
                            id: request.result.keyId,
                            keyPair: {
                                publicKey: Utils.fromBase64(request.result.publicKey),
                                secretKey: Utils.fromBase64(request.result.secretKey)
                            },
                            signature: Utils.fromBase64(request.result.signature),
                            createdAt: request.result.createdAt
                        });
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        // Session operations
        
        // v3.11.0: PQ-KEM key operations
        async savePqKemKeyPair(keyPair) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('identity', 'readwrite');
                const store = tx.objectStore('identity');
                const request = store.put({
                    id: 'pq_kem',
                    publicKey: Utils.toBase64(keyPair.publicKey),
                    secretKey: Utils.toBase64(keyPair.secretKey)
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getPqKemKeyPair() {
            const tx = this.db.transaction('identity', 'readonly');
            const store = tx.objectStore('identity');
            return new Promise((resolve, reject) => {
                const request = store.get('pq_kem');
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve({
                            publicKey: Utils.fromBase64(request.result.publicKey),
                            secretKey: Utils.fromBase64(request.result.secretKey)
                        });
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        async saveSession(recipientId, session) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('sessions', 'readwrite');
                const store = tx.objectStore('sessions');
                const request = store.put({
                    recipientId: recipientId,
                    session: session.toJSON(),
                    updatedAt: Date.now()
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getSession(recipientId) {
            const tx = this.db.transaction('sessions', 'readonly');
            const store = tx.objectStore('sessions');
            return new Promise((resolve, reject) => {
                const request = store.get(recipientId);
                request.onerror = () => reject(request.error);
                request.onsuccess = async () => {
                    if (request.result) {
                        const session = DoubleRatchetSession.fromJSON(request.result.session);
                        if (session === null) {
                            // Invalid/old session - delete it
                            console.log('[E2EE] Deleting invalid session for', recipientId);
                            await this.deleteSession(recipientId);
                        }
                        resolve(session);
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        async deleteSession(recipientId) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('sessions', 'readwrite');
                const store = tx.objectStore('sessions');
                const request = store.delete(recipientId);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        // КАО#373: the pending X3DH/PQXDH HEADER, persisted next to the session it belongs to.
        // Only the values that are already transmitted in cleartext are stored — identity/ephemeral PUBLIC
        // keys, the one-time-prekey id and the PQ-KEM ciphertext. The shared secret and the ephemeral
        // SECRET key are never written, so this adds no key-exposure surface.
        // It lives in the `sessions` store on purpose: storage.clearAll()/clearAllSessions() wipe that store
        // wholesale, so a header can never outlive the session material it belongs to.
        async savePendingX3DHHeader(recipientId, header) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('sessions', 'readwrite');
                const store = tx.objectStore('sessions');
                const request = store.put({
                    recipientId: 'pending_x3dh:' + recipientId,
                    x3dhHeader: header,
                    updatedAt: Date.now()
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getPendingX3DHHeader(recipientId) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('sessions', 'readonly');
                const store = tx.objectStore('sessions');
                const request = store.get('pending_x3dh:' + recipientId);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result ? request.result.x3dhHeader : null);
            });
        }

        async deletePendingX3DHHeader(recipientId) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('sessions', 'readwrite');
                const store = tx.objectStore('sessions');
                const request = store.delete('pending_x3dh:' + recipientId);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        // Group session operations
        async saveGroupSession(groupId, session) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('groupSessions', 'readwrite');
                const store = tx.objectStore('groupSessions');
                const request = store.put({
                    groupId: groupId,
                    session: session.toJSON(),
                    updatedAt: Date.now()
                });
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        async getGroupSession(groupId) {
            const tx = this.db.transaction('groupSessions', 'readonly');
            const store = tx.objectStore('groupSessions');
            return new Promise((resolve, reject) => {
                const request = store.get(groupId);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    if (request.result) {
                        resolve(GroupSession.fromJSON(request.result.session));
                    } else {
                        resolve(null);
                    }
                };
            });
        }

        async deleteGroupSession(groupId) {
            return new Promise((resolve, reject) => {
                const tx = this.db.transaction('groupSessions', 'readwrite');
                const store = tx.objectStore('groupSessions');
                const request = store.delete(groupId);
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve();
            });
        }

        // Clear all sessions (keep identity and prekeys)
        async clearAllSessions() {
            const stores = ['sessions', 'groupSessions'];
            const promises = stores.map(storeName => {
                return new Promise((resolve, reject) => {
                    const tx = this.db.transaction(storeName, 'readwrite');
                    const store = tx.objectStore(storeName);
                    const request = store.clear();
                    request.onerror = () => reject(request.error);
                    request.onsuccess = () => resolve();
                });
            });
            await Promise.all(promises);
        }

        // Clear all crypto data
        async clearAll() {
            const stores = ['identity', 'prekeys', 'sessions', 'groupSessions'];
            const promises = stores.map(storeName => {
                return new Promise((resolve, reject) => {
                    const tx = this.db.transaction(storeName, 'readwrite');
                    const store = tx.objectStore(storeName);
                    const request = store.clear();
                    request.onerror = () => reject(request.error);
                    request.onsuccess = () => resolve();
                });
            });
            await Promise.all(promises);
        }
    }

    // ============================================================================
    // SECTION 10: Session Manager (Main Interface)
    // ============================================================================

    class VibeE2EE {
        constructor() {
            this.storage = new CryptoStorage();
            this.identityKeyPair = null;
            this.signingKeyPair = null;
            this.signedPreKey = null;
            this.oneTimePreKeys = [];
            this.sessions = new Map();  // recipientId -> DoubleRatchetSession
            this.groupSessions = new Map();  // groupId -> GroupSession
            this.pendingX3DH = new Map();  // recipientId -> X3DHResult (for first message)
            this.initialized = false;
            // v3.7.27: Self-encryption key for multi-device sync
            this.selfEncryptionKey = null;
            // v3.11.0: Post-quantum KEM key pair (ML-KEM-768)
            this.pqKemKeyPair = null;
            // КАО#371: per-PEER serialisation queue for the 1:1 Double Ratchet. See _runForPeer below.
            // Keyed by peer id and NOT by session object, because the cold-cache double-load happens
            // BEFORE any session object exists — a per-instance lock (the КАО#331 shape) cannot cover it.
            this._drChains = new Map();  // peerId -> tail promise
            // КАО#372: in-flight group-session loads, plus a generation counter so a load started before a
            // wipe cannot re-publish the old session afterwards. See _loadGroupSession below.
            this._groupLoads = new Map();  // groupId -> in-flight load promise
            // КАО#382: per-GROUP serialisation queue. КАО#331 put a lock on GroupSession.decrypt
            // only, so encrypt and addMemberKey mutated the very same session with no lock at all - and
            // even decryptGroupMessage saved OUTSIDE that lock. See _runForGroup.
            this._groupChains = new Map();  // groupId -> tail promise
            this._groupGen = 0;
        }

        /**
         * КАО#372: single-flight loader for a group session.
         *
         * КАО#331 put the serialisation lock on the GroupSession INSTANCE (`this._chain`), but all four
         * entry points loaded the session with a check-then-await and no in-flight guard, and
         * storage.getGroupSession() returns a FRESH GroupSession.fromJSON on EVERY call. On a cold cache
         * (first group traffic after a page load, or after clearAllSessions) two callers both miss
         * `groupSessions`, both await IndexedDB, and each ends up with its own object carrying its own
         * `_chain` — so each serialises only against itself. Both then snapshot the same {chainKey,
         * iteration}, the later commit writes an ALREADY-CONSUMED message key into skippedKeys, and the two
         * saveGroupSession() calls race so the loser's advance is silently lost on disk. That is precisely
         * the leak-used-group-keys condition КАО#331 was written to close.
         * Concurrency is real, not theoretical: buffered messages are replayed with unawaited
         * handleNewMessage() calls (app.js), so several frames march through identical awaits in lock-step.
         *
         * @param {string} groupId
         * @param {false|true|'init'} create  false = load only; true = create empty if absent;
         *                                    'init' = create AND initialize() a sender key.
         */
        async _loadGroupSession(groupId, create) {
            const cached = this.groupSessions.get(groupId);
            if (cached) return cached;

            let p = this._groupLoads.get(groupId);
            if (!p) {
                const gen = this._groupGen;
                p = (async () => {
                    let s = await this.storage.getGroupSession(groupId);
                    if (!s && create) {
                        s = new GroupSession(groupId);
                        if (create === 'init') await s.initialize();
                    }
                    // Publish only if no wipe happened while we were loading. Without this a load that
                    // started before logout would re-insert the PREVIOUS user's group session into the map
                    // after clearAll() had emptied it — the КАО#325 failure mode, one level down.
                    if (s && this._groupGen === gen) this.groupSessions.set(groupId, s);
                    return s;
                })();
                this._groupLoads.set(groupId, p);
                p.catch(() => {}).then(() => {
                    if (this._groupLoads.get(groupId) === p) this._groupLoads.delete(groupId);
                });
            }
            return p;
        }

        /**
         * КАО#371 (critical): run `fn` with exclusive access to the 1:1 ratchet state of one peer.
         *
         * КАО#331 serialised GroupSession.decrypt for exactly this reason but left the 1:1 path open, even
         * though it has the same two races and is the far more common path:
         *   (a) decrypt() spans many event-loop turns (_skipMessages -> _ratchetChainKey -> HMAC ->
         *       crypto.subtle -> AES-GCM) while handleWSMessage calls handleNewMessage() UNAWAITED, so two
         *       frames interleave; _skipMessages mutates the SHARED receivingChainKey/receivingMessageNumber
         *       in place while the other decrypt still holds a stale local chainKey it later writes back.
         *   (b) on a cold cache both calls miss this.sessions, both await storage.getSession(), and each
         *       gets its own session object — so the last saveSession() silently wins.
         * The visible damage was a chain key one step out of step with its counter: every subsequent message
         * from that peer failed its AES-GCM tag and rendered "🔒 Encrypted message (key expired)" until the
         * peer happened to DH-ratchet. Worse, an already-consumed message key was left in skippedKeys and
         * persisted, so a replayed ciphertext could decrypt a second time.
         *
         * encryptMessage goes through the SAME queue: it does the identical get-or-load / mutate / save
         * sequence on the very same session, so serialising only decrypt would leave the race half-open.
         *
         * ⚠️ Re-entrancy: nothing inside encrypt/decrypt may call back into these two methods for the SAME
         * peer — that would await a promise this very task must resolve, deadlocking the peer permanently.
         * Verified safe today (the bodies never call each other; app.js's three call sites are all outside).
         * Keep it that way.
         */
        /**
         * КАО#382: run `fn` with exclusive access to one group's sender-key state.
         *
         * КАО#331 serialised GroupSession.decrypt, and КАО#372 made every caller share ONE session
         * object so that lock could not be bypassed. Two holes were left:
         *   - encryptGroupMessage() advances mySenderKey and saves, and processGroupKeyDistribution()
         *     replaces a member's receive chain and saves, neither taking `_chain` at all - so a send or an
         *     incoming distribution can interleave with a decrypt and the later save wins, discarding the
         *     other's advance;
         *   - decryptGroupMessage() calls session.decrypt() (locked internally) but then does
         *     `await storage.saveGroupSession()` OUTSIDE it, so two decrypts can serialise their ratchet
         *     steps correctly and still race their writes to IndexedDB.
         * Queue the WHOLE load -> mutate -> save sequence per groupId and all three become atomic against
         * each other. `.then(run, run)` keeps the queue alive after a rejection.
         *
         * Re-entrancy: none of the group entry points calls another for the same group (verified), which is
         * what makes this deadlock-free. Keep it that way.
         */
        _runForGroup(groupId, fn) {
            const prev = this._groupChains.get(groupId) || Promise.resolve();
            const next = prev.then(fn, fn);
            this._groupChains.set(groupId, next);
            next.catch(() => {}).then(() => {
                if (this._groupChains.get(groupId) === next) this._groupChains.delete(groupId);
            });
            return next;
        }

        _runForPeer(peerId, fn) {
            const prev = this._drChains.get(peerId) || Promise.resolve();
            // .then(fn, fn) so one rejected message does not wedge the queue for that peer forever.
            const next = prev.then(fn, fn);
            this._drChains.set(peerId, next);
            // Drop the entry once it is the tail and has settled, so the map cannot grow without bound.
            // Deliberately NOT cleared by clearAll()/deleteSession(): dropping a tail mid-flight would let a
            // new call run CONCURRENTLY with the in-flight one, reintroducing the very race this closes.
            next.catch(() => {}).then(() => {
                if (this._drChains.get(peerId) === next) this._drChains.delete(peerId);
            });
            return next;
        }

        /**
         * Initialize E2EE system
         */
        async init() {
            await this.storage.init();
            
            // Try to load existing keys
            const identity = await this.storage.getIdentityKeyPair();
            if (identity) {
                this.identityKeyPair = identity.keyPair;
                this.signingKeyPair = identity.signingKeyPair;
                
                // Load signed pre-key
                this.signedPreKey = await this.storage.getSignedPreKey(1);
                
                // v3.11.0: Load PQ-KEM key pair
                this.pqKemKeyPair = await this.storage.getPqKemKeyPair();
            }
            
            // v3.7.27: Load self-encryption key from localStorage
            const storedSelfKey = localStorage.getItem('vibe_self_encryption_key');
            if (storedSelfKey) {
                this.selfEncryptionKey = Utils.fromBase64(storedSelfKey);
                console.log('[E2EE] Loaded self-encryption key from localStorage');
            }
            
            this.initialized = true;
            console.log('[E2EE] Initialized, hasKeys:', !!this.identityKeyPair, 'hasSelfKey:', !!this.selfEncryptionKey, 'hasPQ:', !!this.pqKemKeyPair);
        }

        /**
         * Check if we have keys
         */
        hasKeys() {
            return !!this.identityKeyPair;
        }

        /**
         * Generate new key bundle
         * Call this on registration or when keys need refresh
         * @param {number} otpCount - Number of one-time pre-keys to generate
         * @returns {Object} - Public key bundle to upload to server
         */
        async generateKeyBundle(otpCount = 100) {
            console.log('[E2EE] Generating new key bundle...');
            
            // Generate identity key pair (X25519 for DH)
            this.identityKeyPair = nacl.box.keyPair();
            
            // Generate signing key pair (Ed25519)
            this.signingKeyPair = await nacl.sign.keyPair();
            
            // Save identity keys
            await this.storage.saveIdentityKeyPair(this.identityKeyPair, this.signingKeyPair);
            
            // Generate signed pre-key
            this.signedPreKey = await X3DH.generateSignedPreKey(1, this.signingKeyPair);
            await this.storage.saveSignedPreKey(this.signedPreKey);
            
            // Generate one-time pre-keys
            this.oneTimePreKeys = X3DH.generateOneTimePreKeys(1, otpCount);
            await this.storage.saveOneTimePreKeys(this.oneTimePreKeys);
            
            // v3.11.0: Generate PQ-KEM key pair (ML-KEM-768)
            let pqPublicKeyBase64 = null;
            if (typeof PQKEM !== 'undefined' && PQKEM.isAvailable()) {
                this.pqKemKeyPair = PQKEM.keygen();
                await this.storage.savePqKemKeyPair(this.pqKemKeyPair);
                pqPublicKeyBase64 = Utils.toBase64(this.pqKemKeyPair.publicKey);
                console.log('[E2EE] PQ-KEM key generated (ML-KEM-768), pubKey:', this.pqKemKeyPair.publicKey.length, 'bytes');
            } else {
                console.warn('[E2EE] PQ-KEM not available, using classic X3DH only');
            }
            
            // Build public bundle for server
            const bundle = {
                identity_key: Utils.toBase64(this.identityKeyPair.publicKey),
                signed_prekey_id: this.signedPreKey.id,
                signed_prekey: Utils.toBase64(this.signedPreKey.keyPair.publicKey),
                signed_prekey_signature: Utils.toBase64(this.signedPreKey.signature),
                one_time_prekeys: this.oneTimePreKeys.map(k => ({
                    id: k.id,
                    key: Utils.toBase64(k.keyPair.publicKey)
                })),
                pq_kem_public_key: pqPublicKeyBase64,  // v3.11.0: null if PQ unavailable
                signing_public_key: Utils.toBase64(this.signingKeyPair.publicKey),  // v3.11.8: Ed25519 for SPK verification
            };
            
            console.log('[E2EE] Generated bundle with', otpCount, 'OTPs, PQ:', !!pqPublicKeyBase64);
            return bundle;
        }

        /**
         * Get our identity public key (base64)
         */
        getIdentityPublicKey() {
            if (!this.identityKeyPair) return null;
            return Utils.toBase64(this.identityKeyPair.publicKey);
        }

        /**
         * Encrypt message for 1:1 chat
         * @param {string} recipientId
         * @param {string} plaintext - Message text
         * @param {Object} [theirBundle] - Recipient's key bundle (if no session exists)
         * @returns {Promise<string>} - Base64 encoded encrypted payload
         */
        // КАО#371: serialised entry point. Body unchanged below in _encryptMessageSerialised.
        async encryptMessage(recipientId, plaintext, theirBundle = null) {
            return this._runForPeer(recipientId,
                () => this._encryptMessageSerialised(recipientId, plaintext, theirBundle));
        }

        async _encryptMessageSerialised(recipientId, plaintext, theirBundle = null) {
            // Get or create session
            let session = this.sessions.get(recipientId);
            
            if (!session) {
                session = await this.storage.getSession(recipientId);
                if (session) {
                    console.log('[E2EE] Loaded existing session from storage for', recipientId);
                    this.sessions.set(recipientId, session);
                }
            }
            
            if (!session) {
                if (!theirBundle) {
                    throw new Error('No session and no key bundle for ' + recipientId);
                }

                // КАО#6 (TOFU — by design): like Signal, the recipient's identity key is trusted on first
                // use. We do NOT hard-pin against a server-provided bundle (the server is untrusted, but a
                // user has no prior key to compare on the very first contact). Subsequent identity-key
                // CHANGES are surfaced out-of-band: verifyContactIdentityKey() warns on change and users
                // confirm the relationship via the safety-number / emoji fingerprint (КАО#263) — the
                // standard TOFU + manual-verification model. The SPK signature (КАО#261) additionally
                // prevents the server substituting a signed prekey within an established identity.
                // Establish new session via X3DH
                console.log('[E2EE] Establishing NEW session with', recipientId);
                // КАО#303: pass the recipient id the CALLER asked for — the PQ-downgrade pin must not be
                // keyed on theirBundle.user_id, which the (untrusted) server controls and could vary to
                // sidestep the pin.
                const x3dhResult = await X3DH.initiateSession(this.identityKeyPair, theirBundle, recipientId);
                console.log('[E2EE] X3DH completed, usedOtpId:', x3dhResult.usedOneTimePreKeyId);
                
                session = new DoubleRatchetSession();
                await session.initSender(
                    x3dhResult.sharedSecret,
                    Utils.fromBase64(theirBundle.signed_prekey),
                    x3dhResult.ephemeralKeyPair  // Pass ephemeral key pair for DH ratchet consistency
                );
                console.log('[E2EE] Session initialized as sender');
                
                this.sessions.set(recipientId, session);
                this.pendingX3DH.set(recipientId, x3dhResult);
                // КАО#373: persist the PUBLIC header immediately, before this message is even on the wire.
                // pendingX3DH is an in-memory Map recreated empty by the constructor, while the session IS
                // persisted — so after a reload encryptMessage found the session, skipped the initiate
                // branch, and emitted a header-less payload for ever. The peer could then never establish
                // the session and every message from us was permanently undecryptable to them.
                try {
                    await this.storage.savePendingX3DHHeader(recipientId, {
                        isPQXDH: !!x3dhResult.isPQXDH,
                        identity_key: Utils.toBase64(this.identityKeyPair.publicKey),
                        ephemeral_key: Utils.toBase64(x3dhResult.ephemeralKeyPair.publicKey),
                        used_otp_id: x3dhResult.usedOneTimePreKeyId,
                        pq_kem_ciphertext: x3dhResult.pqKemCiphertext ? Utils.toBase64(x3dhResult.pqKemCiphertext) : null,
                    });
                } catch (e) {
                    console.error('[E2EE] КАО#373: could not persist the X3DH header:', e);
                }
            }
            
            // Encrypt with Double Ratchet
            const plaintextBytes = Utils.stringToBytes(plaintext);
            const encrypted = await session.encrypt(plaintextBytes);
            
            // Save session
            await this.storage.saveSession(recipientId, session);
            
            // Check for pending X3DH/PQXDH data (first message).
            // КАО#373: normalise to ONE header shape, and fall back to the persisted copy when the
            // in-memory Map has been lost (page reload / PWA relaunch).
            const pending = this.pendingX3DH.get(recipientId);
            let header = null;
            if (pending) {
                header = {
                    isPQXDH: !!pending.isPQXDH,
                    identity_key: Utils.toBase64(this.identityKeyPair.publicKey),
                    ephemeral_key: Utils.toBase64(pending.ephemeralKeyPair.publicKey),
                    used_otp_id: pending.usedOneTimePreKeyId,
                    pq_kem_ciphertext: pending.pqKemCiphertext ? Utils.toBase64(pending.pqKemCiphertext) : null,
                };
            } else {
                try { header = await this.storage.getPendingX3DHHeader(recipientId); } catch (e) { header = null; }
            }

            // Build payload
            const payload = {
                v: (header && header.isPQXDH) ? 2 : 1,  // v3.11.0: v2 = PQXDH, v1 = X3DH
                message: encrypted
            };

            // Include X3DH/PQXDH info in first message
            if (header) {
                payload.x3dh = {
                    identity_key: header.identity_key,
                    ephemeral_key: header.ephemeral_key,
                    used_otp_id: header.used_otp_id
                };
                // v3.11.0: Include PQ-KEM ciphertext for PQXDH
                if (header.pq_kem_ciphertext) {
                    payload.x3dh.pq_kem_ciphertext = header.pq_kem_ciphertext;
                }
                // КАО#330: do NOT drop the handshake here. This ran when the payload was BUILT, not when
                // the message was delivered — so if the send then failed (network drop, 429, a fail-closed
                // abort, the user cancelling the unencrypted-send confirm) the X3DH data was gone while
                // our local session remained. Every later message went out ratchet-only with no x3dh
                // header, the recipient could never establish the session, and EVERY message from us
                // became permanently undecryptable for them. Keep re-attaching it until we have proof the
                // peer established the session — i.e. until we successfully decrypt a message from them
                // (cleared in decryptMessage). Harmless to repeat: the receiver only consumes `x3dh` when
                // it has no session yet (see decryptMessage: `if (!session && payload.x3dh)`).
            }
            
            return Utils.toBase64(Utils.stringToBytes(JSON.stringify(payload)));
        }

        /**
         * Decrypt message from 1:1 chat
         * @param {string} senderId
         * @param {string} encryptedPayload - Base64 encoded
         * @returns {Promise<string>} - Decrypted message text
         */
        // КАО#371: serialised entry point. Body unchanged below in _decryptMessageSerialised.
        async decryptMessage(senderId, encryptedPayload) {
            return this._runForPeer(senderId,
                () => this._decryptMessageSerialised(senderId, encryptedPayload));
        }

        async _decryptMessageSerialised(senderId, encryptedPayload) {
            const payloadBytes = Utils.fromBase64(encryptedPayload);
            const payload = JSON.parse(Utils.bytesToString(payloadBytes));
            
            console.log('[E2EE] Decrypting message from', senderId, 'v:', payload.v, 'hasX3DH:', !!payload.x3dh);
            
            // Get session
            let session = this.sessions.get(senderId);
            let isNewSession = false;
            let usedOtpId = null;
            
            if (!session) {
                session = await this.storage.getSession(senderId);
                if (session) {
                    console.log('[E2EE] Loaded existing session from storage');
                    this.sessions.set(senderId, session);
                }
            }
            
            // Process X3DH if this is first message
            if (!session && payload.x3dh) {
                console.log('[E2EE] Processing incoming session from', senderId);
                
                const theirIdentityKey = Utils.fromBase64(payload.x3dh.identity_key);
                const theirEphemeralKey = Utils.fromBase64(payload.x3dh.ephemeral_key);
                usedOtpId = payload.x3dh.used_otp_id;
                
                console.log('[E2EE] X3DH params - usedOtpId:', usedOtpId);
                
                // Get our one-time pre-key if used (but don't delete yet!)
                let ourOtp = null;
                if (usedOtpId !== null) {
                    ourOtp = await this.storage.getOneTimePreKey(usedOtpId);
                    if (ourOtp) {
                        console.log('[E2EE] Found one-time prekey:', usedOtpId);
                    } else {
                        console.warn('[E2EE] CRITICAL: One-time prekey not found:', usedOtpId);
                        console.warn('[E2EE] This will cause X3DH mismatch! Sender used OTP but we dont have it.');
                        console.warn('[E2EE] Both sides need to clear E2EE data: indexedDB.deleteDatabase("VibeE2EE")');
                    }
                }
                
                // Compute shared secret
                // v3.11.0: Pass PQ-KEM ciphertext if present (PQXDH v2)
                let pqKemCiphertext = null;
                if (payload.x3dh.pq_kem_ciphertext) {
                    pqKemCiphertext = Utils.fromBase64(payload.x3dh.pq_kem_ciphertext);
                    console.log('[E2EE] PQXDH: PQ-KEM ciphertext received,', pqKemCiphertext.length, 'bytes');
                }
                
                const sharedSecret = await X3DH.processSession(
                    this.identityKeyPair,
                    this.signedPreKey,
                    ourOtp,
                    theirIdentityKey,
                    theirEphemeralKey,
                    pqKemCiphertext,       // v3.11.0: PQ-KEM ciphertext
                    this.pqKemKeyPair      // v3.11.0: Our PQ-KEM key pair
                );
                
                console.log('[E2EE] X3DH shared secret computed');
                
                // Initialize session as receiver
                session = new DoubleRatchetSession();
                await session.initReceiver(sharedSecret, this.signedPreKey.keyPair);
                
                isNewSession = true;
                console.log('[E2EE] New session initialized as receiver');
            }
            
            if (!session) {
                throw new Error('No session with ' + senderId + ' and no X3DH data in message');
            }
            
            // Decrypt with Double Ratchet
            console.log('[E2EE] Decrypting with Double Ratchet...');
            const decryptedBytes = await session.decrypt(payload.message);
            
            // Decryption successful! Now commit changes:
            
            // 1. Delete OTP if we used one (only after successful decryption)
            if (usedOtpId !== null) {
                await this.storage.deleteOneTimePreKey(usedOtpId);
                console.log('[E2EE] Deleted used one-time prekey:', usedOtpId);
            }
            
            // 2. Save session to memory and storage
            this.sessions.set(senderId, session);
            await this.storage.saveSession(senderId, session);

            // 3. КАО#330: a message from this peer decrypted, so they demonstrably have the session —
            // only now is it safe to stop re-attaching our X3DH handshake to outgoing messages.
            this.pendingX3DH.delete(senderId);
            // КАО#373: drop the PERSISTED copy too, or the handshake would keep being re-attached for ever
            // (harmless to the peer, who ignores it once a session exists, but it would also survive a
            // later session reset and re-offer a dead ephemeral/one-time-prekey pair).
            try { await this.storage.deletePendingX3DHHeader(senderId); } catch (e) {}

            console.log('[E2EE] Message decrypted successfully');
            return Utils.bytesToString(decryptedBytes);
        }

        /**
         * Encrypt message for group chat
         * @param {string} groupId
         * @param {string} plaintext
         * @returns {Promise<Object>} - {payload, distribution?}
         */
        // КАО#382: serialised entry point.
        async encryptGroupMessage(groupId, plaintext) {
            return this._runForGroup(groupId, () => this._encryptGroupMessageSerialised(groupId, plaintext));
        }

        async _encryptGroupMessageSerialised(groupId, plaintext) {
            // КАО#372: single-flight load. Two concurrent cold-cache sends used to build and initialize()
            // two DIFFERENT sender keys for the same group, only one of which survived in the map and on disk.
            const session = await this._loadGroupSession(groupId, 'init');

            // Get distribution BEFORE encrypt (so iteration matches the message)
            const distribution = session.getDistribution();
            
            // Encrypt
            const plaintextBytes = Utils.stringToBytes(plaintext);
            const encrypted = await session.encrypt(plaintextBytes);
            
            // Save
            await this.storage.saveGroupSession(groupId, session);
            
            const payload = {
                v: 1,
                group: encrypted
            };
            
            return {
                payload: Utils.toBase64(Utils.stringToBytes(JSON.stringify(payload))),
                distribution: distribution
            };
        }

        /**
         * Process sender key distribution from group member
         */
        // КАО#382: serialised entry point.
        async processGroupKeyDistribution(groupId, senderId, distribution) {
            return this._runForGroup(groupId,
                () => this._processGroupKeyDistributionSerialised(groupId, senderId, distribution));
        }

        async _processGroupKeyDistributionSerialised(groupId, senderId, distribution) {
            const session = await this._loadGroupSession(groupId, true);  // КАО#372

            session.addMemberKey(senderId, distribution);
            await this.storage.saveGroupSession(groupId, session);
        }

        /**
         * Decrypt group message
         */
        // КАО#382: serialised entry point - this also brings the saveGroupSession() call, which used
        // to sit OUTSIDE GroupSession's own lock, inside the critical section.
        async decryptGroupMessage(groupId, senderId, encryptedPayload) {
            return this._runForGroup(groupId,
                () => this._decryptGroupMessageSerialised(groupId, senderId, encryptedPayload));
        }

        async _decryptGroupMessageSerialised(groupId, senderId, encryptedPayload) {
            const payloadBytes = Utils.fromBase64(encryptedPayload);
            const payload = JSON.parse(Utils.bytesToString(payloadBytes));
            
            // КАО#372: single-flight load, so all concurrent decrypts share ONE GroupSession object and
            // therefore ONE `_chain` lock — without this the КАО#331 serialisation was defeated entirely
            // on a cold cache, which is exactly when a burst of buffered messages is replayed.
            const session = await this._loadGroupSession(groupId, false);

            if (!session) {
                throw new Error('No group session for ' + groupId);
            }

            const decryptedBytes = await session.decrypt(senderId, payload.group);
            await this.storage.saveGroupSession(groupId, session);
            
            return Utils.bytesToString(decryptedBytes);
        }

        /**
         * Get sender key distribution for new group member
         */
        async getGroupKeyDistribution(groupId) {
            // КАО#372: this one previously read from storage WITHOUT caching, so it could hand out a
            // distribution derived from a snapshot that a concurrent send had already advanced past.
            const session = await this._loadGroupSession(groupId, false);

            if (!session || !session.mySenderKey) {
                return null;
            }
            
            return session.getDistribution();
        }

        /**
         * Encrypt file/attachment
         * @param {ArrayBuffer} data - File data
         * @returns {Promise<{key: string, encrypted: ArrayBuffer}>}
         */
        async encryptFile(data) {
            const key = Utils.randomBytes(32);
            const plaintext = new Uint8Array(data);
            const encrypted = await AesGcm.encrypt(plaintext, key);
            
            // Combine nonce + ciphertext
            const combined = Utils.concat(encrypted.nonce, encrypted.ciphertext);
            
            return {
                key: Utils.toBase64(key),
                encrypted: combined.buffer
            };
        }

        /**
         * Decrypt file/attachment
         */
        async decryptFile(encryptedData, keyBase64) {
            const key = Utils.fromBase64(keyBase64);
            const data = new Uint8Array(encryptedData);
            const nonce = data.slice(0, 12);
            const ciphertext = data.slice(12);
            
            const decrypted = await AesGcm.decrypt(ciphertext, nonce, key);
            return decrypted.buffer;
        }

        /**
         * КАО#230 (SER#18): Symmetric encrypt of arbitrary text with a caller-supplied key.
         * Used for poll question/options E2EE — one per-poll key encrypts every field, and that
         * key is distributed inside the (already E2E) poll announce message. Returns
         * base64(nonce(12) || ciphertext); decrypt with decryptWithKey using the same key.
         */
        async encryptWithKey(text, keyBase64) {
            const key = Utils.fromBase64(keyBase64);
            const plaintext = new TextEncoder().encode(text);
            const encrypted = await AesGcm.encrypt(plaintext, key);
            const combined = Utils.concat(encrypted.nonce, encrypted.ciphertext);
            return Utils.toBase64(combined);
        }

        /**
         * КАО#230 (SER#18): Symmetric decrypt of encryptWithKey output.
         */
        async decryptWithKey(base64, keyBase64) {
            const key = Utils.fromBase64(keyBase64);
            const data = Utils.fromBase64(base64);
            const nonce = data.slice(0, 12);
            const ciphertext = data.slice(12);
            const decrypted = await AesGcm.decrypt(ciphertext, nonce, key);
            return new TextDecoder().decode(decrypted);
        }

        /** КАО#230 (SER#18): generate a fresh random 256-bit content key (base64). */
        generateContentKey() {
            return Utils.toBase64(Utils.randomBytes(32));
        }

        /**
         * Check and replenish one-time pre-keys if needed
         */
        async checkAndReplenishPreKeys(threshold = 10, replenishCount = 50) {
            const count = await this.storage.getOneTimePreKeyCount();
            
            if (count < threshold) {
                console.log('[E2EE] Replenishing pre-keys, current count:', count);
                
                // Find highest existing ID
                // For simplicity, use timestamp-based IDs
                const startId = Date.now();
                const newKeys = X3DH.generateOneTimePreKeys(startId, replenishCount);
                await this.storage.saveOneTimePreKeys(newKeys);
                
                // Return public keys for upload
                return newKeys.map(k => ({
                    id: k.id,
                    key: Utils.toBase64(k.keyPair.publicKey)
                }));
            }
            
            return null;
        }

        /**
         * Delete session with contact
         */
        async deleteSession(recipientId) {
            this.sessions.delete(recipientId);
            // КАО#373: a session reset must take the pending handshake with it, in memory AND on disk —
            // otherwise the next message would re-offer an ephemeral key and a one-time-prekey id that
            // belong to a session that no longer exists.
            this.pendingX3DH.delete(recipientId);
            await this.storage.deleteSession(recipientId);
            try { await this.storage.deletePendingX3DHHeader(recipientId); } catch (e) {}
        }

        /**
         * v3.8.6: Check if we have a session with contact
         */
        async hasSession(recipientId) {
            // Check memory cache first
            if (this.sessions.has(recipientId)) {
                return true;
            }
            // Check storage
            try {
                const session = await this.storage.getSession(recipientId);
                return session !== null && session !== undefined;
            } catch (e) {
                return false;
            }
        }

        /**
         * Delete group session
         */
        async deleteGroupSession(groupId) {
            // КАО#372: invalidate any load already in flight, so it cannot re-publish the session we are
            // about to drop. Bumping the generation is what actually stops it — merely deleting the map
            // entry would leave the in-flight promise free to call groupSessions.set() when it resolves.
            this._groupGen++;
            this._groupLoads.delete(groupId);
            this.groupSessions.delete(groupId);
            await this.storage.deleteGroupSession(groupId);
        }

        /**
         * Clear all sessions but keep identity keys
         * Use this when sessions are corrupted but you want to keep your identity
         */
        async clearAllSessions() {
            this._groupGen++;              // КАО#372: see deleteGroupSession
            this._groupLoads.clear();
            this.sessions.clear();
            this.groupSessions.clear();
            this.pendingX3DH.clear();
            await this.storage.clearAllSessions();
            console.log('[E2EE] All sessions cleared (identity keys preserved)');
        }

        /**
         * Clear all E2EE data (logout)
         */
        async clearAll() {
            this.identityKeyPair = null;
            this.signingKeyPair = null;
            this.signedPreKey = null;
            this.oneTimePreKeys = [];
            this._groupGen++;              // КАО#372: see deleteGroupSession
            this._groupLoads.clear();
            this.sessions.clear();
            this.groupSessions.clear();
            this.pendingX3DH.clear();
            // КАО#323: the self-encryption key and the PQ-KEM keypair were NOT cleared, and the self key
            // lives in localStorage (not IndexedDB), so it survived clearAll() entirely. After logout the
            // NEXT account signing in on the same browser silently adopted the PREVIOUS user's self key:
            // their multi-device copies (encrypted_for_self) would be sealed with a key the former user
            // also holds, and stale cached blobs could be opened. Wipe both here.
            this.selfEncryptionKey = null;
            this.pqKemKeyPair = null;
            try { localStorage.removeItem('vibe_self_encryption_key'); } catch (e) {}
            await this.storage.clearAll();
            console.log('[E2EE] All data cleared');
        }

        /**
         * v3.7.0: Generate only one-time prekeys (for replenishment)
         * @param {number} count - Number of OTPs to generate (default 100)
         * @returns {Promise<Array>} - Array of OTPs to upload to server
         */
        async generateOneTimePreKeysOnly(count = 100) {
            console.log('[E2EE] Generating', count, 'new one-time prekeys...');
            
            // КАО#377: derive ids from the clock, not from the remaining COUNT. `otpCount * 10` shrinks as
            // prekeys are consumed, so a later batch could reuse ids an earlier batch already issued — and
            // saveOneTimePreKeys() `put`s by id, silently overwriting the SECRET half of an unused prekey
            // whose PUBLIC half the server still hands out. Every X3DH using that prekey would then derive a
            // different shared secret and fail with an opaque AES-GCM error. This mirrors the scheme already
            // proven in checkAndReplenishPreKeys (startId = Date.now()), which is monotonic by construction.
            const startId = Date.now();
            const newOTPs = X3DH.generateOneTimePreKeys(startId, count);
            
            // Save to local storage
            await this.storage.saveOneTimePreKeys(newOTPs);
            
            // Return public keys for upload
            return newOTPs.map(k => ({
                id: k.id,
                key: Utils.toBase64(k.keyPair.publicKey)
            }));
        }

        /**
         * v3.7.0: Rotate signed prekey
         * Generates new SPK and keeps the old one for in-flight messages
         * @returns {Promise<Object>} - Bundle with new and previous SPK for upload
         */
        async rotateSignedPreKey() {
            console.log('[E2EE] Rotating signed prekey...');
            
            // Get current signed prekey
            const currentSPK = this.signedPreKey;
            const currentSPKId = currentSPK ? currentSPK.id : 0;
            
            // Generate new signed prekey with incremented ID
            const newSPK = await X3DH.generateSignedPreKey(currentSPKId + 1, this.signingKeyPair);
            
            // Save previous SPK for in-flight messages (if exists)
            if (currentSPK) {
                await this.storage.savePreviousSignedPreKey(currentSPK);
            }
            
            // Update current SPK
            this.signedPreKey = newSPK;
            await this.storage.saveSignedPreKey(newSPK);
            
            // Build bundle for upload
            const bundle = {
                identity_key: Utils.toBase64(this.identityKeyPair.publicKey),
                signed_prekey_id: newSPK.id,
                signed_prekey: Utils.toBase64(newSPK.keyPair.publicKey),
                signed_prekey_signature: Utils.toBase64(newSPK.signature),
                one_time_prekeys: [],  // Don't change OTPs during rotation
                signing_public_key: Utils.toBase64(this.signingKeyPair.publicKey),  // v3.11.8
            };
            
            // Include previous SPK info
            if (currentSPK) {
                bundle.previous_signed_prekey_id = currentSPK.id;
                bundle.previous_signed_prekey = Utils.toBase64(currentSPK.keyPair.publicKey);
                bundle.previous_signed_prekey_signature = Utils.toBase64(currentSPK.signature);
            }
            
            console.log('[E2EE] Signed prekey rotated. New ID:', newSPK.id);
            return bundle;
        }

        /**
         * v3.7.27: Encrypt message for self (multi-device sync)
         * Uses shared self-encryption key (same across all devices)
         * @param {string} plaintext - Message text
         * @returns {Promise<string>} - Base64 encoded encrypted data
         */
        async encryptForSelf(plaintext) {
            if (!this.selfEncryptionKey) {
                console.warn('[E2EE] No self-encryption key available, skipping encryptForSelf');
                return null;
            }
            
            // Encrypt with AES-GCM using shared self-encryption key
            const plaintextBytes = Utils.stringToBytes(plaintext);
            const encResult = await AesGcm.encrypt(plaintextBytes, this.selfEncryptionKey);
            
            // Pack: nonce + ciphertext
            const packed = new Uint8Array(encResult.nonce.length + encResult.ciphertext.length);
            packed.set(encResult.nonce, 0);
            packed.set(encResult.ciphertext, encResult.nonce.length);
            return Utils.toBase64(packed);
        }

        /**
         * v3.7.27: Decrypt message encrypted for self
         * @param {string} encryptedBase64 - Base64 encoded encrypted data
         * @returns {Promise<string>} - Decrypted plaintext
         */
        async decryptForSelf(encryptedBase64) {
            if (!this.selfEncryptionKey) {
                throw new Error("No self-encryption key available");
            }
            
            // Unpack
            const packed = Utils.fromBase64(encryptedBase64);
            const nonce = packed.slice(0, 12);
            const ciphertext = packed.slice(12);
            
            // Decrypt with shared self-encryption key
            const plaintext = await AesGcm.decrypt(ciphertext, nonce, this.selfEncryptionKey);
            return Utils.bytesToString(plaintext);
        }
        
        /**
         * v3.7.27: Load or create self-encryption key
         * Called after generateKeyBundle to ensure self-key exists
         * @param {Function} apiCall - Function to make API calls (passed from app.js)
         */
        async ensureSelfEncryptionKey(apiCall) {
            // First check localStorage
            const storedKey = localStorage.getItem('vibe_self_encryption_key');
            if (storedKey) {
                this.selfEncryptionKey = Utils.fromBase64(storedKey);
                console.log('[E2EE] Using existing self-encryption key from localStorage');
                return;
            }
            
            // Try to load from server (encrypted with wrapping key)
            try {
                const response = await apiCall('/keys/self-key');
                if (response.ok) {
                    const data = await response.json();
                    if (data.has_key && data.self_encryption_key) {
                        // Server has wrapped key — unwrap it
                        const serverBlob = Utils.fromBase64(data.self_encryption_key);
                        const isLegacy = (serverBlob.length === 32);
                        const unwrapped = await this._unwrapSelfKey(data.self_encryption_key);
                        if (unwrapped) {
                            this.selfEncryptionKey = unwrapped;
                            localStorage.setItem('vibe_self_encryption_key', Utils.toBase64(unwrapped));
                            console.log('[E2EE] Loaded and unwrapped self-encryption key from server');
                            
                            // Re-wrap legacy plaintext keys so server no longer stores cleartext
                            if (isLegacy) {
                                try {
                                    const wrappedKey = await this._wrapSelfKey(unwrapped);
                                    await apiCall('/keys/self-key/rewrap', {
                                        method: 'POST',
                                        headers: { 'Content-Type': 'application/json' },
                                        body: JSON.stringify({ self_encryption_key: wrappedKey })
                                    });
                                    console.log('[E2EE] Re-wrapped legacy self-key on server ✓');
                                } catch (e) {
                                    console.warn('[E2EE] Failed to re-wrap legacy self-key:', e);
                                }
                            }
                            return;
                        } else {
                            console.warn('[E2EE] Failed to unwrap server self-key (identity key may have changed)');
                        }
                    }
                }
            } catch (e) {
                console.warn('[E2EE] Failed to load self-key from server:', e);
            }
            
            // Generate new key
            this.selfEncryptionKey = Utils.randomBytes(32);
            const keyBase64 = Utils.toBase64(this.selfEncryptionKey);
            localStorage.setItem('vibe_self_encryption_key', keyBase64);
            console.log('[E2EE] Generated new self-encryption key');
            
            // Wrap and save to server
            try {
                const wrappedKey = await this._wrapSelfKey(this.selfEncryptionKey);
                const response = await apiCall('/keys/self-key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ self_encryption_key: wrappedKey })
                });
                if (response.ok) {
                    const data = await response.json();
                    if (data.status === 'exists' && data.self_encryption_key) {
                        // Server already had a key - try to unwrap that
                        const unwrapped = await this._unwrapSelfKey(data.self_encryption_key);
                        if (unwrapped) {
                            this.selfEncryptionKey = unwrapped;
                            localStorage.setItem('vibe_self_encryption_key', Utils.toBase64(unwrapped));
                            console.log('[E2EE] Server already had self-key, unwrapped and using it');
                        } else {
                            // v3.11.9: Server key is stale (e.g. after reset) — force overwrite
                            console.warn('[E2EE] Server self-key stale, overwriting with new wrapped key');
                            try {
                                await apiCall('/keys/self-key/rewrap', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ self_encryption_key: wrappedKey })
                                });
                                console.log('[E2EE] Overwrote stale server self-key ✓');
                            } catch (e2) {
                                console.warn('[E2EE] Failed to overwrite stale self-key:', e2);
                            }
                        }
                    } else {
                        console.log('[E2EE] Saved wrapped self-encryption key to server');
                    }
                }
            } catch (e) {
                console.warn('[E2EE] Failed to save self-key to server:', e);
            }
        }

        /**
         * v3.11.8: Wrap (encrypt) self-encryption key using identity-derived wrapping key.
         * Returns base64 string of nonce(12) + ciphertext(32+16).
         */
        async _wrapSelfKey(selfKey) {
            // v3.11.9: No plaintext fallback — wrapping failure is a hard error.
            // If identity key is unavailable, caller must handle the error.
            const wrappingKey = await this._deriveWrappingKey();
            const result = await AesGcm.encrypt(selfKey, wrappingKey);
            // Combine nonce + ciphertext for storage
            const combined = Utils.concat(result.nonce, result.ciphertext);
            const wrapped = Utils.toBase64(combined);
            // Sanity check: wrapped blob must be 60 bytes (12 nonce + 32 key + 16 tag)
            if (combined.length !== 60) {
                throw new Error(`[E2EE] Unexpected wrapped key length: ${combined.length}, expected 60`);
            }
            return wrapped;
        }

        /**
         * v3.11.8: Unwrap (decrypt) self-encryption key.
         * @param {string} wrappedBase64 - base64 of nonce(12) + ciphertext
         * @returns {Uint8Array|null} - unwrapped key or null on failure
         */
        async _unwrapSelfKey(wrappedBase64) {
            try {
                const combined = Utils.fromBase64(wrappedBase64);
                // If it's exactly 32 bytes, it's a legacy unencrypted key
                if (combined.length === 32) {
                    console.log('[E2EE] Legacy unencrypted self-key detected, will re-wrap on next save');
                    return combined;
                }
                // Expected: 12 (nonce) + 32+16 (AES-GCM ciphertext+tag) = 60 bytes
                if (combined.length < 28) {
                    console.warn('[E2EE] Self-key blob too short:', combined.length);
                    return null;
                }
                const nonce = combined.slice(0, 12);
                const ciphertext = combined.slice(12);
                const wrappingKey = await this._deriveWrappingKey();
                return await AesGcm.decrypt(ciphertext, nonce, wrappingKey);
            } catch (e) {
                console.error('[E2EE] Failed to unwrap self-key:', e);
                return null;
            }
        }

        /**
         * v3.11.8: Derive a wrapping key from identity secret key via HKDF.
         * This ensures only the holder of the identity private key can decrypt.
         */
        async _deriveWrappingKey() {
            if (!this.identityKeyPair || !this.identityKeyPair.secretKey) {
                throw new Error('Identity key pair not available for wrapping key derivation');
            }
            return await HKDF.deriveKey(
                this.identityKeyPair.secretKey,
                null,
                Utils.stringToBytes('VibeMessenger-SelfKeyWrap-v1')
            );
        }
    }

    // ============================================================================
    // SECTION 11: Export Public API
    // ============================================================================

    // Create singleton instance
    const vibeE2EE = new VibeE2EE();

    // Export to global scope
    global.VibeCrypto = {
        // Main E2EE interface
        e2ee: vibeE2EE,
        
        // Initialize (call on app start)
        init: async function() {
            return vibeE2EE.init();
        },
        
        // Check if we have keys
        hasKeys: function() {
            return vibeE2EE.hasKeys();
        },
        
        // Generate new key bundle (call on registration)
        generateKeyBundle: async function(otpCount) {
            return vibeE2EE.generateKeyBundle(otpCount);
        },
        
        // Get our identity public key
        getIdentityPublicKey: function() {
            return vibeE2EE.getIdentityPublicKey();
        },
        
        // Encrypt message for 1:1 chat
        encryptMessage: async function(recipientId, plaintext, theirBundle) {
            return vibeE2EE.encryptMessage(recipientId, plaintext, theirBundle);
        },
        
        // Decrypt message from 1:1 chat
        decryptMessage: async function(senderId, encryptedPayload) {
            return vibeE2EE.decryptMessage(senderId, encryptedPayload);
        },
        
        // Encrypt message for group
        encryptGroupMessage: async function(groupId, plaintext) {
            return vibeE2EE.encryptGroupMessage(groupId, plaintext);
        },
        
        // Process group key distribution
        processGroupKeyDistribution: async function(groupId, senderId, distribution) {
            return vibeE2EE.processGroupKeyDistribution(groupId, senderId, distribution);
        },
        
        // Decrypt group message
        decryptGroupMessage: async function(groupId, senderId, encryptedPayload) {
            return vibeE2EE.decryptGroupMessage(groupId, senderId, encryptedPayload);
        },
        
        // Get group key distribution for new member
        getGroupKeyDistribution: async function(groupId) {
            return vibeE2EE.getGroupKeyDistribution(groupId);
        },
        
        // Encrypt file
        encryptFile: async function(data) {
            return vibeE2EE.encryptFile(data);
        },
        
        // Decrypt file
        decryptFile: async function(encryptedData, key) {
            return vibeE2EE.decryptFile(encryptedData, key);
        },

        // КАО#230 (SER#18): symmetric text encrypt/decrypt with a shared key (poll content E2EE)
        encryptWithKey: async function(text, keyBase64) {
            return vibeE2EE.encryptWithKey(text, keyBase64);
        },
        decryptWithKey: async function(base64, keyBase64) {
            return vibeE2EE.decryptWithKey(base64, keyBase64);
        },
        generateContentKey: function() {
            return vibeE2EE.generateContentKey();
        },

        // Check and replenish pre-keys
        checkAndReplenishPreKeys: async function(threshold, count) {
            return vibeE2EE.checkAndReplenishPreKeys(threshold, count);
        },
        
        // Delete session
        deleteSession: async function(recipientId) {
            return vibeE2EE.deleteSession(recipientId);
        },
        
        // v3.8.6: Check if we have a session with user
        hasSession: async function(recipientId) {
            return vibeE2EE.hasSession(recipientId);
        },
        
        // Delete group session
        deleteGroupSession: async function(groupId) {
            return vibeE2EE.deleteGroupSession(groupId);
        },
        
        // Clear all sessions (keep identity keys)
        clearAllSessions: async function() {
            return vibeE2EE.clearAllSessions();
        },
        
        // Clear all data (logout)
        clearAll: async function() {
            return vibeE2EE.clearAll();
        },
        // v3.7.0: Generate only one-time prekeys (for replenishment)
        generateOneTimePreKeysOnly: async function(count) {
            return vibeE2EE.generateOneTimePreKeysOnly(count);
        },
        // v3.7.0: Rotate signed prekey
        rotateSignedPreKey: async function() {
            return vibeE2EE.rotateSignedPreKey();
        },
        // v3.7.1: Encrypt/decrypt for self (multi-device sync)
        encryptForSelf: async function(plaintext) {
            return vibeE2EE.encryptForSelf(plaintext);
        },
        decryptForSelf: async function(encryptedBase64) {
            return vibeE2EE.decryptForSelf(encryptedBase64);
        },
        // v3.7.27: Ensure self-encryption key exists (call after E2EE init)
        ensureSelfEncryptionKey: async function(apiCall) {
            return vibeE2EE.ensureSelfEncryptionKey(apiCall);
        },
        // v3.7.27: Check if self-encryption key is available
        hasSelfEncryptionKey: function() {
            return !!vibeE2EE.selfEncryptionKey;
        },
        
        // Utility functions
        Utils: Utils,
        
        // v3.11.0: Post-quantum KEM status
        hasPqKem: function() {
            return typeof PQKEM !== 'undefined' && PQKEM.isAvailable();
        },
        isPqxdhEnabled: function() {
            return vibeE2EE.pqKemKeyPair !== null;
        },
        getPqKemInfo: function() {
            return {
                available: typeof PQKEM !== 'undefined' && PQKEM.isAvailable(),
                hasKeyPair: !!vibeE2EE.pqKemKeyPair,
                algorithm: 'ML-KEM-768',
                standard: 'FIPS 203'
            };
        },
        
        // Low-level crypto (for advanced use)
        AesGcm: AesGcm,
        HKDF: HKDF,
        nacl: nacl
    };

    console.log('[VibeCrypto] Module loaded (v2.0.0 PQXDH)');

})(typeof window !== 'undefined' ? window : global);
