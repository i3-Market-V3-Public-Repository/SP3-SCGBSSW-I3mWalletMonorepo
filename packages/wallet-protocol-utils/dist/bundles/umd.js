(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.walletProtocolUtils = {}));
})(this, (function (exports) { 'use strict';

    var styleCss = ".__WALLET_PROTOCOL_OVERLAY__ {\n    position: absolute;\n    display: flex;\n    height: 100%;\n    width: 100%;\n    top: 0;\n    left: 0;\n    align-items: center;\n    justify-content: center;\n    background-color: #000000AA;\n    font-family: 'sans-serif';\n    color: #202531;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MODAL__ {\n    display: flex;\n    flex-direction: column;\n    align-items: center;\n    justify-content: center;\n    border: 2px solid #1A1E27;\n    border-radius: 5px;\n    padding: 10px 20px;\n    background-image: linear-gradient(to bottom left, white, #D2D6E1);\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_TITLE__ {\n    font-weight: bold;\n    padding: 5px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_MESSAGE__ {\n    opacity: 0.5;\n    padding: 5px;\n    font-size: 15px\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT_BOX__ {\n    display: flex;\n    margin: 20px;\n    height: 32px;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_INPUT__ {\n    border-radius: 3px;\n    border-top-right-radius: 0;\n    border-bottom-right-radius: 0;\n    outline: none;\n    padding: 5px;\n    border: 2px solid #1A1E27;\n    border-right: none;\n}\n\n.__WALLET_PROTOCOL_OVERLAY__ .__WALLET_BUTTON__ {\n    height: 100%;\n    padding: 5px;\n    border-radius: 3px;\n    border: 2px solid #1A1E27;\n    border-top-left-radius: 0;\n    border-bottom-left-radius: 0;\n    cursor: pointer;\n}\n";

    const defaultOptions = {
        overlayClass: 'wallet-protocol-overlay',
        modalClass: 'wallet-modal',
        titleClass: 'wallet-title',
        messageClass: 'wallet-message',
        inputBoxClass: 'wallet-input-box',
        inputClass: 'wallet-input',
        buttonClass: 'wallet-button'
    };
    const openModal = (opts) => {
        const options = Object.assign({}, opts, defaultOptions);
        return new Promise(resolve => {
            const overlay = document.createElement('div');
            document.body.appendChild(overlay);
            overlay.className = options.overlayClass;
            const style = document.createElement('style');
            overlay.appendChild(style);
            style.innerText = styleCss
                .replace(/__WALLET_PROTOCOL_OVERLAY__/g, options.overlayClass)
                .replace(/__WALLET_MODAL__/g, options.modalClass)
                .replace(/__WALLET_TITLE__/g, options.titleClass)
                .replace(/__WALLET_MESSAGE__/g, options.messageClass)
                .replace(/__WALLET_INPUT_BOX__/g, options.inputBoxClass)
                .replace(/__WALLET_INPUT__/g, options.inputClass)
                .replace(/__WALLET_BUTTON__/g, options.buttonClass);
            const modal = document.createElement('div');
            overlay.appendChild(modal);
            modal.className = options.modalClass;
            const title = document.createElement('span');
            modal.appendChild(title);
            title.className = options.titleClass;
            title.innerText = 'Connecting to your wallet...';
            const message = document.createElement('span');
            modal.appendChild(message);
            message.className = options.messageClass;
            message.innerText = 'Set up your wallet on pairing mode and put the PIN here';
            const inputBox = document.createElement('div');
            modal.appendChild(inputBox);
            inputBox.className = options.inputBoxClass;
            const pinInput = document.createElement('input');
            inputBox.appendChild(pinInput);
            pinInput.className = options.inputClass;
            pinInput.setAttribute('placeholder', 'pin...');
            const pairButton = document.createElement('button');
            inputBox.appendChild(pairButton);
            pairButton.className = options.buttonClass;
            pairButton.innerText = 'Syncronize';
            const close = (value) => {
                document.body.removeChild(overlay);
                resolve(value ?? '');
            };
            pairButton.addEventListener('click', () => close(pinInput.value));
            overlay.addEventListener('click', (ev) => {
                if (ev.target === overlay) {
                    close();
                }
            });
        });
    };

    const base64Encode = (bytes) => {
        const CHUNK_SIZE = 0x8000;
        const arr = [];
        for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
            // @ts-expect-error
            arr.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE)));
        }
        return btoa(arr.join(''));
    };
    const base64Decode = (encoded) => {
        return new Uint8Array(atob(encoded)
            .split('')
            .map((c) => c.charCodeAt(0)));
    };

    /**
     * Base64url for both node.js and brwser javascript. It can work with ArrayBuffer|TypedArray|Buffer
     *
     * @remarks Bowser code obtained from https://github.com/panva/jose/blob/main/src/runtime/browser/base64url.ts
     * @packageDocumentation
     */
    /**
     * Base64Url encoding of a buffer input or a string (UTF16 in browsers, UTF8 in node)
     * @param input
     * @param urlsafe - if true Base64 URL encoding is used ('+' and '/' are replaced by '-', '_')
     * @param padding - if false, padding (trailing '=') is removed
     * @returns a string with the base64-encoded representation of the input
     */
    function encode(input, urlsafe = false, padding = true) {
        let base64 = '';
        {
            const bytes = (typeof input === 'string')
                ? (new TextEncoder()).encode(input)
                : new Uint8Array(input);
            base64 = base64Encode(bytes);
        }
        if (urlsafe)
            base64 = base64ToBase64url(base64);
        if (!padding)
            base64 = removeBase64Padding(base64);
        return base64;
    }
    /**
     * Base64url decoding (binary output) of base64url-encoded string
     * @param base64 - a base64 string
     * @param stringOutput - if true a UTF16 (browser) or UTF8 (node) string is returned
     * @returns a buffer or unicode string
     */
    function decode(base64, stringOutput = false) {
        {
            let urlsafe = false;
            if (/^[0-9a-zA-Z_-]+={0,2}$/.test(base64)) {
                urlsafe = true;
            }
            else if (!/^[0-9a-zA-Z+/]*={0,2}$/.test(base64)) {
                throw new Error('Not a valid base64 input');
            }
            if (urlsafe)
                base64 = base64urlToBase64(base64);
            const bytes = base64Decode(base64);
            return stringOutput
                ? (new TextDecoder()).decode(bytes)
                : bytes;
        }
    }
    function base64ToBase64url(base64) {
        return base64.replace(/\+/g, '-').replace(/\//g, '_');
    }
    function base64urlToBase64(base64url) {
        return base64url.replace(/-/g, '+').replace(/_/g, '/').replace(/=/g, '');
    }
    function removeBase64Padding(str) {
        return str.replace(/=/g, '');
    }

    /**
     * PBKDF2 following RFC 2898 using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as the PRF
     *
     * @packageDocumentation
     */
    const HASHALGS = {
        'SHA-1': { outputLength: 20, blockSize: 64 },
        'SHA-256': { outputLength: 32, blockSize: 64 },
        'SHA-384': { outputLength: 48, blockSize: 128 },
        'SHA-512': { outputLength: 64, blockSize: 128 }
    };
    /**
      * Derives a key using using PBKDF2-HMAC algorithm
      * PBKDF2 (RFC 2898) using HMAC (with SHA-1, SHA-256, SHA-384, SHA-512) as
      * the PRF (RFC2898)
      *
      * @param P - a unicode string with a password
      * @param S - a salt. This should be a random or pseudo-random value of at least 16 bytes. You can easily get one with crypto.getRandomValues(new Uint8Array(16))
      * @param c - iteration count, a positive integer
      * @param dkLen - intended length in octets of the derived key
      * @param hash - hash function to use for the HMAC. One of 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'
      *
      * @returns an ArrayBuffer with the derived key
      */
    function pbkdf2Hmac(P, S, c, dkLen, hash = 'SHA-256') {
        return new Promise((resolve, reject) => {
            if (!(hash in HASHALGS)) {
                reject(new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS).toString()}`));
            }
            if (typeof P === 'string')
                P = new TextEncoder().encode(P); // encode S as UTF-8
            else if (P instanceof ArrayBuffer)
                P = new Uint8Array(P);
            else if (!ArrayBuffer.isView(P))
                reject(RangeError('P should be string, ArrayBuffer, TypedArray, DataView'));
            if (typeof S === 'string')
                S = new TextEncoder().encode(S); // encode S as UTF-8
            else if (S instanceof ArrayBuffer)
                S = new Uint8Array(S);
            else if (ArrayBuffer.isView(S))
                S = new Uint8Array(S.buffer, S.byteOffset, S.byteLength);
            else
                reject(RangeError('S should be string, ArrayBuffer, TypedArray, DataView'));
            {
                crypto.subtle.importKey('raw', P, 'PBKDF2', false, ['deriveBits']).then((PKey) => {
                    const params = { name: 'PBKDF2', hash: hash, salt: S, iterations: c }; // pbkdf2 params
                    crypto.subtle.deriveBits(params, PKey, dkLen * 8).then(derivedKey => resolve(derivedKey), 
                    // eslint-disable-next-line node/handle-callback-err
                    err => {
                        // Try our native implementation if browser's native one fails (firefox one fails when dkLen > 256)
                        _pbkdf2(P, S, c, dkLen, hash).then(derivedKey => resolve(derivedKey), error => reject(error));
                    });
                }, err => reject(err));
            }
        });
    }
    async function _pbkdf2(P, S, c, dkLen, hash) {
        if (!(hash in HASHALGS)) {
            throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(HASHALGS).toString()}`);
        }
        if (!Number.isInteger(c) || c <= 0)
            throw new RangeError('c must be a positive integer');
        /*
         1.  If dkLen > (2^32 - 1) * hLen, output "derived key too long"
                 and stop.
         */
        const hLen = HASHALGS[hash].outputLength;
        if (!Number.isInteger(dkLen) || dkLen <= 0 || dkLen >= (2 ** 32 - 1) * hLen)
            throw new RangeError('dkLen must be a positive integer < (2 ** 32 - 1) * hLen');
        /*
         2.  Let l be the number of hLen-octet blocks in the derived key,
             rounding up, and let r be the number of octets in the last
             block:
               l = CEIL (dkLen / hLen)
               r = dkLen - (l - 1) * hLen
         */
        const l = Math.ceil(dkLen / hLen);
        const r = dkLen - (l - 1) * hLen;
        /*
         3.  For each block of the derived key apply the function F defined
             below to the password P, the salt S, the iteration count c,
             and the block index to compute the block:
      
                       T_1 = F (P, S, c, 1) ,
                       T_2 = F (P, S, c, 2) ,
                       ...
                       T_l = F (P, S, c, l) ,
         */
        const T = new Array(l);
        if (P.byteLength === 0)
            P = new Uint8Array(HASHALGS[hash].blockSize); // HMAC does not accept an empty ArrayVector
        const Pkey = await crypto.subtle.importKey('raw', P, {
            name: 'HMAC',
            hash: { name: hash }
        }, true, ['sign']);
        const HMAC = async function (key, arr) {
            const hmac = await crypto.subtle.sign('HMAC', key, arr);
            return new Uint8Array(hmac);
        };
        for (let i = 0; i < l; i++) {
            T[i] = await F(Pkey, S, c, i + 1);
        }
        /*
             where the function F is defined as the exclusive-or sum of the
             first c iterates of the underlying pseudorandom function PRF
             applied to the password P and the concatenation of the salt S
             and the block index i:
      
                       F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
      
             where
                       U_1 = PRF (P, S || INT (i)) ,
                       U_2 = PRF (P, U_1) ,
                       ...
                       U_c = PRF (P, U_{c-1}) .
      
             Here, INT (i) is a four-octet encoding of the integer i, most
             significant octet first.
         */
        /**
          *
          * @param P - password
          * @param S - salt
          * @param c - iterations
          * @param i - block index
          */
        async function F(P, S, c, i) {
            function INT(i) {
                const buf = new ArrayBuffer(4);
                const view = new DataView(buf);
                view.setUint32(0, i, false);
                return new Uint8Array(buf);
            }
            const Uacc = await HMAC(P, concat(S, INT(i)));
            let UjMinus1 = Uacc;
            for (let j = 1; j < c; j++) {
                UjMinus1 = await HMAC(P, UjMinus1);
                xorMe(Uacc, UjMinus1);
            }
            return Uacc;
        }
        /*
         4.  Concatenate the blocks and extract the first dkLen octets to
             produce a derived key DK:
                       DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
      
         5.  Output the derived key DK.
         */
        T[l - 1] = T[l - 1].slice(0, r);
        return concat(...T).buffer;
    }
    function concat(...arrs) {
        // sum of individual array lengths
        const totalLength = arrs.reduce((acc, value) => acc + value.length, 0);
        if (arrs.length === 0)
            throw new RangeError('Cannot concat no arrays');
        const result = new Uint8Array(totalLength);
        // for each array - copy it over result
        // next array is copied right after the previous one
        let length = 0;
        for (const array of arrs) {
            result.set(array, length);
            length += array.length;
        }
        return result;
    }
    function xorMe(arr1, arr2) {
        for (let i = 0; i < arr1.length; i++) {
            arr1[i] ^= arr2[i];
        }
    }

    function isObject(val) {
        return (val != null) && (typeof val === 'object') && !(Array.isArray(val));
    }
    function objectToArraySortedByKey(obj) {
        if (!isObject(obj) && !Array.isArray(obj)) {
            return obj;
        }
        if (Array.isArray(obj)) {
            return obj.map((item) => {
                if (Array.isArray(item) || isObject(item)) {
                    return objectToArraySortedByKey(item);
                }
                return item;
            });
        }
        // if it is an object convert to array and sort
        return Object.keys(obj) // eslint-disable-line
            .sort()
            .map((key) => {
            return [key, objectToArraySortedByKey(obj[key])];
        });
    }
    /**
     * If the input object is not an Array, this function converts the object to an array, all the key-values to 2-arrays [key, value] and then sort the array by the keys. All the process is done recursively so objects inside objects or arrays are also ordered. Once the array is created the method returns the JSON.stringify() of the sorted array.
     *
     * @param obj the object
     *
     * @returns a JSON stringify of the created sorted array
     */
    function hashable (obj) {
        return JSON.stringify(objectToArraySortedByKey(obj));
    }

    /**
     * My module description. Please update with your module data.
     *
     * @remarks
     * This module runs perfectly in node.js and browsers
     *
     * @packageDocumentation
     */
    /**
      * Returns a string with a hexadecimal representation of the digest of the input object using a given hash algorithm.
      * It first creates an array of the object values ordered by the object keys (using hashable(obj));
      * then, it JSON.stringify-es it; and finally it hashes it.
      *
      * @param obj - An Object
      * @param algorithm - For compatibility with browsers it should be 'SHA-1', 'SHA-256', 'SHA-384' and 'SHA-512'.
      *
      * @throws {@link RangeError} if an invalid hash algorithm is selected.
      *
      * @returns a promise that resolves to a string with hexadecimal content.
      */
    function digest(obj, algorithm = 'SHA-256') {
        const algorithms = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
        if (!algorithms.includes(algorithm)) {
            throw RangeError(`Valid hash algorithm values are any of ${JSON.stringify(algorithms)}`);
        }
        return (async function (obj, algorithm) {
            const encoder = new TextEncoder();
            const hashInput = encoder.encode(hashable(obj)).buffer;
            let digest = '';
            {
                const buf = await crypto.subtle.digest(algorithm, hashInput);
                const h = '0123456789abcdef';
                (new Uint8Array(buf)).forEach((v) => {
                    digest += h[v >> 4] + h[v & 15];
                });
            }
            /* eslint-enable no-lone-blocks */
            return digest;
        })(obj, algorithm);
    }

    const PORT_LENGTH = 12;
    const DEFAULT_RANDOM_LENGTH = 36;
    const DEFAULT_TIMEOUT = 30000;
    const PORT_SPACE = 2 ** PORT_LENGTH;
    const INITIAL_PORT = 29170;
    const NONCE_LENGTH = 128;
    const COMMITMENT_LENGTH = 256;

    var protocolConstants = /*#__PURE__*/Object.freeze({
        __proto__: null,
        PORT_LENGTH: PORT_LENGTH,
        DEFAULT_RANDOM_LENGTH: DEFAULT_RANDOM_LENGTH,
        DEFAULT_TIMEOUT: DEFAULT_TIMEOUT,
        PORT_SPACE: PORT_SPACE,
        INITIAL_PORT: INITIAL_PORT,
        NONCE_LENGTH: NONCE_LENGTH,
        COMMITMENT_LENGTH: COMMITMENT_LENGTH
    });

    const RPC_URL_PATH = '.well-known/wallet-protocol';

    var httpConstants = /*#__PURE__*/Object.freeze({
        __proto__: null,
        RPC_URL_PATH: RPC_URL_PATH
    });

    ({
        ...protocolConstants,
        ...httpConstants
    });
    class BaseRandom {
        async randomFill(buffer, start, size) {
            throw new Error('not implemented');
        }
        async randomFillBits(buffer, start, size) {
            const byteLen = Math.ceil(size / 8);
            const randomBytes = new Uint8Array(byteLen);
            await this.randomFill(randomBytes, 0, byteLen);
            bufferUtils.insertBits(randomBytes, buffer, 0, start, size);
        }
    }
    class BaseCipher {
        constructor(algorithm, key) {
            this.algorithm = algorithm;
            this.key = key;
        }
        async encrypt(payload) {
            throw new Error('not implemented');
        }
        async decrypt(ciphertext) {
            throw new Error('not implemented');
        }
    }

    class BrowserRandom extends BaseRandom {
        async randomFill(buffer, start, size) {
            const newBuffer = new Uint8Array(size);
            crypto.getRandomValues(newBuffer);
            for (let i = 0; i < size; i++) {
                buffer[start + i] = newBuffer[i];
            }
        }
    }
    const random = new BrowserRandom();

    const NODE_TO_BROWSER_CIPHER_ALGORITHMS = {
        'aes-256-gcm': {
            name: 'AES-GCM',
            tagLength: 16 * 8
        }
    };
    class Cipher extends BaseCipher {
        async encrypt(message) {
            const iv = new Uint8Array(12);
            await random.randomFill(iv, 0, iv.length);
            const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm];
            const cryptoKey = await crypto.subtle.importKey('raw', this.key, alg, false, ['encrypt']);
            const ciphertext = await crypto.subtle.encrypt({
                ...alg,
                iv
            }, cryptoKey, message);
            const buffers = [];
            buffers.push(iv);
            buffers.push(new Uint8Array(ciphertext));
            return bufferUtils.join(...buffers);
        }
        async decrypt(cryptosecuence) {
            const sizes = [];
            switch (this.algorithm) {
                case 'aes-256-gcm':
                    sizes[0] = 12;
                    break;
            }
            sizes[1] = cryptosecuence.length - sizes[0];
            const [iv, ciphertext] = bufferUtils.split(cryptosecuence, ...sizes);
            const alg = NODE_TO_BROWSER_CIPHER_ALGORITHMS[this.algorithm];
            const cryptoKey = await crypto.subtle.importKey('raw', this.key, alg, false, ['decrypt']);
            const message = await crypto.subtle.decrypt({
                ...alg,
                iv
            }, cryptoKey, ciphertext);
            return new Uint8Array(message);
        }
    }

    const format = {
        utf2U8Arr: (text) => {
            return new TextEncoder().encode(text);
        },
        u8Arr2Utf: (arr) => {
            return new TextDecoder().decode(arr);
        },
        num2U8Arr: (num, len) => {
            if (len === undefined) {
                len = 1;
                while (2 ** (len * 8) < num) {
                    len++;
                }
            }
            const arr = new Uint8Array(len);
            let rest = num;
            for (let i = len - 1; i >= 0; i--) {
                const nextRest = rest >> 8;
                const num = rest - (nextRest << 8);
                arr[i] = num;
                rest = nextRest;
            }
            return arr;
        },
        u8Arr2Num: (buffer) => {
            let num = 0;
            for (let i = 0; i < buffer.length; i++) {
                num += buffer[i] << ((buffer.length - 1) - i);
            }
            return num;
        },
        hex2U8Arr: (hex) => {
            const match = hex.match(/.{1,2}/g);
            if (match === null) {
                throw new Error(`not a hex: ${hex}`);
            }
            return new Uint8Array(match.map(byte => parseInt(byte, 16)));
        },
        u8Arr2Hex: (arr) => {
            return arr.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
        },
        u8Arr2Base64: (arr) => {
            return encode(arr, true, false);
        },
        base642U8Arr: (b64) => {
            return decode(b64, false);
        }
    };

    const bufferUtils = {
        join: (...list) => {
            const size = list.reduce((a, b) => a + b.length, 0);
            const buffer = new Uint8Array(size);
            let accLen = 0;
            for (const el of list) {
                buffer.set(el, accLen);
                accLen += el.length;
            }
            return buffer;
        },
        split: (buffer, ...sizes) => {
            const list = [];
            let start = 0;
            for (const size of sizes) {
                list.push(buffer.slice(start, start + size));
                start += size;
            }
            return list;
        },
        insertBytes: (src, dst, fromStart, toStart, size) => {
            for (let i = 0; i < size; i++) {
                dst[i + toStart] = src[i + fromStart];
            }
        },
        insertBits: (src, dst, fromStart, toStart, size) => {
            let fromByteIndex = Math.floor(fromStart / 8);
            let fromBitIndex = fromStart % 8;
            let toByteIndex = Math.floor(toStart / 8);
            let toBitIndex = toStart % 8;
            let currFromByte = src[fromByteIndex] ?? 0;
            const deltaOffset = toBitIndex - fromBitIndex;
            for (let i = 0; i < size; i++) {
                let currBit;
                if (deltaOffset >= 0) {
                    currBit = ((currFromByte & (128 >> fromBitIndex)) << deltaOffset);
                }
                else {
                    currBit = ((currFromByte & (128 >> fromBitIndex)));
                }
                const bitSet = ((dst[toByteIndex] & ~(128 >> toBitIndex)) | currBit);
                dst[toByteIndex] = bitSet;
                fromBitIndex++;
                toBitIndex++;
                if (fromBitIndex >= 8) {
                    fromByteIndex++;
                    fromBitIndex = 0;
                    currFromByte = src[fromByteIndex] ?? 0;
                }
                if (toBitIndex >= 8) {
                    toByteIndex++;
                    toBitIndex = 0;
                }
            }
        },
        extractBits: (buf, start, size) => {
            const byteSize = Math.ceil(size / 8);
            const dst = new Uint8Array(byteSize);
            bufferUtils.insertBits(buf, dst, start, 0, size);
            return dst;
        }
    };

    const deriveKey = async (from, to, secret) => {
        const salt = new Uint8Array(16);
        const pbkdf2Input = new Uint8Array(32 * 3);
        const fromBuffer = format.hex2U8Arr(from);
        const toBuffer = format.hex2U8Arr(to);
        bufferUtils.insertBytes(secret, pbkdf2Input, 0, 0, 32);
        bufferUtils.insertBytes(fromBuffer, pbkdf2Input, 0, 32, 32);
        bufferUtils.insertBytes(toBuffer, pbkdf2Input, 0, 32 * 2, 32);
        const derivatedSecret = await pbkdf2Hmac(pbkdf2Input, salt, 1, 32);
        return new Uint8Array(derivatedSecret);
    };
    class MasterKey {
        constructor(port, from, to, na, nb, secret, encryptKey, decryptKey) {
            this.port = port;
            this.from = from;
            this.to = to;
            this.na = na;
            this.nb = nb;
            this.secret = secret;
            this.cipher = new Cipher('aes-256-gcm', encryptKey);
            this.decipher = new Cipher('aes-256-gcm', decryptKey);
        }
        async encrypt(message) {
            return await this.cipher.encrypt(message);
        }
        async decrypt(ciphertext) {
            return await this.decipher.decrypt(ciphertext);
        }
        toJSON() {
            return {
                from: this.from,
                to: this.to,
                port: this.port,
                na: format.u8Arr2Base64(this.na),
                nb: format.u8Arr2Base64(this.nb),
                secret: format.u8Arr2Base64(this.secret)
            };
        }
        async fromHash() {
            return await digest(this.from);
        }
        async toHash() {
            return await digest(this.to);
        }
        static async fromSecret(port, from, to, na, nb, secret) {
            const fromHash = await digest(from);
            const toHash = await digest(to);
            const encryptKey = await deriveKey(fromHash, toHash, secret);
            const decryptKey = await deriveKey(toHash, fromHash, secret);
            return new MasterKey(port, from, to, na, nb, secret, encryptKey, decryptKey);
        }
        static async fromJSON(data) {
            const na = format.base642U8Arr(data.na);
            const nb = format.base642U8Arr(data.nb);
            const secret = format.base642U8Arr(data.secret);
            return await this.fromSecret(data.port, data.from, data.to, na, nb, secret);
        }
    }

    class Session {
        constructor(transport, masterKey, code) {
            this.transport = transport;
            this.masterKey = masterKey;
            this.code = code;
        }
        async send(request) {
            return await this.transport.send(this.masterKey, this.code, request);
        }
        toJSON() {
            return {
                masterKey: this.masterKey.toJSON(),
                code: format.u8Arr2Hex(this.code)
            };
        }
        static async fromJSON(TransportOrConstructor, json) {
            const masterKey = await MasterKey.fromJSON(json.masterKey);
            const code = format.hex2U8Arr(json.code);
            let transport;
            if (typeof TransportOrConstructor === 'object') {
                transport = TransportOrConstructor;
            }
            else if (TransportOrConstructor instanceof Function) {
                transport = new TransportOrConstructor();
            }
            else {
                throw new Error('First param must be transport or constructor of transport');
            }
            return new Session(transport, masterKey, code);
        }
    }

    /******************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */
    /* global Reflect, Promise */

    var extendStatics = function(d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };

    function __extends(d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    }

    function __values(o) {
        var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
        if (m) return m.call(o);
        if (o && typeof o.length === "number") return {
            next: function () {
                if (o && i >= o.length) o = void 0;
                return { value: o && o[i++], done: !o };
            }
        };
        throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
    }

    function __read(o, n) {
        var m = typeof Symbol === "function" && o[Symbol.iterator];
        if (!m) return o;
        var i = m.call(o), r, ar = [], e;
        try {
            while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
        }
        catch (error) { e = { error: error }; }
        finally {
            try {
                if (r && !r.done && (m = i["return"])) m.call(i);
            }
            finally { if (e) throw e.error; }
        }
        return ar;
    }

    function __spreadArray(to, from, pack) {
        if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
            if (ar || !(i in from)) {
                if (!ar) ar = Array.prototype.slice.call(from, 0, i);
                ar[i] = from[i];
            }
        }
        return to.concat(ar || Array.prototype.slice.call(from));
    }

    function isFunction(value) {
        return typeof value === 'function';
    }

    function createErrorClass(createImpl) {
        var _super = function (instance) {
            Error.call(instance);
            instance.stack = new Error().stack;
        };
        var ctorFunc = createImpl(_super);
        ctorFunc.prototype = Object.create(Error.prototype);
        ctorFunc.prototype.constructor = ctorFunc;
        return ctorFunc;
    }

    var UnsubscriptionError = createErrorClass(function (_super) {
        return function UnsubscriptionErrorImpl(errors) {
            _super(this);
            this.message = errors
                ? errors.length + " errors occurred during unsubscription:\n" + errors.map(function (err, i) { return i + 1 + ") " + err.toString(); }).join('\n  ')
                : '';
            this.name = 'UnsubscriptionError';
            this.errors = errors;
        };
    });

    function arrRemove(arr, item) {
        if (arr) {
            var index = arr.indexOf(item);
            0 <= index && arr.splice(index, 1);
        }
    }

    var Subscription = (function () {
        function Subscription(initialTeardown) {
            this.initialTeardown = initialTeardown;
            this.closed = false;
            this._parentage = null;
            this._finalizers = null;
        }
        Subscription.prototype.unsubscribe = function () {
            var e_1, _a, e_2, _b;
            var errors;
            if (!this.closed) {
                this.closed = true;
                var _parentage = this._parentage;
                if (_parentage) {
                    this._parentage = null;
                    if (Array.isArray(_parentage)) {
                        try {
                            for (var _parentage_1 = __values(_parentage), _parentage_1_1 = _parentage_1.next(); !_parentage_1_1.done; _parentage_1_1 = _parentage_1.next()) {
                                var parent_1 = _parentage_1_1.value;
                                parent_1.remove(this);
                            }
                        }
                        catch (e_1_1) { e_1 = { error: e_1_1 }; }
                        finally {
                            try {
                                if (_parentage_1_1 && !_parentage_1_1.done && (_a = _parentage_1.return)) _a.call(_parentage_1);
                            }
                            finally { if (e_1) throw e_1.error; }
                        }
                    }
                    else {
                        _parentage.remove(this);
                    }
                }
                var initialFinalizer = this.initialTeardown;
                if (isFunction(initialFinalizer)) {
                    try {
                        initialFinalizer();
                    }
                    catch (e) {
                        errors = e instanceof UnsubscriptionError ? e.errors : [e];
                    }
                }
                var _finalizers = this._finalizers;
                if (_finalizers) {
                    this._finalizers = null;
                    try {
                        for (var _finalizers_1 = __values(_finalizers), _finalizers_1_1 = _finalizers_1.next(); !_finalizers_1_1.done; _finalizers_1_1 = _finalizers_1.next()) {
                            var finalizer = _finalizers_1_1.value;
                            try {
                                execFinalizer(finalizer);
                            }
                            catch (err) {
                                errors = errors !== null && errors !== void 0 ? errors : [];
                                if (err instanceof UnsubscriptionError) {
                                    errors = __spreadArray(__spreadArray([], __read(errors)), __read(err.errors));
                                }
                                else {
                                    errors.push(err);
                                }
                            }
                        }
                    }
                    catch (e_2_1) { e_2 = { error: e_2_1 }; }
                    finally {
                        try {
                            if (_finalizers_1_1 && !_finalizers_1_1.done && (_b = _finalizers_1.return)) _b.call(_finalizers_1);
                        }
                        finally { if (e_2) throw e_2.error; }
                    }
                }
                if (errors) {
                    throw new UnsubscriptionError(errors);
                }
            }
        };
        Subscription.prototype.add = function (teardown) {
            var _a;
            if (teardown && teardown !== this) {
                if (this.closed) {
                    execFinalizer(teardown);
                }
                else {
                    if (teardown instanceof Subscription) {
                        if (teardown.closed || teardown._hasParent(this)) {
                            return;
                        }
                        teardown._addParent(this);
                    }
                    (this._finalizers = (_a = this._finalizers) !== null && _a !== void 0 ? _a : []).push(teardown);
                }
            }
        };
        Subscription.prototype._hasParent = function (parent) {
            var _parentage = this._parentage;
            return _parentage === parent || (Array.isArray(_parentage) && _parentage.includes(parent));
        };
        Subscription.prototype._addParent = function (parent) {
            var _parentage = this._parentage;
            this._parentage = Array.isArray(_parentage) ? (_parentage.push(parent), _parentage) : _parentage ? [_parentage, parent] : parent;
        };
        Subscription.prototype._removeParent = function (parent) {
            var _parentage = this._parentage;
            if (_parentage === parent) {
                this._parentage = null;
            }
            else if (Array.isArray(_parentage)) {
                arrRemove(_parentage, parent);
            }
        };
        Subscription.prototype.remove = function (teardown) {
            var _finalizers = this._finalizers;
            _finalizers && arrRemove(_finalizers, teardown);
            if (teardown instanceof Subscription) {
                teardown._removeParent(this);
            }
        };
        Subscription.EMPTY = (function () {
            var empty = new Subscription();
            empty.closed = true;
            return empty;
        })();
        return Subscription;
    }());
    var EMPTY_SUBSCRIPTION = Subscription.EMPTY;
    function isSubscription(value) {
        return (value instanceof Subscription ||
            (value && 'closed' in value && isFunction(value.remove) && isFunction(value.add) && isFunction(value.unsubscribe)));
    }
    function execFinalizer(finalizer) {
        if (isFunction(finalizer)) {
            finalizer();
        }
        else {
            finalizer.unsubscribe();
        }
    }

    var config = {
        onUnhandledError: null,
        onStoppedNotification: null,
        Promise: undefined,
        useDeprecatedSynchronousErrorHandling: false,
        useDeprecatedNextContext: false,
    };

    var timeoutProvider = {
        setTimeout: function (handler, timeout) {
            var args = [];
            for (var _i = 2; _i < arguments.length; _i++) {
                args[_i - 2] = arguments[_i];
            }
            return setTimeout.apply(void 0, __spreadArray([handler, timeout], __read(args)));
        },
        clearTimeout: function (handle) {
            return (clearTimeout)(handle);
        },
        delegate: undefined,
    };

    function reportUnhandledError(err) {
        timeoutProvider.setTimeout(function () {
            {
                throw err;
            }
        });
    }

    function noop() { }

    function errorContext(cb) {
        {
            cb();
        }
    }

    var Subscriber = (function (_super) {
        __extends(Subscriber, _super);
        function Subscriber(destination) {
            var _this = _super.call(this) || this;
            _this.isStopped = false;
            if (destination) {
                _this.destination = destination;
                if (isSubscription(destination)) {
                    destination.add(_this);
                }
            }
            else {
                _this.destination = EMPTY_OBSERVER;
            }
            return _this;
        }
        Subscriber.create = function (next, error, complete) {
            return new SafeSubscriber(next, error, complete);
        };
        Subscriber.prototype.next = function (value) {
            if (this.isStopped) ;
            else {
                this._next(value);
            }
        };
        Subscriber.prototype.error = function (err) {
            if (this.isStopped) ;
            else {
                this.isStopped = true;
                this._error(err);
            }
        };
        Subscriber.prototype.complete = function () {
            if (this.isStopped) ;
            else {
                this.isStopped = true;
                this._complete();
            }
        };
        Subscriber.prototype.unsubscribe = function () {
            if (!this.closed) {
                this.isStopped = true;
                _super.prototype.unsubscribe.call(this);
                this.destination = null;
            }
        };
        Subscriber.prototype._next = function (value) {
            this.destination.next(value);
        };
        Subscriber.prototype._error = function (err) {
            try {
                this.destination.error(err);
            }
            finally {
                this.unsubscribe();
            }
        };
        Subscriber.prototype._complete = function () {
            try {
                this.destination.complete();
            }
            finally {
                this.unsubscribe();
            }
        };
        return Subscriber;
    }(Subscription));
    var _bind = Function.prototype.bind;
    function bind(fn, thisArg) {
        return _bind.call(fn, thisArg);
    }
    var ConsumerObserver = (function () {
        function ConsumerObserver(partialObserver) {
            this.partialObserver = partialObserver;
        }
        ConsumerObserver.prototype.next = function (value) {
            var partialObserver = this.partialObserver;
            if (partialObserver.next) {
                try {
                    partialObserver.next(value);
                }
                catch (error) {
                    handleUnhandledError(error);
                }
            }
        };
        ConsumerObserver.prototype.error = function (err) {
            var partialObserver = this.partialObserver;
            if (partialObserver.error) {
                try {
                    partialObserver.error(err);
                }
                catch (error) {
                    handleUnhandledError(error);
                }
            }
            else {
                handleUnhandledError(err);
            }
        };
        ConsumerObserver.prototype.complete = function () {
            var partialObserver = this.partialObserver;
            if (partialObserver.complete) {
                try {
                    partialObserver.complete();
                }
                catch (error) {
                    handleUnhandledError(error);
                }
            }
        };
        return ConsumerObserver;
    }());
    var SafeSubscriber = (function (_super) {
        __extends(SafeSubscriber, _super);
        function SafeSubscriber(observerOrNext, error, complete) {
            var _this = _super.call(this) || this;
            var partialObserver;
            if (isFunction(observerOrNext) || !observerOrNext) {
                partialObserver = {
                    next: observerOrNext !== null && observerOrNext !== void 0 ? observerOrNext : undefined,
                    error: error !== null && error !== void 0 ? error : undefined,
                    complete: complete !== null && complete !== void 0 ? complete : undefined,
                };
            }
            else {
                var context_1;
                if (_this && config.useDeprecatedNextContext) {
                    context_1 = Object.create(observerOrNext);
                    context_1.unsubscribe = function () { return _this.unsubscribe(); };
                    partialObserver = {
                        next: observerOrNext.next && bind(observerOrNext.next, context_1),
                        error: observerOrNext.error && bind(observerOrNext.error, context_1),
                        complete: observerOrNext.complete && bind(observerOrNext.complete, context_1),
                    };
                }
                else {
                    partialObserver = observerOrNext;
                }
            }
            _this.destination = new ConsumerObserver(partialObserver);
            return _this;
        }
        return SafeSubscriber;
    }(Subscriber));
    function handleUnhandledError(error) {
        {
            reportUnhandledError(error);
        }
    }
    function defaultErrorHandler(err) {
        throw err;
    }
    var EMPTY_OBSERVER = {
        closed: true,
        next: noop,
        error: defaultErrorHandler,
        complete: noop,
    };

    var observable = (function () { return (typeof Symbol === 'function' && Symbol.observable) || '@@observable'; })();

    function identity(x) {
        return x;
    }

    function pipeFromArray(fns) {
        if (fns.length === 0) {
            return identity;
        }
        if (fns.length === 1) {
            return fns[0];
        }
        return function piped(input) {
            return fns.reduce(function (prev, fn) { return fn(prev); }, input);
        };
    }

    var Observable = (function () {
        function Observable(subscribe) {
            if (subscribe) {
                this._subscribe = subscribe;
            }
        }
        Observable.prototype.lift = function (operator) {
            var observable = new Observable();
            observable.source = this;
            observable.operator = operator;
            return observable;
        };
        Observable.prototype.subscribe = function (observerOrNext, error, complete) {
            var _this = this;
            var subscriber = isSubscriber(observerOrNext) ? observerOrNext : new SafeSubscriber(observerOrNext, error, complete);
            errorContext(function () {
                var _a = _this, operator = _a.operator, source = _a.source;
                subscriber.add(operator
                    ?
                        operator.call(subscriber, source)
                    : source
                        ?
                            _this._subscribe(subscriber)
                        :
                            _this._trySubscribe(subscriber));
            });
            return subscriber;
        };
        Observable.prototype._trySubscribe = function (sink) {
            try {
                return this._subscribe(sink);
            }
            catch (err) {
                sink.error(err);
            }
        };
        Observable.prototype.forEach = function (next, promiseCtor) {
            var _this = this;
            promiseCtor = getPromiseCtor(promiseCtor);
            return new promiseCtor(function (resolve, reject) {
                var subscriber = new SafeSubscriber({
                    next: function (value) {
                        try {
                            next(value);
                        }
                        catch (err) {
                            reject(err);
                            subscriber.unsubscribe();
                        }
                    },
                    error: reject,
                    complete: resolve,
                });
                _this.subscribe(subscriber);
            });
        };
        Observable.prototype._subscribe = function (subscriber) {
            var _a;
            return (_a = this.source) === null || _a === void 0 ? void 0 : _a.subscribe(subscriber);
        };
        Observable.prototype[observable] = function () {
            return this;
        };
        Observable.prototype.pipe = function () {
            var operations = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                operations[_i] = arguments[_i];
            }
            return pipeFromArray(operations)(this);
        };
        Observable.prototype.toPromise = function (promiseCtor) {
            var _this = this;
            promiseCtor = getPromiseCtor(promiseCtor);
            return new promiseCtor(function (resolve, reject) {
                var value;
                _this.subscribe(function (x) { return (value = x); }, function (err) { return reject(err); }, function () { return resolve(value); });
            });
        };
        Observable.create = function (subscribe) {
            return new Observable(subscribe);
        };
        return Observable;
    }());
    function getPromiseCtor(promiseCtor) {
        var _a;
        return (_a = promiseCtor !== null && promiseCtor !== void 0 ? promiseCtor : config.Promise) !== null && _a !== void 0 ? _a : Promise;
    }
    function isObserver(value) {
        return value && isFunction(value.next) && isFunction(value.error) && isFunction(value.complete);
    }
    function isSubscriber(value) {
        return (value && value instanceof Subscriber) || (isObserver(value) && isSubscription(value));
    }

    function hasLift(source) {
        return isFunction(source === null || source === void 0 ? void 0 : source.lift);
    }
    function operate(init) {
        return function (source) {
            if (hasLift(source)) {
                return source.lift(function (liftedSource) {
                    try {
                        return init(liftedSource, this);
                    }
                    catch (err) {
                        this.error(err);
                    }
                });
            }
            throw new TypeError('Unable to lift unknown Observable type');
        };
    }

    function createOperatorSubscriber(destination, onNext, onComplete, onError, onFinalize) {
        return new OperatorSubscriber(destination, onNext, onComplete, onError, onFinalize);
    }
    var OperatorSubscriber = (function (_super) {
        __extends(OperatorSubscriber, _super);
        function OperatorSubscriber(destination, onNext, onComplete, onError, onFinalize, shouldUnsubscribe) {
            var _this = _super.call(this, destination) || this;
            _this.onFinalize = onFinalize;
            _this.shouldUnsubscribe = shouldUnsubscribe;
            _this._next = onNext
                ? function (value) {
                    try {
                        onNext(value);
                    }
                    catch (err) {
                        destination.error(err);
                    }
                }
                : _super.prototype._next;
            _this._error = onError
                ? function (err) {
                    try {
                        onError(err);
                    }
                    catch (err) {
                        destination.error(err);
                    }
                    finally {
                        this.unsubscribe();
                    }
                }
                : _super.prototype._error;
            _this._complete = onComplete
                ? function () {
                    try {
                        onComplete();
                    }
                    catch (err) {
                        destination.error(err);
                    }
                    finally {
                        this.unsubscribe();
                    }
                }
                : _super.prototype._complete;
            return _this;
        }
        OperatorSubscriber.prototype.unsubscribe = function () {
            var _a;
            if (!this.shouldUnsubscribe || this.shouldUnsubscribe()) {
                var closed_1 = this.closed;
                _super.prototype.unsubscribe.call(this);
                !closed_1 && ((_a = this.onFinalize) === null || _a === void 0 ? void 0 : _a.call(this));
            }
        };
        return OperatorSubscriber;
    }(Subscriber));

    function refCount() {
        return operate(function (source, subscriber) {
            var connection = null;
            source._refCount++;
            var refCounter = createOperatorSubscriber(subscriber, undefined, undefined, undefined, function () {
                if (!source || source._refCount <= 0 || 0 < --source._refCount) {
                    connection = null;
                    return;
                }
                var sharedConnection = source._connection;
                var conn = connection;
                connection = null;
                if (sharedConnection && (!conn || sharedConnection === conn)) {
                    sharedConnection.unsubscribe();
                }
                subscriber.unsubscribe();
            });
            source.subscribe(refCounter);
            if (!refCounter.closed) {
                connection = source.connect();
            }
        });
    }

    ((function (_super) {
        __extends(ConnectableObservable, _super);
        function ConnectableObservable(source, subjectFactory) {
            var _this = _super.call(this) || this;
            _this.source = source;
            _this.subjectFactory = subjectFactory;
            _this._subject = null;
            _this._refCount = 0;
            _this._connection = null;
            if (hasLift(source)) {
                _this.lift = source.lift;
            }
            return _this;
        }
        ConnectableObservable.prototype._subscribe = function (subscriber) {
            return this.getSubject().subscribe(subscriber);
        };
        ConnectableObservable.prototype.getSubject = function () {
            var subject = this._subject;
            if (!subject || subject.isStopped) {
                this._subject = this.subjectFactory();
            }
            return this._subject;
        };
        ConnectableObservable.prototype._teardown = function () {
            this._refCount = 0;
            var _connection = this._connection;
            this._subject = this._connection = null;
            _connection === null || _connection === void 0 ? void 0 : _connection.unsubscribe();
        };
        ConnectableObservable.prototype.connect = function () {
            var _this = this;
            var connection = this._connection;
            if (!connection) {
                connection = this._connection = new Subscription();
                var subject_1 = this.getSubject();
                connection.add(this.source.subscribe(createOperatorSubscriber(subject_1, undefined, function () {
                    _this._teardown();
                    subject_1.complete();
                }, function (err) {
                    _this._teardown();
                    subject_1.error(err);
                }, function () { return _this._teardown(); })));
                if (connection.closed) {
                    this._connection = null;
                    connection = Subscription.EMPTY;
                }
            }
            return connection;
        };
        ConnectableObservable.prototype.refCount = function () {
            return refCount()(this);
        };
        return ConnectableObservable;
    })(Observable));

    var performanceTimestampProvider = {
        now: function () {
            return (performanceTimestampProvider.delegate || performance).now();
        },
        delegate: undefined,
    };

    var animationFrameProvider = {
        schedule: function (callback) {
            var request = requestAnimationFrame;
            var cancel = cancelAnimationFrame;
            var handle = request(function (timestamp) {
                cancel = undefined;
                callback(timestamp);
            });
            return new Subscription(function () { return cancel === null || cancel === void 0 ? void 0 : cancel(handle); });
        },
        requestAnimationFrame: function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            var delegate = animationFrameProvider.delegate;
            return ((delegate === null || delegate === void 0 ? void 0 : delegate.requestAnimationFrame) || requestAnimationFrame).apply(void 0, __spreadArray([], __read(args)));
        },
        cancelAnimationFrame: function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            return (cancelAnimationFrame).apply(void 0, __spreadArray([], __read(args)));
        },
        delegate: undefined,
    };

    function animationFramesFactory(timestampProvider) {
        var schedule = animationFrameProvider.schedule;
        return new Observable(function (subscriber) {
            var subscription = new Subscription();
            var provider = timestampProvider || performanceTimestampProvider;
            var start = provider.now();
            var run = function (timestamp) {
                var now = provider.now();
                subscriber.next({
                    timestamp: timestampProvider ? now : timestamp,
                    elapsed: now - start,
                });
                if (!subscriber.closed) {
                    subscription.add(schedule(run));
                }
            };
            subscription.add(schedule(run));
            return subscription;
        });
    }
    animationFramesFactory();

    var ObjectUnsubscribedError = createErrorClass(function (_super) {
        return function ObjectUnsubscribedErrorImpl() {
            _super(this);
            this.name = 'ObjectUnsubscribedError';
            this.message = 'object unsubscribed';
        };
    });

    var Subject = (function (_super) {
        __extends(Subject, _super);
        function Subject() {
            var _this = _super.call(this) || this;
            _this.closed = false;
            _this.currentObservers = null;
            _this.observers = [];
            _this.isStopped = false;
            _this.hasError = false;
            _this.thrownError = null;
            return _this;
        }
        Subject.prototype.lift = function (operator) {
            var subject = new AnonymousSubject(this, this);
            subject.operator = operator;
            return subject;
        };
        Subject.prototype._throwIfClosed = function () {
            if (this.closed) {
                throw new ObjectUnsubscribedError();
            }
        };
        Subject.prototype.next = function (value) {
            var _this = this;
            errorContext(function () {
                var e_1, _a;
                _this._throwIfClosed();
                if (!_this.isStopped) {
                    if (!_this.currentObservers) {
                        _this.currentObservers = Array.from(_this.observers);
                    }
                    try {
                        for (var _b = __values(_this.currentObservers), _c = _b.next(); !_c.done; _c = _b.next()) {
                            var observer = _c.value;
                            observer.next(value);
                        }
                    }
                    catch (e_1_1) { e_1 = { error: e_1_1 }; }
                    finally {
                        try {
                            if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
                        }
                        finally { if (e_1) throw e_1.error; }
                    }
                }
            });
        };
        Subject.prototype.error = function (err) {
            var _this = this;
            errorContext(function () {
                _this._throwIfClosed();
                if (!_this.isStopped) {
                    _this.hasError = _this.isStopped = true;
                    _this.thrownError = err;
                    var observers = _this.observers;
                    while (observers.length) {
                        observers.shift().error(err);
                    }
                }
            });
        };
        Subject.prototype.complete = function () {
            var _this = this;
            errorContext(function () {
                _this._throwIfClosed();
                if (!_this.isStopped) {
                    _this.isStopped = true;
                    var observers = _this.observers;
                    while (observers.length) {
                        observers.shift().complete();
                    }
                }
            });
        };
        Subject.prototype.unsubscribe = function () {
            this.isStopped = this.closed = true;
            this.observers = this.currentObservers = null;
        };
        Object.defineProperty(Subject.prototype, "observed", {
            get: function () {
                var _a;
                return ((_a = this.observers) === null || _a === void 0 ? void 0 : _a.length) > 0;
            },
            enumerable: false,
            configurable: true
        });
        Subject.prototype._trySubscribe = function (subscriber) {
            this._throwIfClosed();
            return _super.prototype._trySubscribe.call(this, subscriber);
        };
        Subject.prototype._subscribe = function (subscriber) {
            this._throwIfClosed();
            this._checkFinalizedStatuses(subscriber);
            return this._innerSubscribe(subscriber);
        };
        Subject.prototype._innerSubscribe = function (subscriber) {
            var _this = this;
            var _a = this, hasError = _a.hasError, isStopped = _a.isStopped, observers = _a.observers;
            if (hasError || isStopped) {
                return EMPTY_SUBSCRIPTION;
            }
            this.currentObservers = null;
            observers.push(subscriber);
            return new Subscription(function () {
                _this.currentObservers = null;
                arrRemove(observers, subscriber);
            });
        };
        Subject.prototype._checkFinalizedStatuses = function (subscriber) {
            var _a = this, hasError = _a.hasError, thrownError = _a.thrownError, isStopped = _a.isStopped;
            if (hasError) {
                subscriber.error(thrownError);
            }
            else if (isStopped) {
                subscriber.complete();
            }
        };
        Subject.prototype.asObservable = function () {
            var observable = new Observable();
            observable.source = this;
            return observable;
        };
        Subject.create = function (destination, source) {
            return new AnonymousSubject(destination, source);
        };
        return Subject;
    }(Observable));
    var AnonymousSubject = (function (_super) {
        __extends(AnonymousSubject, _super);
        function AnonymousSubject(destination, source) {
            var _this = _super.call(this) || this;
            _this.destination = destination;
            _this.source = source;
            return _this;
        }
        AnonymousSubject.prototype.next = function (value) {
            var _a, _b;
            (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.next) === null || _b === void 0 ? void 0 : _b.call(_a, value);
        };
        AnonymousSubject.prototype.error = function (err) {
            var _a, _b;
            (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.error) === null || _b === void 0 ? void 0 : _b.call(_a, err);
        };
        AnonymousSubject.prototype.complete = function () {
            var _a, _b;
            (_b = (_a = this.destination) === null || _a === void 0 ? void 0 : _a.complete) === null || _b === void 0 ? void 0 : _b.call(_a);
        };
        AnonymousSubject.prototype._subscribe = function (subscriber) {
            var _a, _b;
            return (_b = (_a = this.source) === null || _a === void 0 ? void 0 : _a.subscribe(subscriber)) !== null && _b !== void 0 ? _b : EMPTY_SUBSCRIPTION;
        };
        return AnonymousSubject;
    }(Subject));

    var BehaviorSubject = (function (_super) {
        __extends(BehaviorSubject, _super);
        function BehaviorSubject(_value) {
            var _this = _super.call(this) || this;
            _this._value = _value;
            return _this;
        }
        Object.defineProperty(BehaviorSubject.prototype, "value", {
            get: function () {
                return this.getValue();
            },
            enumerable: false,
            configurable: true
        });
        BehaviorSubject.prototype._subscribe = function (subscriber) {
            var subscription = _super.prototype._subscribe.call(this, subscriber);
            !subscription.closed && subscriber.next(this._value);
            return subscription;
        };
        BehaviorSubject.prototype.getValue = function () {
            var _a = this, hasError = _a.hasError, thrownError = _a.thrownError, _value = _a._value;
            if (hasError) {
                throw thrownError;
            }
            this._throwIfClosed();
            return _value;
        };
        BehaviorSubject.prototype.next = function (value) {
            _super.prototype.next.call(this, (this._value = value));
        };
        return BehaviorSubject;
    }(Subject));

    var dateTimestampProvider = {
        now: function () {
            return (dateTimestampProvider.delegate || Date).now();
        },
        delegate: undefined,
    };

    ((function (_super) {
        __extends(ReplaySubject, _super);
        function ReplaySubject(_bufferSize, _windowTime, _timestampProvider) {
            if (_bufferSize === void 0) { _bufferSize = Infinity; }
            if (_windowTime === void 0) { _windowTime = Infinity; }
            if (_timestampProvider === void 0) { _timestampProvider = dateTimestampProvider; }
            var _this = _super.call(this) || this;
            _this._bufferSize = _bufferSize;
            _this._windowTime = _windowTime;
            _this._timestampProvider = _timestampProvider;
            _this._buffer = [];
            _this._infiniteTimeWindow = true;
            _this._infiniteTimeWindow = _windowTime === Infinity;
            _this._bufferSize = Math.max(1, _bufferSize);
            _this._windowTime = Math.max(1, _windowTime);
            return _this;
        }
        ReplaySubject.prototype.next = function (value) {
            var _a = this, isStopped = _a.isStopped, _buffer = _a._buffer, _infiniteTimeWindow = _a._infiniteTimeWindow, _timestampProvider = _a._timestampProvider, _windowTime = _a._windowTime;
            if (!isStopped) {
                _buffer.push(value);
                !_infiniteTimeWindow && _buffer.push(_timestampProvider.now() + _windowTime);
            }
            this._trimBuffer();
            _super.prototype.next.call(this, value);
        };
        ReplaySubject.prototype._subscribe = function (subscriber) {
            this._throwIfClosed();
            this._trimBuffer();
            var subscription = this._innerSubscribe(subscriber);
            var _a = this, _infiniteTimeWindow = _a._infiniteTimeWindow, _buffer = _a._buffer;
            var copy = _buffer.slice();
            for (var i = 0; i < copy.length && !subscriber.closed; i += _infiniteTimeWindow ? 1 : 2) {
                subscriber.next(copy[i]);
            }
            this._checkFinalizedStatuses(subscriber);
            return subscription;
        };
        ReplaySubject.prototype._trimBuffer = function () {
            var _a = this, _bufferSize = _a._bufferSize, _timestampProvider = _a._timestampProvider, _buffer = _a._buffer, _infiniteTimeWindow = _a._infiniteTimeWindow;
            var adjustedBufferSize = (_infiniteTimeWindow ? 1 : 2) * _bufferSize;
            _bufferSize < Infinity && adjustedBufferSize < _buffer.length && _buffer.splice(0, _buffer.length - adjustedBufferSize);
            if (!_infiniteTimeWindow) {
                var now = _timestampProvider.now();
                var last = 0;
                for (var i = 1; i < _buffer.length && _buffer[i] <= now; i += 2) {
                    last = i;
                }
                last && _buffer.splice(0, last + 1);
            }
        };
        return ReplaySubject;
    })(Subject));

    ((function (_super) {
        __extends(AsyncSubject, _super);
        function AsyncSubject() {
            var _this = _super !== null && _super.apply(this, arguments) || this;
            _this._value = null;
            _this._hasValue = false;
            _this._isComplete = false;
            return _this;
        }
        AsyncSubject.prototype._checkFinalizedStatuses = function (subscriber) {
            var _a = this, hasError = _a.hasError, _hasValue = _a._hasValue, _value = _a._value, thrownError = _a.thrownError, isStopped = _a.isStopped, _isComplete = _a._isComplete;
            if (hasError) {
                subscriber.error(thrownError);
            }
            else if (isStopped || _isComplete) {
                _hasValue && subscriber.next(_value);
                subscriber.complete();
            }
        };
        AsyncSubject.prototype.next = function (value) {
            if (!this.isStopped) {
                this._value = value;
                this._hasValue = true;
            }
        };
        AsyncSubject.prototype.complete = function () {
            var _a = this, _hasValue = _a._hasValue, _value = _a._value, _isComplete = _a._isComplete;
            if (!_isComplete) {
                this._isComplete = true;
                _hasValue && _super.prototype.next.call(this, _value);
                _super.prototype.complete.call(this);
            }
        };
        return AsyncSubject;
    })(Subject));

    var Action = (function (_super) {
        __extends(Action, _super);
        function Action(scheduler, work) {
            return _super.call(this) || this;
        }
        Action.prototype.schedule = function (state, delay) {
            return this;
        };
        return Action;
    }(Subscription));

    var intervalProvider = {
        setInterval: function (handler, timeout) {
            var args = [];
            for (var _i = 2; _i < arguments.length; _i++) {
                args[_i - 2] = arguments[_i];
            }
            return setInterval.apply(void 0, __spreadArray([handler, timeout], __read(args)));
        },
        clearInterval: function (handle) {
            return (clearInterval)(handle);
        },
        delegate: undefined,
    };

    var AsyncAction = (function (_super) {
        __extends(AsyncAction, _super);
        function AsyncAction(scheduler, work) {
            var _this = _super.call(this, scheduler, work) || this;
            _this.scheduler = scheduler;
            _this.work = work;
            _this.pending = false;
            return _this;
        }
        AsyncAction.prototype.schedule = function (state, delay) {
            if (delay === void 0) { delay = 0; }
            if (this.closed) {
                return this;
            }
            this.state = state;
            var id = this.id;
            var scheduler = this.scheduler;
            if (id != null) {
                this.id = this.recycleAsyncId(scheduler, id, delay);
            }
            this.pending = true;
            this.delay = delay;
            this.id = this.id || this.requestAsyncId(scheduler, this.id, delay);
            return this;
        };
        AsyncAction.prototype.requestAsyncId = function (scheduler, _id, delay) {
            if (delay === void 0) { delay = 0; }
            return intervalProvider.setInterval(scheduler.flush.bind(scheduler, this), delay);
        };
        AsyncAction.prototype.recycleAsyncId = function (_scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if (delay != null && this.delay === delay && this.pending === false) {
                return id;
            }
            intervalProvider.clearInterval(id);
            return undefined;
        };
        AsyncAction.prototype.execute = function (state, delay) {
            if (this.closed) {
                return new Error('executing a cancelled action');
            }
            this.pending = false;
            var error = this._execute(state, delay);
            if (error) {
                return error;
            }
            else if (this.pending === false && this.id != null) {
                this.id = this.recycleAsyncId(this.scheduler, this.id, null);
            }
        };
        AsyncAction.prototype._execute = function (state, _delay) {
            var errored = false;
            var errorValue;
            try {
                this.work(state);
            }
            catch (e) {
                errored = true;
                errorValue = e ? e : new Error('Scheduled action threw falsy error');
            }
            if (errored) {
                this.unsubscribe();
                return errorValue;
            }
        };
        AsyncAction.prototype.unsubscribe = function () {
            if (!this.closed) {
                var _a = this, id = _a.id, scheduler = _a.scheduler;
                var actions = scheduler.actions;
                this.work = this.state = this.scheduler = null;
                this.pending = false;
                arrRemove(actions, this);
                if (id != null) {
                    this.id = this.recycleAsyncId(scheduler, id, null);
                }
                this.delay = null;
                _super.prototype.unsubscribe.call(this);
            }
        };
        return AsyncAction;
    }(Action));

    var nextHandle = 1;
    var resolved;
    var activeHandles = {};
    function findAndClearHandle(handle) {
        if (handle in activeHandles) {
            delete activeHandles[handle];
            return true;
        }
        return false;
    }
    var Immediate = {
        setImmediate: function (cb) {
            var handle = nextHandle++;
            activeHandles[handle] = true;
            if (!resolved) {
                resolved = Promise.resolve();
            }
            resolved.then(function () { return findAndClearHandle(handle) && cb(); });
            return handle;
        },
        clearImmediate: function (handle) {
            findAndClearHandle(handle);
        },
    };

    var setImmediate = Immediate.setImmediate, clearImmediate = Immediate.clearImmediate;
    var immediateProvider = {
        setImmediate: function () {
            var args = [];
            for (var _i = 0; _i < arguments.length; _i++) {
                args[_i] = arguments[_i];
            }
            var delegate = immediateProvider.delegate;
            return ((delegate === null || delegate === void 0 ? void 0 : delegate.setImmediate) || setImmediate).apply(void 0, __spreadArray([], __read(args)));
        },
        clearImmediate: function (handle) {
            return (clearImmediate)(handle);
        },
        delegate: undefined,
    };

    var AsapAction = (function (_super) {
        __extends(AsapAction, _super);
        function AsapAction(scheduler, work) {
            var _this = _super.call(this, scheduler, work) || this;
            _this.scheduler = scheduler;
            _this.work = work;
            return _this;
        }
        AsapAction.prototype.requestAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if (delay !== null && delay > 0) {
                return _super.prototype.requestAsyncId.call(this, scheduler, id, delay);
            }
            scheduler.actions.push(this);
            return scheduler._scheduled || (scheduler._scheduled = immediateProvider.setImmediate(scheduler.flush.bind(scheduler, undefined)));
        };
        AsapAction.prototype.recycleAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if ((delay != null && delay > 0) || (delay == null && this.delay > 0)) {
                return _super.prototype.recycleAsyncId.call(this, scheduler, id, delay);
            }
            if (!scheduler.actions.some(function (action) { return action.id === id; })) {
                immediateProvider.clearImmediate(id);
                scheduler._scheduled = undefined;
            }
            return undefined;
        };
        return AsapAction;
    }(AsyncAction));

    var Scheduler = (function () {
        function Scheduler(schedulerActionCtor, now) {
            if (now === void 0) { now = Scheduler.now; }
            this.schedulerActionCtor = schedulerActionCtor;
            this.now = now;
        }
        Scheduler.prototype.schedule = function (work, delay, state) {
            if (delay === void 0) { delay = 0; }
            return new this.schedulerActionCtor(this, work).schedule(state, delay);
        };
        Scheduler.now = dateTimestampProvider.now;
        return Scheduler;
    }());

    var AsyncScheduler = (function (_super) {
        __extends(AsyncScheduler, _super);
        function AsyncScheduler(SchedulerAction, now) {
            if (now === void 0) { now = Scheduler.now; }
            var _this = _super.call(this, SchedulerAction, now) || this;
            _this.actions = [];
            _this._active = false;
            _this._scheduled = undefined;
            return _this;
        }
        AsyncScheduler.prototype.flush = function (action) {
            var actions = this.actions;
            if (this._active) {
                actions.push(action);
                return;
            }
            var error;
            this._active = true;
            do {
                if ((error = action.execute(action.state, action.delay))) {
                    break;
                }
            } while ((action = actions.shift()));
            this._active = false;
            if (error) {
                while ((action = actions.shift())) {
                    action.unsubscribe();
                }
                throw error;
            }
        };
        return AsyncScheduler;
    }(Scheduler));

    var AsapScheduler = (function (_super) {
        __extends(AsapScheduler, _super);
        function AsapScheduler() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        AsapScheduler.prototype.flush = function (action) {
            this._active = true;
            var flushId = this._scheduled;
            this._scheduled = undefined;
            var actions = this.actions;
            var error;
            action = action || actions.shift();
            do {
                if ((error = action.execute(action.state, action.delay))) {
                    break;
                }
            } while ((action = actions[0]) && action.id === flushId && actions.shift());
            this._active = false;
            if (error) {
                while ((action = actions[0]) && action.id === flushId && actions.shift()) {
                    action.unsubscribe();
                }
                throw error;
            }
        };
        return AsapScheduler;
    }(AsyncScheduler));

    new AsapScheduler(AsapAction);

    new AsyncScheduler(AsyncAction);

    var QueueAction = (function (_super) {
        __extends(QueueAction, _super);
        function QueueAction(scheduler, work) {
            var _this = _super.call(this, scheduler, work) || this;
            _this.scheduler = scheduler;
            _this.work = work;
            return _this;
        }
        QueueAction.prototype.schedule = function (state, delay) {
            if (delay === void 0) { delay = 0; }
            if (delay > 0) {
                return _super.prototype.schedule.call(this, state, delay);
            }
            this.delay = delay;
            this.state = state;
            this.scheduler.flush(this);
            return this;
        };
        QueueAction.prototype.execute = function (state, delay) {
            return (delay > 0 || this.closed) ?
                _super.prototype.execute.call(this, state, delay) :
                this._execute(state, delay);
        };
        QueueAction.prototype.requestAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if ((delay != null && delay > 0) || (delay == null && this.delay > 0)) {
                return _super.prototype.requestAsyncId.call(this, scheduler, id, delay);
            }
            return scheduler.flush(this);
        };
        return QueueAction;
    }(AsyncAction));

    var QueueScheduler = (function (_super) {
        __extends(QueueScheduler, _super);
        function QueueScheduler() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return QueueScheduler;
    }(AsyncScheduler));

    new QueueScheduler(QueueAction);

    var AnimationFrameAction = (function (_super) {
        __extends(AnimationFrameAction, _super);
        function AnimationFrameAction(scheduler, work) {
            var _this = _super.call(this, scheduler, work) || this;
            _this.scheduler = scheduler;
            _this.work = work;
            return _this;
        }
        AnimationFrameAction.prototype.requestAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if (delay !== null && delay > 0) {
                return _super.prototype.requestAsyncId.call(this, scheduler, id, delay);
            }
            scheduler.actions.push(this);
            return scheduler._scheduled || (scheduler._scheduled = animationFrameProvider.requestAnimationFrame(function () { return scheduler.flush(undefined); }));
        };
        AnimationFrameAction.prototype.recycleAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            if ((delay != null && delay > 0) || (delay == null && this.delay > 0)) {
                return _super.prototype.recycleAsyncId.call(this, scheduler, id, delay);
            }
            if (!scheduler.actions.some(function (action) { return action.id === id; })) {
                animationFrameProvider.cancelAnimationFrame(id);
                scheduler._scheduled = undefined;
            }
            return undefined;
        };
        return AnimationFrameAction;
    }(AsyncAction));

    var AnimationFrameScheduler = (function (_super) {
        __extends(AnimationFrameScheduler, _super);
        function AnimationFrameScheduler() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        AnimationFrameScheduler.prototype.flush = function (action) {
            this._active = true;
            var flushId = this._scheduled;
            this._scheduled = undefined;
            var actions = this.actions;
            var error;
            action = action || actions.shift();
            do {
                if ((error = action.execute(action.state, action.delay))) {
                    break;
                }
            } while ((action = actions[0]) && action.id === flushId && actions.shift());
            this._active = false;
            if (error) {
                while ((action = actions[0]) && action.id === flushId && actions.shift()) {
                    action.unsubscribe();
                }
                throw error;
            }
        };
        return AnimationFrameScheduler;
    }(AsyncScheduler));

    new AnimationFrameScheduler(AnimationFrameAction);

    ((function (_super) {
        __extends(VirtualTimeScheduler, _super);
        function VirtualTimeScheduler(schedulerActionCtor, maxFrames) {
            if (schedulerActionCtor === void 0) { schedulerActionCtor = VirtualAction; }
            if (maxFrames === void 0) { maxFrames = Infinity; }
            var _this = _super.call(this, schedulerActionCtor, function () { return _this.frame; }) || this;
            _this.maxFrames = maxFrames;
            _this.frame = 0;
            _this.index = -1;
            return _this;
        }
        VirtualTimeScheduler.prototype.flush = function () {
            var _a = this, actions = _a.actions, maxFrames = _a.maxFrames;
            var error;
            var action;
            while ((action = actions[0]) && action.delay <= maxFrames) {
                actions.shift();
                this.frame = action.delay;
                if ((error = action.execute(action.state, action.delay))) {
                    break;
                }
            }
            if (error) {
                while ((action = actions.shift())) {
                    action.unsubscribe();
                }
                throw error;
            }
        };
        VirtualTimeScheduler.frameTimeFactor = 10;
        return VirtualTimeScheduler;
    })(AsyncScheduler));
    var VirtualAction = (function (_super) {
        __extends(VirtualAction, _super);
        function VirtualAction(scheduler, work, index) {
            if (index === void 0) { index = (scheduler.index += 1); }
            var _this = _super.call(this, scheduler, work) || this;
            _this.scheduler = scheduler;
            _this.work = work;
            _this.index = index;
            _this.active = true;
            _this.index = scheduler.index = index;
            return _this;
        }
        VirtualAction.prototype.schedule = function (state, delay) {
            if (delay === void 0) { delay = 0; }
            if (Number.isFinite(delay)) {
                if (!this.id) {
                    return _super.prototype.schedule.call(this, state, delay);
                }
                this.active = false;
                var action = new VirtualAction(this.scheduler, this.work);
                this.add(action);
                return action.schedule(state, delay);
            }
            else {
                return Subscription.EMPTY;
            }
        };
        VirtualAction.prototype.requestAsyncId = function (scheduler, id, delay) {
            if (delay === void 0) { delay = 0; }
            this.delay = scheduler.frame + delay;
            var actions = scheduler.actions;
            actions.push(this);
            actions.sort(VirtualAction.sortActions);
            return true;
        };
        VirtualAction.prototype.recycleAsyncId = function (scheduler, id, delay) {
            return undefined;
        };
        VirtualAction.prototype._execute = function (state, delay) {
            if (this.active === true) {
                return _super.prototype._execute.call(this, state, delay);
            }
        };
        VirtualAction.sortActions = function (a, b) {
            if (a.delay === b.delay) {
                if (a.index === b.index) {
                    return 0;
                }
                else if (a.index > b.index) {
                    return 1;
                }
                else {
                    return -1;
                }
            }
            else if (a.delay > b.delay) {
                return 1;
            }
            else {
                return -1;
            }
        };
        return VirtualAction;
    }(AsyncAction));

    new Observable(function (subscriber) { return subscriber.complete(); });

    var NotificationKind;
    (function (NotificationKind) {
        NotificationKind["NEXT"] = "N";
        NotificationKind["ERROR"] = "E";
        NotificationKind["COMPLETE"] = "C";
    })(NotificationKind || (NotificationKind = {}));

    createErrorClass(function (_super) { return function EmptyErrorImpl() {
        _super(this);
        this.name = 'EmptyError';
        this.message = 'no elements in sequence';
    }; });

    createErrorClass(function (_super) {
        return function ArgumentOutOfRangeErrorImpl() {
            _super(this);
            this.name = 'ArgumentOutOfRangeError';
            this.message = 'argument out of range';
        };
    });

    createErrorClass(function (_super) {
        return function NotFoundErrorImpl(message) {
            _super(this);
            this.name = 'NotFoundError';
            this.message = message;
        };
    });

    createErrorClass(function (_super) {
        return function SequenceErrorImpl(message) {
            _super(this);
            this.name = 'SequenceError';
            this.message = message;
        };
    });

    createErrorClass(function (_super) {
        return function TimeoutErrorImpl(info) {
            if (info === void 0) { info = null; }
            _super(this);
            this.message = 'Timeout has occurred';
            this.name = 'TimeoutError';
            this.info = info;
        };
    });

    new Observable(noop);

    class LocalSessionManager {
        constructor(protocol, options = {}) {
            this.protocol = protocol;
            this.fetch = (...args) => {
                if (!this.session) {
                    throw new Error('no session');
                }
                return this.session.send(...args);
            };
            this.opts = {
                localStorageKey: options.localStorageKey ?? 'wallet-session'
            };
            this.$session = new BehaviorSubject(undefined);
        }
        get hasSession() {
            return this.session !== undefined;
        }
        async createIfNotExists() {
            if (this.session !== undefined) {
                return this.session;
            }
            const session = await this.protocol.run();
            this.setSession(session);
            return session;
        }
        removeSession() {
            this.setSession();
        }
        setSession(session) {
            this.session = session;
            if (session === undefined) {
                localStorage.removeItem('wallet-session');
            }
            else {
                const sessionJson = session.toJSON();
                localStorage.setItem('wallet-session', JSON.stringify(sessionJson));
            }
            this.$session.next(session);
        }
        async loadSession() {
            let session;
            const sessionJson = localStorage.getItem('wallet-session');
            if (sessionJson !== null) {
                session = await Session.fromJSON(this.protocol.transport, JSON.parse(sessionJson));
            }
            this.setSession(session);
        }
    }

    exports.LocalSessionManager = LocalSessionManager;
    exports.openModal = openModal;

    Object.defineProperty(exports, '__esModule', { value: true });

}));
