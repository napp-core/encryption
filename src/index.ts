import cryptojs from "crypto-js"

export class EncryptionError extends Error {
    name = "EncryptionError"
    constructor(message: string) {
        super(message);
    }
}
export class EncryptionTimeoutError extends EncryptionError {
    name = "EncryptionTimeoutError"
    constructor(message: string) {
        super(message);
    }
}

export interface OEncryption {
    pass: string;

    /**
     * default 256. keySize / 32
     */
    keySize?: number

    /**
     * default 128. saltSize / 8
     */
    saltSize?: number

    /**
     * default value 128. ivSize / 8
     */
    ivSize?: number;

    /**
     * default 100
     */
    iterations?: number

    /**
     * default value hex
     */
    format?: 'hex' | 'base64';
}
export class Encryption {

    private keySize: number
    private ivSize: number;
    private saltSize: number;
    private iterations: number;
    private format: 'hex' | 'base64';
    private pass: string


    constructor(opt: OEncryption) {
        // this.saltLength = saltLength || 8;
        this.format = opt.format || 'hex'
        this.pass = cryptojs.SHA256(opt.pass).toString(cryptojs.enc.Hex)
        this.keySize = opt.keySize || 256;
        this.ivSize = opt.ivSize || 128;
        this.saltSize = opt.saltSize || 128;
        this.iterations = opt.iterations || 100;
    }

    encrypt(value: string) {
        try {
            let salt = cryptojs.lib.WordArray.random(this.saltSize / 8);
            let iv = cryptojs.lib.WordArray.random(this.ivSize / 8);
            let key = cryptojs.PBKDF2(this.pass, salt, {
                keySize: this.keySize / 32,
                iterations: this.iterations
            });

            let encrypted = cryptojs.AES.encrypt(value, key, {
                iv,
                format: cryptojs.format.Hex,
                padding: cryptojs.pad.Pkcs7,
                mode: cryptojs.mode.CBC,
                hasher: cryptojs.algo.SHA256
            });

            let _salt = salt.toString(cryptojs.enc.Hex);
            let _iv = iv.toString(cryptojs.enc.Hex);
            let _dta = encrypted.toString(this.format === 'hex' ? cryptojs.format.Hex : cryptojs.format.OpenSSL);

            return `${_salt}${_iv}${_dta}`;
        } catch (error) {
            if (error instanceof Error) {
                throw new EncryptionError(error.message);
            }
            console.error(error)
            throw new EncryptionError('cannot encrypt data');
        }
    }

    decript(value: string) {

        try {
            // let packet = cryptojs.enc.Hex.parse(value);

            let saltLen = cryptojs.lib.WordArray.random(this.saltSize / 8).toString(cryptojs.enc.Hex).length;
            let ivLen = cryptojs.lib.WordArray.random(this.ivSize / 8).toString(cryptojs.enc.Hex).length;

            if ((value || '').length < (saltLen + ivLen + 2)) {
                throw new Error('not supported ciphertext')
            }


            let salt = value.substring(0, saltLen);
            let iv = value.substring(saltLen, saltLen + ivLen);
            let ciphertext = value.substring(saltLen + ivLen);

            let key = cryptojs.PBKDF2(this.pass, cryptojs.enc.Hex.parse(salt), {
                keySize: this.keySize / 32,
                iterations: this.iterations
            });

            let decrypted = cryptojs.AES.decrypt(ciphertext, key, {
                iv: cryptojs.enc.Hex.parse(iv),
                format: this.format === 'hex' ? cryptojs.format.Hex : cryptojs.format.OpenSSL,
                padding: cryptojs.pad.Pkcs7,
                mode: cryptojs.mode.CBC,
                hasher: cryptojs.algo.SHA256

            });

            return decrypted.toString(cryptojs.enc.Utf8)

        } catch (error) {

            if (error instanceof Error) {
                throw new EncryptionError(error.message);
            }
            console.error(error)
            throw new EncryptionError('cannot decript data');
        }
    }

    encryptObj(value: object) {
        if (value == null || value == undefined) {
            throw new EncryptionError('value must not be null or undefined');
        }
        try {
            if (typeof value === 'object') {
                let _v = JSON.stringify(value);
                return this.encrypt(_v);
            }
            throw new EncryptionError("encrypt value is not object");
        } catch (error) {


            if (error instanceof Error) {
                throw new EncryptionError(error.message);
            }
            console.error(error)
            throw new EncryptionError('cannot encryptObj data');
        }

    }
    decryptObj<T>(value: string) {
        if (value == null || value == undefined) {
            throw new EncryptionError('value must not be null or undefined');
        }

        try {
            let _v = this.decript(value);
            let _o = JSON.parse(_v);
            if (typeof _o === 'object') {
                return _o as T;
            }
            throw new EncryptionError("decrypt value is not object");
        } catch (error) {


            if (error instanceof Error) {
                throw new EncryptionError(error.message);
            }
            console.error(error)
            throw new EncryptionError('cannot decryptObj data');
        }
    }

    encryptToken(payload: object, ex: number) {
        let t = {
            e: Date.now() + ex,
            d: payload || {}
        };
        return this.encryptObj(t);
    }
    decryptToken<T>(value: string): T {
        let t = this.decryptObj<{ e: number, d: T }>(value);
        if (t && t.e && t.d) {
            if (t.e >= Date.now()) {
                return t.d;
            }
            throw new EncryptionTimeoutError("token expired");
        }
        throw new EncryptionError("not supported token");
    }
}