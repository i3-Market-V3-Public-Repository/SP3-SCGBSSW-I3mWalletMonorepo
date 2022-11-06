"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalAuthentication = void 0;
const pbkdf2_hmac_1 = __importDefault(require("pbkdf2-hmac"));
const crypto_1 = __importDefault(require("crypto"));
const exceptions_1 = require("./exceptions");
class LocalAuthentication {
    locals;
    maxTries;
    passwordRegex;
    passwordRegexMessage;
    pekSettings;
    authSettings;
    pek;
    constructor(locals) {
        this.locals = locals;
        this.maxTries = 3;
        this.passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\W]{8,}$/;
        this.passwordRegexMessage = 'Password must fulfill: \n - Minimum eight characters.\n - At least one uppercase letter, one lowercase letter and one number. \n - Optional: Symbols ';
        this.pekSettings = {
            iterations: 50000,
            keyLength: 32,
            usage: 'pek'
        };
        this.authSettings = {
            iterations: 100000,
            keyLength: 32,
            usage: 'local'
        };
    }
    verifyPasswordRegex(password) {
        const match = password.match(this.passwordRegex) !== null;
        if (!match) {
            this.locals.toast.show({
                message: 'Incorrect password format',
                details: this.passwordRegexMessage,
                type: 'error'
            });
            return false;
        }
        return true;
    }
    async askValidPassword(message, extraChecks = async () => true) {
        const { dialog } = this.locals;
        let leftTries = this.maxTries;
        while (leftTries > 0) {
            const password = await dialog.text({
                message: message(leftTries--),
                allowCancel: false,
                hiddenText: true
            });
            if (password === undefined) {
                break;
            }
            if (!this.verifyPasswordRegex(password)) {
                continue;
            }
            if (await extraChecks(password)) {
                return password;
            }
            else {
                this.locals.toast.show({
                    message: 'Incorrect password',
                    type: 'error'
                });
            }
        }
    }
    async deriveKey(password, salt, settings) {
        let passwordBuffer;
        if (password instanceof ArrayBuffer) {
            passwordBuffer = password;
        }
        else {
            passwordBuffer = Buffer.from(password);
        }
        const usageBuffer = Buffer.from(settings.usage);
        const p = new Uint8Array(passwordBuffer.byteLength + usageBuffer.byteLength);
        p.set(new Uint8Array(passwordBuffer), 0);
        p.set(new Uint8Array(usageBuffer), passwordBuffer.byteLength);
        return await (0, pbkdf2_hmac_1.default)(p, salt, settings.iterations, settings.keyLength);
    }
    async initializePassword() {
        const message = (tries) => `You don't have an application password: setup a new one (${tries} left).\n ${this.passwordRegexMessage}`;
        const validPassword = await this.askValidPassword(message);
        if (validPassword === undefined) {
            throw new exceptions_1.AuthenticationError('tries exceeded');
        }
        const confirmedPassword = await this.askValidPassword((tries) => `Confirm your password (${tries} left).`, async (password) => validPassword === password);
        if (confirmedPassword === undefined) {
            throw new exceptions_1.AuthenticationError('unconfirmed password');
        }
        const salt = await crypto_1.default.randomBytes(16);
        const localAuth = await this.deriveKey(validPassword, salt, this.authSettings);
        const auth = {
            salt: salt.toString('base64'),
            localAuth: Buffer.from(localAuth).toString('base64')
        };
        this.locals.settings.set('auth', auth);
        this.pek = Buffer.from(await this.deriveKey(validPassword, salt, this.pekSettings));
    }
    async localAuthentication(auth) {
        const salt = Buffer.from(auth.salt, 'base64');
        const testLocalAuth = Buffer.from(auth.localAuth, 'base64');
        const message = (tries) => `Enter the application password. You have ${tries} left.`;
        const validPassword = await this.askValidPassword(message, async (password) => {
            const localAuth = await this.deriveKey(password, salt, this.authSettings);
            return testLocalAuth.equals(new Uint8Array(localAuth));
        });
        if (validPassword === undefined) {
            throw new exceptions_1.AuthenticationError('tries exceeded');
        }
        this.pek = Buffer.from(await this.deriveKey(validPassword, salt, this.pekSettings));
    }
    async authenticate() {
        const { settings } = this.locals;
        const auth = settings.get('auth');
        if (auth === undefined) {
            await this.initializePassword();
        }
        else {
            await this.localAuthentication(auth);
        }
    }
    get authenticated() {
        return this.pek !== undefined;
    }
    async computeWalletKey(walletUuid) {
        if (this.pek === undefined) {
            throw new Error('cannot compute wallet key before a correct application authentication');
        }
        const wkSettings = {
            ...this.pekSettings,
            usage: walletUuid
        };
        const salt = crypto_1.default.createHash('sha256').update(this.pek).digest();
        const wk = await this.deriveKey(this.pek, salt.subarray(0, 15), wkSettings);
        return Buffer.from(wk);
    }
}
exports.LocalAuthentication = LocalAuthentication;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aGVudGljYXRpb24uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi9hdXRoL2F1dGhlbnRpY2F0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBLDhEQUFvQztBQUNwQyxvREFBMkI7QUFJM0IsNkNBQWtEO0FBUWxELE1BQWEsbUJBQW1CO0lBU1A7SUFSYixRQUFRLENBQVE7SUFDaEIsYUFBYSxDQUFRO0lBQ3JCLG9CQUFvQixDQUFRO0lBRTVCLFdBQVcsQ0FBZTtJQUMxQixZQUFZLENBQWU7SUFDM0IsR0FBRyxDQUFTO0lBRXRCLFlBQXVCLE1BQWM7UUFBZCxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ25DLElBQUksQ0FBQyxRQUFRLEdBQUcsQ0FBQyxDQUFBO1FBQ2pCLElBQUksQ0FBQyxhQUFhLEdBQUcsa0RBQWtELENBQUE7UUFDdkUsSUFBSSxDQUFDLG9CQUFvQixHQUFHLHVKQUF1SixDQUFBO1FBQ25MLElBQUksQ0FBQyxXQUFXLEdBQUc7WUFDakIsVUFBVSxFQUFFLEtBQUs7WUFDakIsU0FBUyxFQUFFLEVBQUU7WUFDYixLQUFLLEVBQUUsS0FBSztTQUNiLENBQUE7UUFDRCxJQUFJLENBQUMsWUFBWSxHQUFHO1lBQ2xCLFVBQVUsRUFBRSxNQUFNO1lBQ2xCLFNBQVMsRUFBRSxFQUFFO1lBQ2IsS0FBSyxFQUFFLE9BQU87U0FDZixDQUFBO0lBQ0gsQ0FBQztJQUVPLG1CQUFtQixDQUFFLFFBQWdCO1FBQzNDLE1BQU0sS0FBSyxHQUFHLFFBQVEsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxLQUFLLElBQUksQ0FBQTtRQUN6RCxJQUFJLENBQUMsS0FBSyxFQUFFO1lBQ1YsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO2dCQUNyQixPQUFPLEVBQUUsMkJBQTJCO2dCQUNwQyxPQUFPLEVBQUUsSUFBSSxDQUFDLG9CQUFvQjtnQkFDbEMsSUFBSSxF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