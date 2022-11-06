"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JwtCodeGenerator = void 0;
const wallet_protocol_1 = require("@i3m/wallet-protocol");
const jose_1 = require("jose");
class JwtCodeGenerator {
    key;
    locals;
    constructor(key, locals) {
        this.key = key;
        this.locals = locals;
    }
    async generate(masterKey) {
        const { settings } = this.locals;
        const payload = masterKey.toJSON();
        const iat = Math.trunc(new Date().getTime() / 1000);
        const token = new jose_1.EncryptJWT(payload)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setAudience(masterKey.from.name)
            .setIssuer(masterKey.from.name)
            .setSubject(masterKey.to.name)
            .setIssuedAt(iat);
        const connect = settings.get('connect');
        if (connect.enableTokenExpiration) {
            const exp = iat + connect.tokenTTL;
            token.setExpirationTime(exp);
        }
        const data = await token.encrypt(this.key);
        return Buffer.from(data, 'utf8');
    }
    async getMasterKey(code) {
        const jwt = Buffer.from(code).toString('utf8');
        const { payload } = await (0, jose_1.jwtDecrypt)(jwt, this.key);
        return await wallet_protocol_1.MasterKey.fromJSON(payload);
    }
}
exports.JwtCodeGenerator = JwtCodeGenerator;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY29kZS1nZW5lcmF0b3IuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbWFpbi9jb25uZWN0L2NvZGUtZ2VuZXJhdG9yLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLDBEQUErRDtBQUMvRCwrQkFBc0Q7QUFHdEQsTUFBYSxnQkFBZ0I7SUFDSjtJQUFxQztJQUE1RCxZQUF1QixHQUF5QixFQUFZLE1BQWM7UUFBbkQsUUFBRyxHQUFILEdBQUcsQ0FBc0I7UUFBWSxXQUFNLEdBQU4sTUFBTSxDQUFRO0lBQUksQ0FBQztJQUUvRSxLQUFLLENBQUMsUUFBUSxDQUFFLFNBQW9CO1FBQ2xDLE1BQU0sRUFBRSxRQUFRLEVBQUUsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFBO1FBQ2hDLE1BQU0sT0FBTyxHQUFHLFNBQVMsQ0FBQyxNQUFNLEVBQUUsQ0FBQTtRQUNsQyxNQUFNLEdBQUcsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksSUFBSSxFQUFFLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxDQUFDLENBQUE7UUFDbkQsTUFBTSxLQUFLLEdBQUcsSUFBSSxpQkFBVSxDQUFDLE9BQU8sQ0FBQzthQUNsQyxrQkFBa0IsQ0FBQyxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxDQUFDO2FBQ2xELFdBQVcsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQzthQUNoQyxTQUFTLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUM7YUFDOUIsVUFBVSxDQUFDLFNBQVMsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDO2FBQzdCLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUVuQixNQUFNLE9BQU8sR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxDQUFBO1FBQ3ZDLElBQUksT0FBTyxDQUFDLHFCQUFxQixFQUFFO1lBQ2pDLE1BQU0sR0FBRyxHQUFHLEdBQUcsR0FBRyxPQUFPLENBQUMsUUFBUSxDQUFBO1lBQ2xDLEtBQUssQ0FBQyxpQkFBaUIsQ0FBQyxHQUFHLENBQUMsQ0FBQTtTQUM3QjtRQUVELE1BQU0sSUFBSSxHQUFHLE1BQU0sS0FBSyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7UUFFMUMsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksRUFBRSxNQUFNLENBQUMsQ0FBQTtJQUNsQyxDQUFDO0lBRUQsS0FBSyxDQUFDLFlBQVksQ0FBRSxJQUFnQjtRQUNsQyxNQUFNLEdBQUcsR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUM5QyxNQUFNLEVBQUUsT0FBTyxFQUFFLEdBQUcsTUFBTSxJQUFBLGlCQUFVLEVBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUVuRCxPQUFPLE1BQU0sMkJBQVMsQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUE7SUFDMUMsQ0FBQztDQUNGO0FBL0JELDRDQStCQyJ9