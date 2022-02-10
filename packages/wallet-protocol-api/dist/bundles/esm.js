class IdentitiesApi {
    constructor(api) {
        this.api = api;
    }
    async list(queryParams) {
        return await this.api.executeQuery({
            path: '/identities',
            method: 'GET'
        }, undefined, queryParams, undefined);
    }
    async select(queryParams) {
        return await this.api.executeQuery({
            path: '/identities/select',
            method: 'GET'
        }, undefined, queryParams, undefined);
    }
    async create(body) {
        return await this.api.executeQuery({
            path: '/identities',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, undefined, undefined, body);
    }
    async sign(pathParams, body) {
        return await this.api.executeQuery({
            path: '/identities/{did}/sign',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, pathParams, undefined, body);
    }
    async info(pathParams) {
        return await this.api.executeQuery({
            path: '/identities/{did}/info',
            method: 'GET'
        }, pathParams, undefined, undefined);
    }
    async deployTransaction(pathParams, body) {
        return await this.api.executeQuery({
            path: '/identities/{did}/deploy-tx',
            method: 'POST'
        }, pathParams, undefined, body);
    }
}

class ResourcesApi {
    constructor(api) {
        this.api = api;
    }
    async list() {
        return await this.api.executeQuery({
            path: '/resources',
            method: 'GET'
        }, undefined, undefined, undefined);
    }
    async create(body) {
        return await this.api.executeQuery({
            path: '/resources',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, undefined, undefined, body);
    }
}

class DisclosureApi {
    constructor(api) {
        this.api = api;
    }
    async disclose(pathParams) {
        return await this.api.executeQuery({
            path: '/disclosure/{jwt}',
            method: 'GET'
        }, pathParams, undefined, undefined);
    }
}

class TransactionApi {
    constructor(api) {
        this.api = api;
    }
    async deploy(body) {
        return await this.api.executeQuery({
            path: '/transaction/deploy',
            method: 'POST'
        }, undefined, undefined, body);
    }
}

class WalletApi {
    constructor(session) {
        this.session = session;
        this.identities = new IdentitiesApi(this);
        this.transaction = new TransactionApi(this);
        this.resources = new ResourcesApi(this);
        this.disclosure = new DisclosureApi(this);
    }
    async executeQuery(api, pathParams, queryParams, bodyObject) {
        let queryParamsString = '';
        if (queryParams !== undefined) {
            queryParamsString = '?' + Object
                .keys(queryParams)
                .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
                .join('&');
        }
        let body;
        if (bodyObject !== undefined) {
            body = JSON.stringify(bodyObject);
        }
        let url = api.path + queryParamsString;
        if (pathParams !== undefined) {
            for (const [key, value] of Object.entries(pathParams)) {
                url = url.replace(`{${key}}`, value);
            }
        }
        const resp = await this.session.send({
            url,
            init: {
                headers: api.headers,
                method: api.method,
                body
            }
        });
        return JSON.parse(resp.body);
    }
}

export { WalletApi };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXNtLmpzIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHMvbW9kZWxzL2lkZW50aXRpZXMudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL3Jlc291cmNlcy50cyIsIi4uLy4uL3NyYy90cy9tb2RlbHMvZGlzY2xvc3VyZS50cyIsIi4uLy4uL3NyYy90cy9tb2RlbHMvdHJhbnNhY3Rpb24udHMiLCIuLi8uLi9zcmMvdHMvYXBpLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiTUFJYSxhQUFhO0lBQ3hCLFlBQXVCLEdBQWdCO1FBQWhCLFFBQUcsR0FBSCxHQUFHLENBQWE7S0FBSztJQUU1QyxNQUFNLElBQUksQ0FBRSxXQUFzRDtRQUNoRSxPQUFPLE1BQU0sSUFBSSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUM7WUFDakMsSUFBSSxFQUFFLGFBQWE7WUFDbkIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsV0FBd0Q7UUFDcEUsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxvQkFBb0I7WUFDMUIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsSUFBNEM7UUFDeEQsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxhQUFhO1lBQ25CLE1BQU0sRUFBRSxNQUFNO1lBQ2QsT0FBTyxFQUFFLEVBQUUsY0FBYyxFQUFFLGtCQUFrQixFQUFFO1NBQ2hELEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQTtLQUMvQjtJQUVELE1BQU0sSUFBSSxDQUFFLFVBQW1ELEVBQUUsSUFBMEM7UUFDekcsT0FB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
