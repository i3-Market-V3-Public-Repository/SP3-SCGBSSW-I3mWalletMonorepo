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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXNtLmpzIiwic291cmNlcyI6WyIuLi8uLi9zcmMvdHMvbW9kZWxzL2lkZW50aXRpZXMudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL3Jlc291cmNlcy50cyIsIi4uLy4uL3NyYy90cy9tb2RlbHMvdHJhbnNhY3Rpb24udHMiLCIuLi8uLi9zcmMvdHMvYXBpLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiTUFJYSxhQUFhO0lBQ3hCLFlBQXVCLEdBQWdCO1FBQWhCLFFBQUcsR0FBSCxHQUFHLENBQWE7S0FBSztJQUU1QyxNQUFNLElBQUksQ0FBRSxXQUFzRDtRQUNoRSxPQUFPLE1BQU0sSUFBSSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUM7WUFDakMsSUFBSSxFQUFFLGFBQWE7WUFDbkIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsV0FBd0Q7UUFDcEUsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxvQkFBb0I7WUFDMUIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsSUFBNEM7UUFDeEQsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxhQUFhO1lBQ25CLE1BQU0sRUFBRSxNQUFNO1lBQ2QsT0FBTyxFQUFFLEVBQUUsY0FBYyxFQUFFLGtCQUFrQixFQUFFO1NBQ2hELEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQTtLQUMvQjtJQUVELE1BQU0sSUFBSSxDQUFFLFVBQW1ELEVBQUUsSUFBMEM7UUFDekcsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFD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
