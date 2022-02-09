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
            path: '/disclosure',
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL21vZGVscy9pZGVudGl0aWVzLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9yZXNvdXJjZXMudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL2Rpc2Nsb3N1cmUudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL3RyYW5zYWN0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL2FwaS50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ik1BSWEsYUFBYTtJQUN4QixZQUF1QixHQUFnQjtRQUFoQixRQUFHLEdBQUgsR0FBRyxDQUFhO0tBQUs7SUFFNUMsTUFBTSxJQUFJLENBQUUsV0FBc0Q7UUFDaEUsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxhQUFhO1lBQ25CLE1BQU0sRUFBRSxLQUFLO1NBQ2QsRUFBRSxTQUFTLEVBQUUsV0FBcUIsRUFBRSxTQUFTLENBQUMsQ0FBQTtLQUNoRDtJQUVELE1BQU0sTUFBTSxDQUFFLFdBQXdEO1FBQ3BFLE9BQU8sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQztZQUNqQyxJQUFJLEVBQUUsb0JBQW9CO1lBQzFCLE1BQU0sRUFBRSxLQUFLO1NBQ2QsRUFBRSxTQUFTLEVBQUUsV0FBcUIsRUFBRSxTQUFTLENBQUMsQ0FBQTtLQUNoRDtJQUVELE1BQU0sTUFBTSxDQUFFLElBQTRDO1FBQ3hELE9BQU8sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQztZQUNqQyxJQUFJLEVBQUUsYUFBYTtZQUNuQixNQUFNLEVBQUUsTUFBTTtZQUNkLE9BQU8sRUFBRSxFQUFFLGNBQWMsRUFBRSxrQkFBa0IsRUFBRTtTQUNoRCxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsSUFBSSxDQUFDLENBQUE7S0FDL0I7SUFFRCxNQUFNLElBQUksQ0FBRSxVQUFtRCxFQUFFLElBQTBDO1FB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
