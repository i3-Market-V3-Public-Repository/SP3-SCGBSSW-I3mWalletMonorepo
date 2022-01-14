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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguYnJvd3Nlci5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL21vZGVscy9pZGVudGl0aWVzLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9yZXNvdXJjZXMudHMiLCIuLi8uLi9zcmMvdHMvbW9kZWxzL3RyYW5zYWN0aW9uLnRzIiwiLi4vLi4vc3JjL3RzL2FwaS50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ik1BSWEsYUFBYTtJQUN4QixZQUF1QixHQUFnQjtRQUFoQixRQUFHLEdBQUgsR0FBRyxDQUFhO0tBQUs7SUFFNUMsTUFBTSxJQUFJLENBQUUsV0FBc0Q7UUFDaEUsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxhQUFhO1lBQ25CLE1BQU0sRUFBRSxLQUFLO1NBQ2QsRUFBRSxTQUFTLEVBQUUsV0FBcUIsRUFBRSxTQUFTLENBQUMsQ0FBQTtLQUNoRDtJQUVELE1BQU0sTUFBTSxDQUFFLFdBQXdEO1FBQ3BFLE9BQU8sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQztZQUNqQyxJQUFJLEVBQUUsb0JBQW9CO1lBQzFCLE1BQU0sRUFBRSxLQUFLO1NBQ2QsRUFBRSxTQUFTLEVBQUUsV0FBcUIsRUFBRSxTQUFTLENBQUMsQ0FBQTtLQUNoRDtJQUVELE1BQU0sTUFBTSxDQUFFLElBQTRDO1FBQ3hELE9BQU8sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQztZQUNqQyxJQUFJLEVBQUUsYUFBYTtZQUNuQixNQUFNLEVBQUUsTUFBTTtZQUNkLE9BQU8sRUFBRSxFQUFFLGNBQWMsRUFBRSxrQkFBa0IsRUFBRTtTQUNoRCxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsSUFBSSxDQUFDLENBQUE7S0FDL0I7SUFFRCxNQUFNLElBQUksQ0FBRSxVQUFtRCxFQUFFLElBQTBDO1FBQ3pHLE9BQU8sTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFD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
