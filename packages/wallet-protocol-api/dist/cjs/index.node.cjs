'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

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

exports.WalletApi = WalletApi;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9tb2RlbHMvaWRlbnRpdGllcy50cyIsIi4uLy4uL3NyYy90cy9tb2RlbHMvcmVzb3VyY2VzLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy9kaXNjbG9zdXJlLnRzIiwiLi4vLi4vc3JjL3RzL21vZGVscy90cmFuc2FjdGlvbi50cyIsIi4uLy4uL3NyYy90cy9hcGkudHMiXSwic291cmNlc0NvbnRlbnQiOm51bGwsIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7TUFJYSxhQUFhO0lBQ3hCLFlBQXVCLEdBQWdCO1FBQWhCLFFBQUcsR0FBSCxHQUFHLENBQWE7S0FBSztJQUU1QyxNQUFNLElBQUksQ0FBRSxXQUFzRDtRQUNoRSxPQUFPLE1BQU0sSUFBSSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUM7WUFDakMsSUFBSSxFQUFFLGFBQWE7WUFDbkIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsV0FBd0Q7UUFDcEUsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxvQkFBb0I7WUFDMUIsTUFBTSxFQUFFLEtBQUs7U0FDZCxFQUFFLFNBQVMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2hEO0lBRUQsTUFBTSxNQUFNLENBQUUsSUFBNEM7UUFDeEQsT0FBTyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDO1lBQ2pDLElBQUksRUFBRSxhQUFhO1lBQ25CLE1BQU0sRUFBRSxNQUFNO1lBQ2QsT0FBTyxFQUFFLEVBQUUsY0FBYyxFQUFFLGtCQUFrQixFQUFFO1NBQ2hELEVBQUUsU0FBUyxFQUFFLFNBQVMsRUFBRSxJQUFJLENBQUMsQ0FBQTtLQUMvQjtJQUVELE1BQU0sSUFBSSxDQUFFLFVBQW1ELEVBQUUsSUFB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
