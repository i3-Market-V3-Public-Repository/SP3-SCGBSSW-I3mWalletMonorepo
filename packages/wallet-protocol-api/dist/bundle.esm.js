class IdentitiesApi {
    constructor(api) {
        this.api = api;
    }
    async list(queryParams) {
        const response = await this.api.executeQuery({
            path: '/identities',
            method: 'GET'
        }, undefined, queryParams, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async select(queryParams) {
        const response = await this.api.executeQuery({
            path: '/identities/select',
            method: 'GET'
        }, undefined, queryParams, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async create(body) {
        const response = await this.api.executeQuery({
            path: '/identities',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, undefined, undefined, body);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async sign(pathParams, body) {
        const response = await this.api.executeQuery({
            path: '/identities/{did}/sign',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, pathParams, undefined, body);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async info(pathParams) {
        const response = await this.api.executeQuery({
            path: '/identities/{did}/info',
            method: 'GET'
        }, pathParams, undefined, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async deployTransaction(pathParams, body) {
        const response = await this.api.executeQuery({
            path: '/identities/{did}/deploy-tx',
            method: 'POST'
        }, pathParams, undefined, body);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class ResourcesApi {
    constructor(api) {
        this.api = api;
    }
    async list(options) {
        const response = await this.api.executeQuery({
            path: '/resources',
            method: 'GET'
        }, undefined, options, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
    async create(body) {
        const response = await this.api.executeQuery({
            path: '/resources',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, undefined, undefined, body);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class DisclosureApi {
    constructor(api) {
        this.api = api;
    }
    async disclose(pathParams) {
        const response = await this.api.executeQuery({
            path: '/disclosure/{jwt}',
            method: 'GET'
        }, pathParams, undefined, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class TransactionApi {
    constructor(api) {
        this.api = api;
    }
    async deploy(body) {
        const response = await this.api.executeQuery({
            path: '/transaction/deploy',
            method: 'POST'
        }, undefined, undefined, body);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class DidJwtApi {
    constructor(api) {
        this.api = api;
    }
    async verify(body) {
        const response = (await this.api.executeQuery({
            path: '/did-jwt/verify',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, undefined, undefined, body));
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class ProviderInfoApi {
    constructor(api) {
        this.api = api;
    }
    async get() {
        const response = await this.api.executeQuery({
            path: '/providerinfo',
            method: 'GET'
        }, undefined, undefined, undefined);
        if (response.code !== undefined) {
            throw new Error(`${response.code}: ${response.message}`);
        }
        return response;
    }
}

class WalletApi {
    constructor(session) {
        this.session = session;
        this.identities = new IdentitiesApi(this);
        this.transaction = new TransactionApi(this);
        this.resources = new ResourcesApi(this);
        this.disclosure = new DisclosureApi(this);
        this.didJwt = new DidJwtApi(this);
        this.providerinfo = new ProviderInfoApi(this);
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
