const GET_IDENTITIES = {
    path: 'identities'
};

class WalletApi {
    constructor(session) {
        this.session = session;
    }
    async executeQuery(api, queryParams, bodyObject) {
        let queryParamsString = '';
        if (queryParams !== undefined) {
            queryParamsString = '?' + Object
                .keys(queryParams)
                .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
                .join('&');
        }
        let body;
        if (bodyObject !== undefined) {
            body = JSON.parse(bodyObject);
        }
        const url = api.path + queryParamsString;
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
    async getIdentites(queryParams) {
        return await this.executeQuery(GET_IDENTITIES, queryParams, undefined);
    }
}

export { WalletApi };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2FwaS1tZXRob2QudHMiLCIuLi8uLi9zcmMvdHMvYXBpLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFTTyxNQUFNLGNBQWMsR0FBdUQ7SUFDaEYsSUFBSSxFQUFFLFlBQVk7Q0FDbkI7O01DSlksU0FBUztJQUNwQixZQUF1QixPQUF3QztRQUF4QyxZQUFPLEdBQVAsT0FBTyxDQUFpQztLQUFJO0lBRTNELE1BQU0sWUFBWSxDQUFJLEdBQWlCLEVBQUUsV0FBbUIsRUFBRSxVQUFnQjtRQUNwRixJQUFJLGlCQUFpQixHQUFHLEVBQUUsQ0FBQTtRQUMxQixJQUFJLFdBQVcsS0FBSyxTQUFTLEVBQUU7WUFDN0IsaUJBQWlCLEdBQUcsR0FBRyxHQUFHLE1BQU07aUJBQzdCLElBQUksQ0FBQyxXQUFXLENBQUM7aUJBQ2pCLEdBQUcsQ0FBQyxDQUFDLEdBQUcsS0FBSyxHQUFHLGtCQUFrQixDQUFDLEdBQUcsQ0FBQyxJQUFJLGtCQUFrQixDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFLENBQUM7aUJBQ2xGLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQTtTQUNiO1FBRUQsSUFBSSxJQUFJLENBQUE7UUFDUixJQUFJLFVBQVUsS0FBSyxTQUFTLEVBQUU7WUFDNUIsSUFBSSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsVUFBVSxDQUFDLENBQUE7U0FDOUI7UUFFRCxNQUFNLEdBQUcsR0FBRyxHQUFHLENBQUMsSUFBSSxHQUFHLGlCQUFpQixDQUFBO1FBQ3hDLE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUM7WUFDbkMsR0FBRztZQUNILElBQUksRUFBRTtnQkFDSixPQUFPLEVBQUUsR0FBRyxDQUFDLE9BQU87Z0JBQ3BCLE1BQU0sRUFBRSxHQUFHLENBQUMsTUFBTTtnQkFDbEIsSUFBSTthQUNMO1NBQ0YsQ0FBQyxDQUFBO1FBQ0YsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtLQUM3QjtJQUVELE1BQU0sWUFBWSxDQUFFLFdBQXNEO1FBQ3hFLE9BQU8sTUFBTSxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsRUFBRSxXQUFxQixFQUFFLFNBQVMsQ0FBQyxDQUFBO0tBQ2pGOzs7OzsifQ==
