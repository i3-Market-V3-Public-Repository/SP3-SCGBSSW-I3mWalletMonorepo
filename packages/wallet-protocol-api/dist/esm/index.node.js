const GET_IDENTITIES = {
    path: 'identities',
    method: 'GET'
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5qcyIsInNvdXJjZXMiOlsiLi4vLi4vc3JjL3RzL2FwaS1tZXRob2QudHMiLCIuLi8uLi9zcmMvdHMvYXBpLnRzIl0sInNvdXJjZXNDb250ZW50IjpudWxsLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFTTyxNQUFNLGNBQWMsR0FBdUQ7SUFDaEYsSUFBSSxFQUFFLFlBQVk7SUFDbEIsTUFBTSxFQUFFLEtBQUs7Q0FDZDs7TUNMWSxTQUFTO0lBQ3BCLFlBQXVCLE9BQXdDO1FBQXhDLFlBQU8sR0FBUCxPQUFPLENBQWlDO0tBQUk7SUFFM0QsTUFBTSxZQUFZLENBQUksR0FBaUIsRUFBRSxXQUFtQixFQUFFLFVBQWdCO1FBQ3BGLElBQUksaUJBQWlCLEdBQUcsRUFBRSxDQUFBO1FBQzFCLElBQUksV0FBVyxLQUFLLFNBQVMsRUFBRTtZQUM3QixpQkFBaUIsR0FBRyxHQUFHLEdBQUcsTUFBTTtpQkFDN0IsSUFBSSxDQUFDLFdBQVcsQ0FBQztpQkFDakIsR0FBRyxDQUFDLENBQUMsR0FBRyxLQUFLLEdBQUcsa0JBQWtCLENBQUMsR0FBRyxDQUFDLElBQUksa0JBQWtCLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQztpQkFDbEYsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1NBQ2I7UUFFRCxJQUFJLElBQUksQ0FBQTtRQUNSLElBQUksVUFBVSxLQUFLLFNBQVMsRUFBRTtZQUM1QixJQUFJLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsQ0FBQTtTQUM5QjtRQUVELE1BQU0sR0FBRyxHQUFHLEdBQUcsQ0FBQyxJQUFJLEdBQUcsaUJBQWlCLENBQUE7UUFDeEMsTUFBTSxJQUFJLEdBQUcsTUFBTSxJQUFJLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQztZQUNuQyxHQUFHO1lBQ0gsSUFBSSxFQUFFO2dCQUNKLE9BQU8sRUFBRSxHQUFHLENBQUMsT0FBTztnQkFDcEIsTUFBTSxFQUFFLEdBQUcsQ0FBQyxNQUFNO2dCQUNsQixJQUFJO2FBQ0w7U0FDRixDQUFDLENBQUE7UUFDRixPQUFPLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO0tBQzdCO0lBRUQsTUFBTSxZQUFZLENBQUUsV0FBc0Q7UUFDeEUsT0FBTyxNQUFNLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxFQUFFLFdBQXFCLEVBQUUsU0FBUyxDQUFDLENBQUE7S0FDakY7Ozs7OyJ9
