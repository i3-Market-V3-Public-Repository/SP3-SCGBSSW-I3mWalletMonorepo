'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

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

exports.WalletApi = WalletApi;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgubm9kZS5janMiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy90cy9hcGktbWV0aG9kLnRzIiwiLi4vLi4vc3JjL3RzL2FwaS50cyJdLCJzb3VyY2VzQ29udGVudCI6bnVsbCwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQVNPLE1BQU0sY0FBYyxHQUF1RDtJQUNoRixJQUFJLEVBQUUsWUFBWTtJQUNsQixNQUFNLEVBQUUsS0FBSztDQUNkOztNQ0xZLFNBQVM7SUFDcEIsWUFBdUIsT0FBd0M7UUFBeEMsWUFBTyxHQUFQLE9BQU8sQ0FBaUM7S0FBSTtJQUUzRCxNQUFNLFlBQVksQ0FBSSxHQUFpQixFQUFFLFdBQW1CLEVBQUUsVUFBZ0I7UUFDcEYsSUFBSSxpQkFBaUIsR0FBRyxFQUFFLENBQUE7UUFDMUIsSUFBSSxXQUFXLEtBQUssU0FBUyxFQUFFO1lBQzdCLGlCQUFpQixHQUFHLEdBQUcsR0FBRyxNQUFNO2lCQUM3QixJQUFJLENBQUMsV0FBVyxDQUFDO2lCQUNqQixHQUFHLENBQUMsQ0FBQyxHQUFHLEtBQUssR0FBRyxrQkFBa0IsQ0FBQyxHQUFHLENBQUMsSUFBSSxrQkFBa0IsQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDO2lCQUNsRixJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7U0FDYjtRQUVELElBQUksSUFBSSxDQUFBO1FBQ1IsSUFBSSxVQUFVLEtBQUssU0FBUyxFQUFFO1lBQzVCLElBQUksR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxDQUFBO1NBQzlCO1FBRUQsTUFBTSxHQUFHLEdBQUcsR0FBRyxDQUFDLElBQUksR0FBRyxpQkFBaUIsQ0FBQTtRQUN4QyxNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDO1lBQ25DLEdBQUc7WUFDSCxJQUFJLEVBQUU7Z0JBQ0osT0FBTyxFQUFFLEdBQUcsQ0FBQyxPQUFPO2dCQUNwQixNQUFNLEVBQUUsR0FBRyxDQUFDLE1BQU07Z0JBQ2xCLElBQUk7YUFDTDtTQUNGLENBQUMsQ0FBQTtRQUNGLE9BQU8sSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7S0FDN0I7SUFFRCxNQUFNLFlBQVksQ0FBRSxXQUFzRDtRQUN4RSxPQUFPLE1BQU0sSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLEVBQUUsV0FBcUIsRUFBRSxTQUFTLENBQUMsQ0FBQTtLQUNqRjs7Ozs7In0=
