"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActionReducer = void 0;
const rxjs_1 = require("rxjs");
const internal_1 = require("../internal");
const wallet_1 = require("./wallet");
const connect_1 = require("./connect");
const system_1 = require("./system");
class ActionReducer {
    locals;
    action$;
    handlers;
    constructor(locals) {
        this.locals = locals;
        this.action$ = new rxjs_1.Subject();
        this.handlers = new Map();
        this.action$.subscribe((action) => {
            internal_1.logger.info(`Received action '${action.type}'`);
        });
        for (const epic of this.getDefaultModules()) {
            this.addModule(epic);
        }
    }
    getDefaultModules() {
        return [
            wallet_1.walletModule,
            connect_1.connectModule,
            system_1.systemModule
        ];
    }
    addModule(epic) {
        epic.bindReducer(this.action$, this.handlers, this.locals);
    }
    async fromApi(req, res, action) {
        // const action = builder.create(req.body)
        const result = await this.reduce(action);
        if (result === undefined) {
            throw new Error(`No handler fount for action type '${action.type}'`);
        }
        res.status(result.status ?? 200).json(result.response);
    }
    async reduce(action) {
        const handler = this.handlers.get(action.type);
        let result;
        if (handler !== undefined) {
            result = await handler.handle(action);
        }
        this.action$.next(action);
        if (result !== undefined) {
            return result;
        }
    }
}
exports.ActionReducer = ActionReducer;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVkdWNlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9tYWluL2FjdGlvbnMvcmVkdWNlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSwrQkFBOEI7QUFJOUIsMENBQTRDO0FBRzVDLHFDQUF1QztBQUN2Qyx1Q0FBeUM7QUFDekMscUNBQXVDO0FBR3ZDLE1BQWEsYUFBYTtJQUlEO0lBSEosT0FBTyxDQUFpQjtJQUNqQyxRQUFRLENBQTRCO0lBRTlDLFlBQXVCLE1BQWM7UUFBZCxXQUFNLEdBQU4sTUFBTSxDQUFRO1FBQ25DLElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxjQUFPLEVBQVUsQ0FBQTtRQUNwQyxJQUFJLENBQUMsUUFBUSxHQUFHLElBQUksR0FBRyxFQUFFLENBQUE7UUFFekIsSUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQyxNQUFNLEVBQUUsRUFBRTtZQUNoQyxpQkFBTSxDQUFDLElBQUksQ0FBQyxvQkFBb0IsTUFBTSxDQUFDLElBQWMsR0FBRyxDQUFDLENBQUE7UUFDM0QsQ0FBQyxDQUFDLENBQUE7UUFFRixLQUFLLE1BQU0sSUFBSSxJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxFQUFFO1lBQzNDLElBQUksQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUE7U0FDckI7SUFDSCxDQUFDO0lBRVMsaUJBQWlCO1FBQ3pCLE9BQU87WUFDTCxxQkFBWTtZQUNaLHVCQUFhO1lBQ2IscUJBQVk7U0FDYixDQUFBO0lBQ0gsQ0FBQztJQUVELFNBQVMsQ0FBRSxJQUFZO1FBQ3JCLElBQUksQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxJQUFJLENBQUMsUUFBUSxFQUFFLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQTtJQUM1RCxDQUFDO0lBRUQsS0FBSyxDQUFDLE9BQU8sQ0FDWCxHQUFnQyxFQUNoQyxHQUFhLEVBQ2IsTUFBUztRQUVULDBDQUEwQztRQUMxQyxNQUFNLE1BQU0sR0FBRyxNQUFNLElBQUksQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDeEMsSUFBSSxNQUFNLEtBQUssU0FBUyxFQUFFO1lBQ3hCLE1BQU0sSUFBSSxLQUFLLENBQUMscUNBQXFDLE1BQU0sQ0FBQyxJQUFjLEdBQUcsQ0FBQyxDQUFBO1NBQy9FO1FBQ0QsR0FBRyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxJQUFJLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUE7SUFDeEQsQ0FBQztJQUVELEtBQUssQ0FBQyxNQUFNLENBQTJCLE1BQW9CO1FBQ3pELE1BQU0sT0FBTyxHQUFHLElBQUksQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUM5QyxJQUFJLE1BQWdDLENBQUE7UUFDcEMsSUFBSSxPQUFPLEtBQUssU0FBUyxFQUFFO1lBQ3pCLE1BQU0sR0FBRyxNQUFNLE9BQU8sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUE7U0FDdEM7UUFFRCxJQUFJLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUV6QixJQUFJLE1BQU0sS0FBSyxTQUFTLEVBQUU7WUFDeEIsT0FBTyxNQUFNLENBQUE7U0FDZDtJQUNILENBQUM7Q0FDRjtBQXZERCxzQ0F1REMifQ==