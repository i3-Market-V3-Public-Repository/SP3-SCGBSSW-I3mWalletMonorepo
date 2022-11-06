"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.iterateObservable = void 0;
// eslint-disable-next-line @typescript-eslint/promise-function-async
function iterateObservable(obs$, iter) {
    return new Promise((resolve) => {
        const subscription = obs$.subscribe({
            next(value) {
                iter(value).then(ret => {
                    if (ret !== undefined) {
                        subscription.unsubscribe();
                        resolve({ completed: false, value: ret });
                    }
                }).catch(err => {
                    throw err;
                });
            },
            complete() {
                resolve({ completed: true });
            }
        });
    });
}
exports.iterateObservable = iterateObservable;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaXRlcmF0ZS1vYnNlcnZhYmxlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi91dGlsL2l0ZXJhdGUtb2JzZXJ2YWJsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFTQSxxRUFBcUU7QUFDckUsU0FBZ0IsaUJBQWlCLENBQy9CLElBQW1CLEVBQ25CLElBQTJCO0lBRTNCLE9BQU8sSUFBSSxPQUFPLENBQW9CLENBQUMsT0FBTyxFQUFFLEVBQUU7UUFDaEQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQztZQUNsQyxJQUFJLENBQUUsS0FBSztnQkFDVCxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFO29CQUNyQixJQUFJLEdBQUcsS0FBSyxTQUFTLEVBQUU7d0JBQ3JCLFlBQVksQ0FBQyxXQUFXLEVBQUUsQ0FBQTt3QkFDMUIsT0FBTyxDQUFDLEVBQUUsU0FBUyxFQUFFLEtBQUssRUFBRSxLQUFLLEVBQUUsR0FBRyxFQUFFLENBQUMsQ0FBQTtxQkFDMUM7Z0JBQ0gsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxFQUFFO29CQUNiLE1BQU0sR0FBRyxDQUFBO2dCQUNYLENBQUMsQ0FBQyxDQUFBO1lBQ0osQ0FBQztZQUNELFFBQVE7Z0JBQ04sT0FBTyxDQUFDLEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxDQUFDLENBQUE7WUFDOUIsQ0FBQztTQUNGLENBQUMsQ0FBQTtJQUNKLENBQUMsQ0FBQyxDQUFBO0FBQ0osQ0FBQztBQXJCRCw4Q0FxQkMifQ==