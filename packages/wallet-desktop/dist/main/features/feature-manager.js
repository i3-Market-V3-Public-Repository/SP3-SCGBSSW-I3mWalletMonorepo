"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FeatureManager = void 0;
const internal_1 = require("@wallet/main/internal");
class FeatureManager {
    features;
    constructor() {
        this.features = new Map();
    }
    static CreateFeature(handler, opts) {
        return { handler, opts };
    }
    addFeature(feature) {
        const name = feature.handler.name;
        if (this.features.has(name)) {
            internal_1.logger.error(`Feature with name '${name}' already set`);
            return;
        }
        this.features.set(name, feature);
    }
    async clearFeatures(locals) {
        for (const [, feature] of this.features) {
            if (feature.handler.stop !== undefined) {
                await feature.handler.stop(feature.opts, locals);
            }
        }
        this.features.clear();
    }
    async start(locals) {
        for (const [, feature] of this.features) {
            if (feature.handler.start !== undefined) {
                await feature.handler.start(feature.opts, locals);
            }
        }
    }
}
exports.FeatureManager = FeatureManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZmVhdHVyZS1tYW5hZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL21haW4vZmVhdHVyZXMvZmVhdHVyZS1tYW5hZ2VyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUNBLG9EQUFzRDtBQVF0RCxNQUFhLGNBQWM7SUFDekIsUUFBUSxDQUEyQjtJQUNuQztRQUNFLElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBSSxHQUFHLEVBQUUsQ0FBQTtJQUMzQixDQUFDO0lBRUQsTUFBTSxDQUFDLGFBQWEsQ0FBSyxPQUEwQixFQUFFLElBQVE7UUFDM0QsT0FBTyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsQ0FBQTtJQUMxQixDQUFDO0lBRUQsVUFBVSxDQUFLLE9BQW1CO1FBQ2hDLE1BQU0sSUFBSSxHQUFHLE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFBO1FBQ2pDLElBQUksSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEVBQUU7WUFDM0IsaUJBQU0sQ0FBQyxLQUFLLENBQUMsc0JBQXNCLElBQUksZUFBZSxDQUFDLENBQUE7WUFDdkQsT0FBTTtTQUNQO1FBRUQsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxDQUFBO0lBQ2xDLENBQUM7SUFFRCxLQUFLLENBQUMsYUFBYSxDQUFFLE1BQWM7UUFDakMsS0FBSyxNQUFNLENBQUMsRUFBRSxPQUFPLENBQUMsSUFBSSxJQUFJLENBQUMsUUFBUSxFQUFFO1lBQ3ZDLElBQUksT0FBTyxDQUFDLE9BQU8sQ0FBQyxJQUFJLEtBQUssU0FBUyxFQUFFO2dCQUN0QyxNQUFNLE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxJQUFJLEVBQUUsTUFBTSxDQUFDLENBQUE7YUFDakQ7U0FDRjtRQUNELElBQUksQ0FBQyxRQUFRLENBQUMsS0FBSyxFQUFFLENBQUE7SUFDdkIsQ0FBQztJQUVELEtBQUssQ0FBQyxLQUFLLENBQUUsTUFBYztRQUN6QixLQUFLLE1BQU0sQ0FBQyxFQUFFLE9BQU8sQ0FBQyxJQUFJLElBQUksQ0FBQyxRQUFRLEVBQUU7WUFDdkMsSUFBSSxPQUFPLENBQUMsT0FBTyxDQUFDLEtBQUssS0FBSyxTQUFTLEVBQUU7Z0JBQ3ZDLE1BQU0sT0FBTyxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxNQUFNLENBQUMsQ0FBQTthQUNsRDtTQUNGO0lBQ0gsQ0FBQztDQUNGO0FBcENELHdDQW9DQyJ9