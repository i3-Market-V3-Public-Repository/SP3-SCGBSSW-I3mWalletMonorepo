"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resourceUpdate = exports.resourceRead = exports.resourceDelete = exports.resourceCreate = exports.resourceList = void 0;
const internal_1 = require("@wallet/main/internal");
const async_handler_1 = require("./async-handler");
exports.resourceList = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory } = (0, internal_1.extractLocals)(req.app);
    const resp = await walletFactory.wallet.resourceList(req.query);
    res.json(resp);
});
exports.resourceCreate = (0, async_handler_1.asyncHandler)(async (req, res) => {
    const { walletFactory, sharedMemoryManager } = (0, internal_1.extractLocals)(req.app);
    const resp = await walletFactory.wallet.resourceCreate(req.body);
    // Update state
    const resources = await walletFactory.wallet.getResources();
    sharedMemoryManager.update((mem) => ({ ...mem, resources }));
    res.status(201).json(resp);
});
const resourceDelete = (req, res) => {
    const windowManager = req.app.locals.windowManager;
    windowManager.openSignWindow('hello');
    console.log('Hello world');
    res.send('Hello world');
};
exports.resourceDelete = resourceDelete;
const resourceRead = (req, res) => {
    const windowManager = req.app.locals.windowManager;
    windowManager.openSignWindow('hello');
    console.log('Hello world');
    res.send('Hello world');
};
exports.resourceRead = resourceRead;
const resourceUpdate = (req, res) => {
    const windowManager = req.app.locals.windowManager;
    windowManager.openSignWindow('hello');
    console.log('Hello world');
    res.send('Hello world');
};
exports.resourceUpdate = resourceUpdate;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2VzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL21haW4vYXBpL3JvdXRlcy9yZXNvdXJjZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBR0Esb0RBQW9FO0FBQ3BFLG1EQUE4QztBQUVqQyxRQUFBLFlBQVksR0FBRyxJQUFBLDRCQUFZLEVBQWtHLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDM0osTUFBTSxFQUFFLGFBQWEsRUFBRSxHQUFHLElBQUEsd0JBQWEsRUFBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7SUFDaEQsTUFBTSxJQUFJLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUE7SUFDL0QsR0FBRyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUNoQixDQUFDLENBQUMsQ0FBQTtBQUVXLFFBQUEsY0FBYyxHQUFHLElBQUEsNEJBQVksRUFBMkYsS0FBSyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtJQUN0SixNQUFNLEVBQUUsYUFBYSxFQUFFLG1CQUFtQixFQUFFLEdBQUcsSUFBQSx3QkFBYSxFQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUNyRSxNQUFNLElBQUksR0FBRyxNQUFNLGFBQWEsQ0FBQyxNQUFNLENBQUMsY0FBYyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQTtJQUVoRSxlQUFlO0lBQ2YsTUFBTSxTQUFTLEdBQUcsTUFBTSxhQUFhLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxDQUFBO0lBQzNELG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxFQUFFLFNBQVMsRUFBRSxDQUFDLENBQUMsQ0FBQTtJQUU1RCxHQUFHLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtBQUM1QixDQUFDLENBQUMsQ0FBQTtBQUVLLE1BQU0sY0FBYyxHQUFtQixDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsRUFBRTtJQUN6RCxNQUFNLGFBQWEsR0FBa0IsR0FBRyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsYUFBYSxDQUFBO0lBQ2pFLGFBQWEsQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFDLENBQUE7SUFDckMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUMsQ0FBQTtJQUMxQixHQUFHLENBQUMsSUFBSSxDQUFDLGFBQWEsQ0FBQyxDQUFBO0FBQ3pCLENBQUMsQ0FBQTtBQUxZLFFBQUEsY0FBYyxrQkFLMUI7QUFFTSxNQUFNLFlBQVksR0FBbUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEVBQUU7SUFDdkQsTUFBTSxhQUFhLEdBQWtCLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLGFBQWEsQ0FBQTtJQUNqRSxhQUFhLENBQUMsY0FBYyxDQUFDLE9BQU8sQ0FBQyxDQUFBO0lBQ3JDLE9BQU8sQ0FBQyxHQUFHLENBQUMsYUFBYSxDQUFDLENBQUE7SUFDMUIsR0FBRyxDQUFDLElBQUksQ0FBQyxhQUFhLENBQUMsQ0FBQTtBQUN6QixDQUFDLENBQUE7QUFMWSxRQUFBLFlBQVksZ0JBS3hCO0FBRU0sTUFBTSxjQUFjLEdBQW1CLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFO0lBQ3pELE1BQU0sYUFBYSxHQUFrQixHQUFHLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUE7SUFDakUsYUFBYSxDQUFDLGNBQWMsQ0FBQyxPQUFPLENBQUMsQ0FBQTtJQUNyQyxPQUFPLENBQUMsR0FBRyxDQUFDLGFBQWEsQ0FBQyxDQUFBO0lBQzFCLEdBQUcsQ0FBQyxJQUFJLENBQUMsYUFBYSxDQUFDLENBQUE7QUFDekIsQ0FBQyxDQUFBO0FBTFksUUFBQSxjQUFjLGtCQUsxQiJ9