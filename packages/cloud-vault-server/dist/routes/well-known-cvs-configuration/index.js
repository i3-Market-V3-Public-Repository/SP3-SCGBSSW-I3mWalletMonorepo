"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const config_1 = require("../../config");
exports.default = async () => {
    const router = (0, express_1.Router)();
    router.get('/.well-known/cvs-configuration', (req, res) => {
        res.json(config_1.wellKnownCvsConfiguration);
    });
    return router;
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvcm91dGVzL3dlbGwta25vd24tY3ZzLWNvbmZpZ3VyYXRpb24vaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxxQ0FBbUQ7QUFFbkQseUNBQXdEO0FBRXhELGtCQUFlLEtBQUssSUFBcUIsRUFBRTtJQUN6QyxNQUFNLE1BQU0sR0FBRyxJQUFBLGdCQUFNLEdBQUUsQ0FBQTtJQUV2QixNQUFNLENBQUMsR0FBRyxDQUFDLGdDQUFnQyxFQUN6QyxDQUFDLEdBQTRCLEVBQUUsR0FBd0UsRUFBRSxFQUFFO1FBQ3pHLEdBQUcsQ0FBQyxJQUFJLENBQUMsa0NBQXlCLENBQUMsQ0FBQTtJQUNyQyxDQUFDLENBQ0YsQ0FBQTtJQUNELE9BQU8sTUFBTSxDQUFBO0FBQ2YsQ0FBQyxDQUFBIn0=