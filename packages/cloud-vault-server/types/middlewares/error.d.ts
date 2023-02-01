import { NextFunction, Request, Response } from 'express';
import { HttpError } from 'express-openapi-validator/dist/framework/types';
export declare function errorMiddleware(err: HttpError, req: Request, res: Response, next: NextFunction): void;
