import { NextFunction, Request, Response } from 'express';
export declare function errorMiddleware(err: unknown, req: Request, res: Response, next: NextFunction): void;
