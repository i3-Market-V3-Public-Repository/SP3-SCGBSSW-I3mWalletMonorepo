import { RequestHandler, Request, Response, NextFunction } from 'express'

export const asyncHandler = <A = never, B = never, C = never, D = never, E extends Record<string, any>= never>(
  handler: (req: Request<A, B, C, D, E>, res: Response<B, E>, next: NextFunction) => Promise<void>
): RequestHandler<A, B, C, D, E> => (req: Request<A, B, C, D, E>, res: Response<B, E>, next: NextFunction) => {
  handler(req, res, next).catch((err) => {
    next(err)
  })
}
