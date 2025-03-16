import { Request, Response, NextFunction } from 'express';

/**
 * Async error handling wrapper to avoid try/catch blocks in controllers
 */
export const catchAsync = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        fn(req, res, next).catch(next);
      };
    };