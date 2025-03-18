declare module 'express-mongo-sanitize' {
  import { Request, Response, NextFunction } from 'express';
  
  interface MongoSanitizeOptions {
    replaceWith?: string;
    onSanitize?: (key: string, value: any) => void;
  }
  
  /**
   * Express middleware to sanitize user-supplied data to prevent MongoDB operator injection
   */
  function mongoSanitize(options?: MongoSanitizeOptions): (req: Request, res: Response, next: NextFunction) => void;
  
  export default mongoSanitize;
} 