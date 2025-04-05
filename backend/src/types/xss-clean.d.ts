declare module 'xss-clean' {
  import { Request, Response, NextFunction } from 'express';
  
  /**
   * XSS Clean middleware
   */
  function xssClean(): (req: Request, res: Response, next: (err?: any) => void) => void;
  
  export default xssClean;
} 