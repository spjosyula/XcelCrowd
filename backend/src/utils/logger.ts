import { createLogger, format, transports } from 'winston';
import { ENV } from '../constants';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid'; // Add uuid to your dependencies

const { combine, timestamp, printf, colorize } = format;

// Custom log format
const logFormat = printf(({ level, message, timestamp, requestId, ...metadata }) => {
  let metadataStr = '';
  if (Object.keys(metadata).length > 0) {
    metadataStr = JSON.stringify(metadata);
  }
  const reqIdStr = requestId ? ` [${requestId}]` : '';
  return `[${timestamp}]${reqIdStr} ${level}: ${message} ${metadataStr}`;
});

// Create logger instance
export const logger = createLogger({
  level: process.env.NODE_ENV === ENV.PRODUCTION ? 'info' : 'debug',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    logFormat
  ),
  defaultMeta: { service: 'xcelcrowd-api' },
  transports: [
    // Console transport
    new transports.Console({
      format: combine(
        colorize(),
        logFormat
      )
    })
  ],
  silent: process.env.NODE_ENV === ENV.TEST
});

// Add file transport in production
if (process.env.NODE_ENV === ENV.PRODUCTION) {
  logger.add(new transports.File({ 
    filename: 'logs/error.log', 
    level: 'error',
    maxsize: 10485760, // 10MB
    maxFiles: 5
  }));
  logger.add(new transports.File({ 
    filename: 'logs/combined.log',
    maxsize: 10485760, // 10MB
    maxFiles: 5
  }));
}

// Request tracking
declare global {
  namespace Express {
    interface Request {
      id?: string;
    }
  }
}

/**
 * Middleware to add request ID and log request details
 */
export const logRequest = (req: Request, res: Response, next: NextFunction) => {
  // Generate a unique request ID
  req.id = uuidv4();
  res.setHeader('X-Request-ID', req.id);
  
  // Log basic request info
  logger.info(`${req.method} ${req.originalUrl}`, {
    requestId: req.id,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    params: req.params,
    query: req.query,
    body: req.method !== 'GET' ? req.body : undefined
  });

  // Track response time
  const startTime = Date.now();
  
  // Log response details when finished
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    const logLevel = res.statusCode >= 400 ? 'warn' : 'info';
    
    logger[logLevel](`${req.method} ${req.originalUrl} ${res.statusCode} - ${responseTime}ms`, {
      requestId: req.id,
      statusCode: res.statusCode,
      responseTime
    });
  });
  
  next();
};