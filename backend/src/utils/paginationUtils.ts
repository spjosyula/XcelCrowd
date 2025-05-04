import { logger } from './logger';
import { MongoSanitizer } from './mongo.sanitize';

/**
 * Standard pagination options interface
 */
export interface PaginationOptions {
  page?: number | string;
  limit?: number | string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  maxLimit?: number;
  status?: string;
}

/**
 * Standard pagination results interface
 */
export interface PaginationResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPrevPage: boolean;
}

/**
 * Process pagination options to standardized values
 * @param options - Raw pagination options
 * @returns Normalized pagination parameters
 */
export function normalizePaginationOptions(options: PaginationOptions): {
  page: number;
  limit: number;
  skip: number;
  sortOptions: Record<string, 1 | -1>;
} {
  // Parse string values if needed
  const pageValue = typeof options.page === 'string' ? parseInt(options.page) : options.page;
  const limitValue = typeof options.limit === 'string' ? parseInt(options.limit) : options.limit;
  
  // Apply defaults and constraints
  const page = Math.max(1, pageValue || 1);
  const maxLimit = options.maxLimit || 100;
  const limit = Math.min(Math.max(1, limitValue || 10), maxLimit);
  const skip = (page - 1) * limit;
  
  // Create sort options
  const sortOptions: Record<string, 1 | -1> = {};
  const sortBy = options.sortBy || 'createdAt';
  sortOptions[sortBy] = options.sortOrder === 'asc' ? 1 : -1;
  
  return { page, limit, skip, sortOptions };
}

/**
 * Create pagination result object
 * @param data - The data array
 * @param total - Total number of items (before pagination)
 * @param page - Current page number
 * @param limit - Items per page
 * @returns Standard pagination result
 */
export function createPaginationResult<T>(
  data: T[],
  total: number,
  page: number,
  limit: number
): PaginationResult<T> {
  const totalPages = Math.ceil(total / limit);
  
  return {
    data,
    total,
    page,
    limit,
    totalPages,
    hasNextPage: page < totalPages,
    hasPrevPage: page > 1
  };
}

/**
 * Apply pagination to a Mongoose query
 * @param query - Mongoose query
 * @param options - Pagination options
 * @returns Modified query with pagination applied
 */
export function applyPaginationToQuery(query: any, options: PaginationOptions): any {
  const { skip, limit, sortOptions } = normalizePaginationOptions(options);
  
  return query.sort(sortOptions).skip(skip).limit(limit);
}

/**
 * Execute a paginated query with total count
 * @param model - Mongoose model
 * @param filter - Query filter
 * @param options - Pagination options
 * @param queryModifier - Optional function to modify the query (for populate, etc.)
 * @returns Pagination result
 */
export async function executePaginatedQuery<T>(
  model: any,
  filter: Record<string, any>,
  options: PaginationOptions,
  queryModifier?: (query: any) => any
): Promise<PaginationResult<T>> {
  try {
    const { page, limit } = normalizePaginationOptions(options);
    
    // Sanitize sort options
    const validatedOptions = validateAndSanitizeSortOptions(options);
    
    // Validate and sanitize filter to prevent NoSQL injection
    const sanitizedFilter = sanitizeFilter(filter);
    
    // Build base query with sanitized filter
    let query = model.find(sanitizedFilter);
    
    // Apply custom modifications (like populate)
    if (queryModifier) {
      query = queryModifier(query);
    }
    
    // Apply pagination with validated options
    query = applyPaginationToQuery(query, validatedOptions);
    
    // Execute query and count in parallel
    const [data, total] = await Promise.all([
      query.lean(),
      model.countDocuments(sanitizedFilter)
    ]);
    
    // Return standardized result
    return createPaginationResult<T>(data, total, page, limit);
  } catch (error) {
    logger.error('Pagination query error:', error);
    throw error;
  }
}

/**
 * Validate and sanitize sort options to prevent injection attacks
 * @param options - Raw pagination options
 * @returns Validated and sanitized pagination options
 */
function validateAndSanitizeSortOptions(options: PaginationOptions): PaginationOptions {
  const sanitizedOptions: PaginationOptions = {
    page: options.page,
    limit: options.limit,
    maxLimit: options.maxLimit
  };
  
  // Validate sortBy to only allow alphanumeric and underscore characters
  // This prevents NoSQL injection via sort field names
  if (options.sortBy) {
    const safeFieldPattern = /^[a-zA-Z0-9_\.]+$/;
    if (!safeFieldPattern.test(options.sortBy)) {
      logger.warn(`Potentially unsafe sort field rejected: ${options.sortBy}`);
      sanitizedOptions.sortBy = 'createdAt'; // Default to safe field
    } else {
      sanitizedOptions.sortBy = options.sortBy;
    }
  }
  
  // Validate sortOrder to only allow 'asc' or 'desc'
  if (options.sortOrder && ['asc', 'desc'].includes(options.sortOrder)) {
    sanitizedOptions.sortOrder = options.sortOrder;
  } else {
    sanitizedOptions.sortOrder = 'desc'; // Default
  }
  
  return sanitizedOptions;
}

/**
 * Sanitize filter object to prevent NoSQL injection
 * @param filter - Raw filter object
 * @returns Sanitized filter object
 */
function sanitizeFilter(filter: Record<string, any>): Record<string, any> {
  const sanitizedFilter: Record<string, any> = {};
  
  // Process each filter property
  for (const [key, value] of Object.entries(filter)) {
    // Skip undefined or null values
    if (value === undefined || value === null) continue;
    
    // Handle special $or operator
    if (key === '$or' && Array.isArray(value)) {
      sanitizedFilter.$or = value.map(item => sanitizeFilter(item));
      continue;
    }
    
    // Use $eq for simple value types to prevent injection
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      sanitizedFilter[key] = { $eq: value };
    } else if (value instanceof Date) {
      sanitizedFilter[key] = { $eq: value };
    } else if (typeof value === 'object') {
      // For objects that might already contain MongoDB operators
      const safeOperations: Record<string, any> = {};
      const allowedOperators = ['$eq', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$regex', '$options'];
      
      // Check if it's a MongoDB query operator object
      const hasOperators = Object.keys(value).some(k => k.startsWith('$'));
      
      if (hasOperators) {
        // If it has operators, only allow whitelisted ones
        for (const [op, opValue] of Object.entries(value)) {
          if (allowedOperators.includes(op)) {
            // Special handling for regex to prevent ReDoS
            if (op === '$regex' && typeof opValue === 'string') {
              try {
                // Use MongoSanitizer for safe regex
                const safeRegex = MongoSanitizer.buildSafeRegexCondition(opValue);
                safeOperations.$regex = safeRegex.$regex;
                safeOperations.$options = safeRegex.$options;
              } catch (error) {
                logger.warn(`Invalid regex pattern rejected: ${opValue}`);
                // Skip this operator if regex is invalid
              }
            } else {
              safeOperations[op] = opValue;
            }
          }
        }
        
        if (Object.keys(safeOperations).length > 0) {
          sanitizedFilter[key] = safeOperations;
        }
      } else {
        // If not an operator object, treat as literal value
        sanitizedFilter[key] = { $eq: value };
      }
    }
  }
  
  return sanitizedFilter;
}