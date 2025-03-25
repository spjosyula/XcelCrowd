import { logger } from './logger';

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
    
    // Build base query
    let query = model.find(filter);
    
    // Apply custom modifications (like populate)
    if (queryModifier) {
      query = queryModifier(query);
    }
    
    // Apply pagination
    query = applyPaginationToQuery(query, options);
    
    // Execute query and count in parallel
    const [data, total] = await Promise.all([
      query.lean(),
      model.countDocuments(filter)
    ]);
    
    // Return standardized result
    return createPaginationResult<T>(data, total, page, limit);
  } catch (error) {
    logger.error('Pagination query error:', error);
    throw error;
  }
}