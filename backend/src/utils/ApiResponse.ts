/**
 * Standard API response format
 */
export class ApiResponse<T> {
  success: boolean;
  message: string;
  data: T | null;
  metadata?: Record<string, any>;
  timestamp: string;
  requestId?: string;
  
  constructor(
    success = true,
    message = 'Operation successful',
    data: T | null = null,
    metadata?: Record<string, any>,
    requestId?: string
  ) {
    this.success = success;
    this.message = message;
    this.data = data;
    this.metadata = metadata;
    this.timestamp = new Date().toISOString();
    this.requestId = requestId;
  }
  
  /**
   * Create a successful response
   * @param data Response data
   * @param message Success message
   * @param metadata Additional metadata
   * @param requestId Request identifier for correlation
   */
  static success<T>(
    data: T, 
    message = 'Operation successful',
    metadata?: Record<string, any>,
    requestId?: string
  ): ApiResponse<T> {
    return new ApiResponse(true, message, data, metadata, requestId);
  }
  
  /**
   * Create an error response
   * @param message Error message
   * @param metadata Additional error metadata
   * @param requestId Request identifier for correlation
   */
  static error(
    message = 'Operation failed',
    metadata?: Record<string, any>,
    requestId?: string
  ): ApiResponse<null> {
    return new ApiResponse(false, message, null, metadata, requestId);
  }
  
  /**
   * Add pagination details to response metadata
   * @param page Current page number
   * @param limit Items per page
   * @param total Total number of items
   */
  withPagination(page: number, limit: number, total: number): ApiResponse<T> {
    const totalPages = Math.ceil(total / limit);
    
    this.metadata = {
      ...this.metadata,
      pagination: {
        page,
        limit,
        total,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    };
    
    return this;
  }
}