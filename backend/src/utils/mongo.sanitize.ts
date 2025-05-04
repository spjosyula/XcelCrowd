import { Types } from 'mongoose';
import { escapeRegExp } from 'lodash';
import { ApiError } from './api.error';
import { HTTP_STATUS } from '../constants';
import { logger } from './logger';

/**
 * Utility class for MongoDB query sanitization
 * Provides methods to safely build MongoDB queries from user input
 */
export class MongoSanitizer {
  /**
   * Sanitizes a MongoDB ObjectId string
   * @param id - The ID to sanitize
   * @param entityName - Optional name of the entity for error messages
   * @throws ApiError if the ID is invalid
   */
  static sanitizeObjectId(id: any, entityName = 'document'): Types.ObjectId {
    if (!id) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `${entityName} ID is required`,
        true,
        'INVALID_ID'
      );
    }
    
    if (typeof id !== 'string' && !(id instanceof Types.ObjectId)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Invalid ${entityName} ID format`,
        true,
        'INVALID_ID_FORMAT'
      );
    }
    
    // If it's already an ObjectId, return it
    if (id instanceof Types.ObjectId) {
      return id;
    }
    
    // Validate the ID string
    if (!Types.ObjectId.isValid(id)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Invalid ${entityName} ID format`,
        true,
        'INVALID_ID_FORMAT'
      );
    }
    
    return new Types.ObjectId(id);
  }
  
  /**
   * Validates and normalizes a MongoDB ObjectId with enhanced error reporting
   * @param id - The ID to validate (string, ObjectId, or unknown)
   * @param entityName - Name of the entity for context-specific error messages
   * @param options - Additional validation options
   * @returns Normalized ObjectId string
   * @throws ApiError with detailed error information
   */
  static validateObjectId(
    id: string | Types.ObjectId | unknown,
    entityName: string,
    options: {
      required?: boolean;
      errorStatus?: number;
      additionalContext?: string;
    } = {}
  ): string {
    const { 
      required = true, 
      errorStatus = HTTP_STATUS.BAD_REQUEST,
      additionalContext = ''
    } = options;

    // Handle undefined or null
    if (id === undefined || id === null) {
      if (required) {
        throw new ApiError(
          errorStatus,
          `${entityName} ID is required${additionalContext ? ': ' + additionalContext : ''}`,
          true,
          'INVALID_ID'
        );
      }
      return '';
    }

    // Convert to string and trim
    const idString = String(id).trim();
    
    // Check if empty string
    if (idString === '') {
      if (required) {
        throw new ApiError(
          errorStatus,
          `${entityName} ID cannot be empty${additionalContext ? ': ' + additionalContext : ''}`,
          true,
          'INVALID_ID'
        );
      }
      return '';
    }
    
    // Validate ObjectId format
    if (!Types.ObjectId.isValid(idString)) {
      throw new ApiError(
        errorStatus,
        `Invalid ${entityName} ID format: Must be a 24-character hexadecimal string` +
        `${idString ? ` (received: "${idString}")` : ''}` +
        `${additionalContext ? '. ' + additionalContext : ''}`,
        true,
        'INVALID_ID_FORMAT'
      );
    }
    
    return idString;
  }
  
  /**
   * Safely creates an equality condition for MongoDB queries
   * Prevents NoSQL injection by ensuring the value is treated as a literal
   * @param value - The value to use in the equality condition
   */
  static buildEqualityCondition(value: any): { $eq: any } {
    return { $eq: value };
  }
  
  /**
   * Safely creates a regex search condition for MongoDB
   * Escapes special regex characters to prevent ReDoS attacks
   * @param searchTerm - The search term
   * @param options - MongoDB regex options (default: 'i' for case-insensitive)
   */
  static buildSafeRegexCondition(searchTerm: string, options = 'i'): { $regex: string, $options: string } {
    if (!searchTerm || typeof searchTerm !== 'string') {
      return { $regex: '', $options: options };
    }
    
    // Validate search term length to prevent DoS
    if (searchTerm.length > 100) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        'Search term exceeds maximum allowed length (100 characters)',
        true,
        'SEARCH_TERM_TOO_LONG'
      );
    }
    
    // Escape regex special characters to prevent ReDoS
    const sanitizedTerm = escapeRegExp(searchTerm.trim());
    
    return { $regex: sanitizedTerm, $options: options };
  }
  
  /**
   * Safely creates a numeric range condition
   * @param min - Minimum value (optional)
   * @param max - Maximum value (optional)
   */
  static buildNumericRangeCondition(min?: number, max?: number): any {
    const rangeCondition: any = {};
    
    if (min !== undefined) {
      if (typeof min !== 'number' || isNaN(min)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Minimum value must be a valid number',
          true,
          'INVALID_MIN_VALUE'
        );
      }
      rangeCondition.$gte = min;
    }
    
    if (max !== undefined) {
      if (typeof max !== 'number' || isNaN(max)) {
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          'Maximum value must be a valid number',
          true,
          'INVALID_MAX_VALUE'
        );
      }
      rangeCondition.$lte = max;
    }
    
    return rangeCondition;
  }
  
  /**
   * Validates sorting parameters
   * @param sortBy - Field to sort by
   * @param sortOrder - Sort direction ('asc' or 'desc')
   * @param allowedFields - Array of allowed fields for sorting
   */
  static validateSortParams(
    sortBy: string, 
    sortOrder: 'asc' | 'desc',
    allowedFields: string[] = []
  ): { sortBy: string, sortOrder: 1 | -1 } {
    // Validate sort field if allowedFields is provided
    if (allowedFields.length > 0 && !allowedFields.includes(sortBy)) {
      throw new ApiError(
        HTTP_STATUS.BAD_REQUEST,
        `Invalid sort field. Allowed fields: ${allowedFields.join(', ')}`,
        true,
        'INVALID_SORT_FIELD'
      );
    }
    
    return {
      sortBy,
      sortOrder: sortOrder === 'asc' ? 1 : -1
    };
  }
  
  /**
   * Safely builds a MongoDB query object from user input
   * @param baseQuery - Initial query object to extend
   * @param filters - User-provided filters
   * @param allowedFilters - Map of allowed filters and their types
   */
  static buildSafeQuery(
    baseQuery: Record<string, any>,
    filters: Record<string, any>,
    allowedFilters: Record<string, 'string' | 'number' | 'boolean' | 'objectId' | 'enum' | 'regex'>,
    enumValues: Record<string, string[]> = {}
  ): Record<string, any> {
    const safeQuery = { ...baseQuery };
    
    if (!filters) {
      return safeQuery;
    }
    
    // Process only allowed filters
    for (const [key, type] of Object.entries(allowedFilters)) {
      if (!(key in filters) || filters[key] === undefined || filters[key] === null) {
        continue;
      }
      
      const value = filters[key];
      
      try {
        switch (type) {
          case 'string':
            if (typeof value !== 'string') {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a string`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }
            safeQuery[key] = this.buildEqualityCondition(value);
            break;
            
          case 'number':
            const numValue = Number(value);
            if (isNaN(numValue)) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a number`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }
            safeQuery[key] = this.buildEqualityCondition(numValue);
            break;
            
          case 'boolean':
            let boolValue: boolean;
            if (typeof value === 'boolean') {
              boolValue = value;
            } else if (value === 'true') {
              boolValue = true;
            } else if (value === 'false') {
              boolValue = false;
            } else {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a boolean`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }
            safeQuery[key] = this.buildEqualityCondition(boolValue);
            break;
            
          case 'objectId':
            safeQuery[key] = this.sanitizeObjectId(value);
            break;
            
          case 'enum':
            if (!enumValues[key]) {
              throw new ApiError(
                HTTP_STATUS.INTERNAL_SERVER_ERROR,
                `Enum values not provided for ${key}`,
                true,
                'MISSING_ENUM_VALUES'
              );
            }
            if (!enumValues[key].includes(value)) {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `Invalid value for ${key}. Allowed values: ${enumValues[key].join(', ')}`,
                true,
                'INVALID_ENUM_VALUE'
              );
            }
            safeQuery[key] = this.buildEqualityCondition(value);
            break;
            
          case 'regex':
            if (typeof value !== 'string') {
              throw new ApiError(
                HTTP_STATUS.BAD_REQUEST,
                `${key} must be a string for search`,
                true,
                'INVALID_FILTER_TYPE'
              );
            }
            safeQuery[key] = this.buildSafeRegexCondition(value);
            break;
            
          default:
            logger.warn(`Unknown filter type: ${type} for key: ${key}`);
        }
      } catch (error) {
        if (error instanceof ApiError) throw error;
        
        throw new ApiError(
          HTTP_STATUS.BAD_REQUEST,
          `Invalid filter: ${key}`,
          true,
          'INVALID_FILTER'
        );
      }
    }
    
    return safeQuery;
  }
}