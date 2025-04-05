import { Types } from 'mongoose';
import { ApiError } from './api.error';
import { HTTP_STATUS } from '../models/interfaces';

/**
 * Validates and normalizes a MongoDB ObjectId with enhanced error reporting
 * @param id - The ID to validate (string, ObjectId, or undefined)
 * @param entityName - Name of the entity for context-specific error messages
 * @param options - Additional validation options
 * @returns Normalized ObjectId string
 * @throws ApiError with detailed error information
 */
export const validateObjectId = (
  id: string | Types.ObjectId | unknown,
  entityName: string,
  options: {
    required?: boolean;
    errorStatus?: number;
    additionalContext?: string;
  } = {}
): string => {
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
        `${entityName} ID is required${additionalContext ? ': ' + additionalContext : ''}`
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
        `${entityName} ID cannot be empty${additionalContext ? ': ' + additionalContext : ''}`
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
      `${additionalContext ? '. ' + additionalContext : ''}`
    );
  }
  
  return idString;
};