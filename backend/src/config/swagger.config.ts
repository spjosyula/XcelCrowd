import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { Express, RequestHandler, Request, Response, NextFunction } from 'express';
import { version } from '../../package.json';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'XcelCrowd API Documentation',
      version,
      description: 'API documentation for XcelCrowd platform - A student-only platform connecting university talent with industry challenges. This platform enables students to build professional profiles, engage with company challenges, and receive professional feedback.',
      license: {
        name: 'Proprietary',
        url: 'https://xcelcrowd.com',
      },
      contact: {
        name: 'XcelCrowd Support',
        url: 'https://xcelcrowd.com/support',
        email: 'support@xcelcrowd.com',
      },
    },
    servers: [
      {
        url: '/api',
        description: 'API Server',
      },
    ],
    tags: [
      {
        name: 'Authentication',
        description: 'API endpoints for user authentication and authorization'
      },
      {
        name: 'Users',
        description: 'User management operations'
      },
      {
        name: 'Profiles',
        description: 'User profile management for students, companies, and architects'
      },
      {
        name: 'Challenges',
        description: 'Operations for managing company challenges'
      },
      {
        name: 'Solutions',
        description: 'Operations for student solutions to challenges'
      },
      {
        name: 'Architects',
        description: 'Operations specific to architect users'
      },
      {
        name: 'Dashboard',
        description: 'Dashboard statistics and metrics'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      schemas: {
        Error: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              example: 'error',
            },
            message: {
              type: 'string',
              example: 'Something went wrong',
            },
            code: {
              type: 'string',
              example: 'INTERNAL_SERVER_ERROR',
            },
            errors: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  path: {
                    type: 'string',
                    example: 'email'
                  },
                  message: {
                    type: 'string',
                    example: 'Invalid email format'
                  },
                  code: {
                    type: 'string',
                    example: 'invalid_string'
                  }
                }
              },
              description: 'Validation errors',
            }
          },
        },
        ValidationError: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              example: 'error',
            },
            message: {
              type: 'string',
              example: 'Validation failed',
            },
            code: {
              type: 'string',
              example: 'VALIDATION_ERROR',
            },
            errors: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  path: {
                    type: 'string',
                    example: 'email'
                  },
                  message: {
                    type: 'string',
                    example: 'Invalid email format'
                  },
                  code: {
                    type: 'string',
                    example: 'invalid_string'
                  }
                }
              }
            }
          },
        },
        Success: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              example: 'success',
            },
            data: {
              type: 'object',
            },
            message: {
              type: 'string',
              example: 'Operation successful',
            },
          },
        },
        Pagination: {
          type: 'object',
          properties: {
            page: {
              type: 'integer',
              example: 1,
              description: 'Current page number'
            },
            limit: {
              type: 'integer',
              example: 10,
              description: 'Number of items per page'
            },
            total: {
              type: 'integer',
              example: 100,
              description: 'Total number of items'
            },
            totalPages: {
              type: 'integer',
              example: 10,
              description: 'Total number of pages'
            }
          }
        }
      },
      responses: {
        UnauthorizedError: {
          description: 'Access token is missing or invalid',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              }
            }
          }
        },
        ForbiddenError: {
          description: 'User does not have permission to access this resource',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              }
            }
          }
        },
        ValidationError: {
          description: 'Validation failed for the request',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/ValidationError'
              }
            }
          }
        },
        NotFoundError: {
          description: 'The requested resource was not found',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              }
            }
          }
        },
        InternalServerError: {
          description: 'Server encountered an error',
          content: {
            'application/json': {
              schema: {
                $ref: '#/components/schemas/Error'
              }
            }
          }
        }
      },
      parameters: {
        PageParam: {
          name: 'page',
          in: 'query',
          schema: {
            type: 'integer',
            minimum: 1,
            default: 1
          },
          description: 'Page number for pagination'
        },
        LimitParam: {
          name: 'limit',
          in: 'query',
          schema: {
            type: 'integer',
            minimum: 1,
            maximum: 100,
            default: 10
          },
          description: 'Number of items per page'
        },
        SortParam: {
          name: 'sort',
          in: 'query',
          schema: {
            type: 'string',
            example: 'createdAt:desc'
          },
          description: 'Sort field and direction (field:asc or field:desc)'
        },
        IdParam: {
          name: 'id',
          in: 'path',
          required: true,
          schema: {
            type: 'string',
            pattern: '^[0-9a-fA-F]{24}$'
          },
          description: 'MongoDB ObjectId'
        }
      }
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [
    './src/routes/*.ts',
    './src/models/*.ts',
    './src/types/*.ts',
    './src/types/swagger/*.ts',
    './src/controllers/*.ts'
  ],
};
// Cache for Swagger specs to avoid regenerating on every request
let cachedSpecs: any = null;

// Function to fix common issues in the generated specs
const fixSwaggerSpec = (spec: any) => {
  // Deep clone to avoid modifying the original
  const fixedSpec = JSON.parse(JSON.stringify(spec));
  
  // Fix array references that can cause "Cannot read property '0' of undefined" errors
  const fixArrayReferences = (obj: any) => {
    if (!obj || typeof obj !== 'object') return;
    
    Object.keys(obj).forEach(key => {
      if (obj[key] && typeof obj[key] === 'object') {
        // Check if this is an array operation that might cause issues
        if (Array.isArray(obj[key])) {
          // Clean up null/undefined entries in arrays
          obj[key] = obj[key].filter(item => item !== undefined && item !== null);
        }
        
        // Check for problematic $ref properties
        if (obj[key].$ref && typeof obj[key].$ref === 'string') {
          // Ensure references are properly formatted
          if (!obj[key].$ref.startsWith('#/')) {
            delete obj[key].$ref;
          }
        }
        
        // Recursively process nested objects
        fixArrayReferences(obj[key]);
      }
    });
  };
  
  fixArrayReferences(fixedSpec);
  return fixedSpec;
};

// Function to get Swagger specs (with lazy generation and caching)
const getSpecs = () => {
  if (!cachedSpecs) {
    console.log('Generating Swagger documentation...');
    try {
      // Generate the raw specs
      const rawSpecs = swaggerJsdoc(options);
      // Fix and cache the specs
      cachedSpecs = fixSwaggerSpec(rawSpecs);
      console.log('Swagger documentation generated successfully');
    } catch (error) {
      console.error('Error generating Swagger documentation:', error);
      // Provide a minimal fallback spec on error
      cachedSpecs = {
        openapi: '3.0.0',
        info: {
          title: 'XcelCrowd API Documentation',
          version,
          description: 'API documentation is currently unavailable. Please try again later.'
        },
        paths: {}
      };
    }
  }
  return cachedSpecs;
};

// Function to set up Swagger UI with Express
export const setupSwagger = (app: Express) => {
  // Serve Swagger UI - Use the getSpecs function to get specs on demand
  // Define interfaces for Swagger UI options
  interface SwaggerUIOptions {
    explorer: boolean;
    customCss: string;
    swaggerOptions: {
      persistAuthorization: boolean;
      docExpansion: string;
      filter: boolean;
      displayRequestDuration: boolean;
      tryItOutEnabled: boolean;
    };
  }

  // Add types to the middleware
  app.use('/api-docs', swaggerUi.serve, (req: Request, res: Response, next: NextFunction) => {
    // Generate specs on first access, not at server startup
    const specs: any = getSpecs();
    const uiHandler: RequestHandler = swaggerUi.setup(specs, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }',
      swaggerOptions: {
        persistAuthorization: true,
        docExpansion: 'none',
        filter: true,
        displayRequestDuration: true,
        tryItOutEnabled: true
      }
    } as SwaggerUIOptions);
    return uiHandler(req, res, next);
  });
  
  // Endpoint to get the swagger JSON
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(getSpecs());
  });
  
  console.log('📚 Swagger documentation initialized at /api-docs');
};

// Clear cache function - for testing or manual cache refresh
export const clearSwaggerCache = () => {
  cachedSpecs = null;
  console.log('Swagger documentation cache cleared');
};