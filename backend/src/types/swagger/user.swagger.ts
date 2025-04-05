/**
 * @swagger
 * components:
 *   schemas:
 *     UserRole:
 *       type: string
 *       enum:
 *         - student
 *         - company
 *         - architect
 *         - admin
 *       description: User role in the system
 *       example: student
 *     
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - role
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: MongoDB ObjectId
 *           example: 60d21b4667d0d8992e610c85
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address (unique)
 *           example: user@example.com
 *         role:
 *           $ref: '#/components/schemas/UserRole'
 *         isEmailVerified:
 *           type: boolean
 *           description: Whether the email has been verified
 *           example: false
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: User creation timestamp
 *           example: '2023-05-20T14:20:30.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: User last update timestamp
 *           example: '2023-05-20T14:20:30.000Z'
 *     
 *     UserWithProfile:
 *       allOf:
 *         - $ref: '#/components/schemas/User'
 *         - type: object
 *           properties:
 *             profile:
 *               type: object
 *               description: User's profile data (varies by role)
 *     
 *     UserList:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Users retrieved successfully
 *         data:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/User'
 *         metadata:
 *           type: object
 *           properties:
 *             pagination:
 *               $ref: '#/components/schemas/Pagination'
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *         requestId:
 *           type: string
 *           example: '1a2b3c4d-5e6f-7g8h-9i0j'
 *     
 *     UserDetail:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: User retrieved successfully
 *         data:
 *           $ref: '#/components/schemas/UserWithProfile'
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *         requestId:
 *           type: string
 *           example: '1a2b3c4d-5e6f-7g8h-9i0j'
 *     
 *     CreateUserRequest:
 *       type: object
 *       required:
 *         - email
 *         - password
 *         - role
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *           example: user@example.com
 *         password:
 *           type: string
 *           format: password
 *           minLength: 8
 *           description: User's password (min 8 chars with uppercase, lowercase, number, and special char)
 *           example: Password@123
 *         role:
 *           $ref: '#/components/schemas/UserRole'
 *     
 *     UpdateUserRequest:
 *       type: object
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: User's new email address
 *           example: newemail@example.com
 *         password:
 *           type: string
 *           format: password
 *           minLength: 8
 *           description: User's new password
 *           example: NewPassword@123
 *         isEmailVerified:
 *           type: boolean
 *           description: Set email verification status (admin only)
 *           example: true
 *     
 *     CreateArchitectRequest:
 *       type: object
 *       required:
 *         - email
 *         - password
 *         - firstName
 *         - lastName
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Architect's email address
 *           example: architect@example.com
 *         password:
 *           type: string
 *           format: password
 *           minLength: 8
 *           description: Architect's password
 *           example: Password@123
 *         firstName:
 *           type: string
 *           description: Architect's first name
 *           example: John
 *         lastName:
 *           type: string
 *           description: Architect's last name
 *           example: Doe
 *         specialization:
 *           type: string
 *           description: Architect's area of specialization
 *           example: Full-stack Development
 *         yearsOfExperience:
 *           type: integer
 *           description: Years of experience
 *           example: 5
 *         bio:
 *           type: string
 *           description: Short biography
 *           example: Experienced software architect with expertise in cloud solutions.
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           example: ['JavaScript', 'React', 'Node.js', 'AWS']
 *         certifications:
 *           type: array
 *           items:
 *             type: string
 *           example: ['AWS Certified Solutions Architect', 'Microsoft Certified: Azure Solutions Architect']
 *     
 *     Error:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: false
 *         message:
 *           type: string
 *           example: Error message
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *         requestId:
 *           type: string
 *           example: '1a2b3c4d-5e6f-7g8h-9i0j'
 *     
 *     ValidationError:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: false
 *         message:
 *           type: string
 *           example: Validation failed
 *         metadata:
 *           type: object
 *           properties:
 *             errors:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   field:
 *                     type: string
 *                     example: email
 *                   message:
 *                     type: string
 *                     example: Invalid email format
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *         requestId:
 *           type: string
 *           example: '1a2b3c4d-5e6f-7g8h-9i0j'
 *   
 *   responses:
 *     ValidationError:
 *       description: Validation error
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ValidationError'
 *     
 *     UnauthorizedError:
 *       description: Authentication required
 *       content:
 *         application/json:
 *           schema:
 *             allOf:
 *               - $ref: '#/components/schemas/Error'
 *               - type: object
 *                 properties:
 *                   message:
 *                     example: Authentication required
 *     
 *     ForbiddenError:
 *       description: Access denied
 *       content:
 *         application/json:
 *           schema:
 *             allOf:
 *               - $ref: '#/components/schemas/Error'
 *               - type: object
 *                 properties:
 *                   message:
 *                     example: You don't have permission to access this resource
 *     
 *     NotFoundError:
 *       description: Resource not found
 *       content:
 *         application/json:
 *           schema:
 *             allOf:
 *               - $ref: '#/components/schemas/Error'
 *               - type: object
 *                 properties:
 *                   message:
 *                     example: Resource not found
 *     
 *     InternalServerError:
 *       description: Internal server error
 *       content:
 *         application/json:
 *           schema:
 *             allOf:
 *               - $ref: '#/components/schemas/Error'
 *               - type: object
 *                 properties:
 *                   message:
 *                     example: An unexpected error occurred
 *   
 *   parameters:
 *     PageParam:
 *       name: page
 *       in: query
 *       schema:
 *         type: integer
 *         minimum: 1
 *         default: 1
 *       description: Page number
 *     
 *     LimitParam:
 *       name: limit
 *       in: query
 *       schema:
 *         type: integer
 *         minimum: 1
 *         maximum: 100
 *         default: 10
 *       description: Number of items per page
 *     
 *     SortParam:
 *       name: sort
 *       in: query
 *       schema:
 *         type: string
 *         example: createdAt:desc
 *       description: Sort field and direction (field:asc|desc)
 *     
 *     IdParam:
 *       name: id
 *       in: path
 *       required: true
 *       schema:
 *         type: string
 *         format: objectId
 *       description: Resource ID
 *   
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *       description: JWT token authentication
 */

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management operations
 */

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users with pagination and filtering
 *     description: Retrieves a paginated list of users. Restricted to admin users only.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: email
 *         in: query
 *         schema:
 *           type: string
 *         description: Filter by email (partial match)
 *       - name: role
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/UserRole'
 *         description: Filter by user role
 *     responses:
 *       200:
 *         description: A paginated list of users
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserList'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   post:
 *     summary: Create a new user
 *     description: Creates a new user in the system. Restricted to admin users only.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateUserRequest'
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User created successfully
 *                 data:
 *                   $ref: '#/components/schemas/User'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /users/{id}:
 *   get:
 *     summary: Get user by ID
 *     description: Retrieves a specific user by their ID. Users can access their own data, and admins can access any user's data.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/IdParam'
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserDetail'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   put:
 *     summary: Update user
 *     description: Updates a user's information. Users can update their own data, and admins can update any user's data.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/IdParam'
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUserRequest'
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserDetail'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 *   delete:
 *     summary: Delete user
 *     description: Deletes a user from the system. Restricted to admin users only.
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/IdParam'
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: User deleted successfully
 *                 data:
 *                   type: null
 *                   example: null
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /users/architects:
 *   post:
 *     summary: Create a new architect user
 *     description: Creates a new architect user in the system. Restricted to admin users only.
 *     tags: [Users, Architects]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateArchitectRequest'
 *     responses:
 *       201:
 *         description: Architect user created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Architect user created successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *                     profile:
 *                       type: object
 *                       description: Architect profile information
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */