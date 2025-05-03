/**
 * @swagger
 * components:
 *   schemas:
 *     LoginRequest:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *           example: user@example.com
 *         password:
 *           type: string
 *           format: password
 *           description: User's password
 *           example: Password123!
 *           minLength: 8
 *     
 *     RequestPasswordResetRequest:
 *       type: object
 *       required:
 *         - email
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Email address associated with the account
 *           example: student@university.edu
 *     
 *     ResetPasswordRequest:
 *       type: object
 *       required:
 *         - email
 *         - otp
 *         - newPassword
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Email address associated with the account
 *           example: student@university.edu
 *         otp:
 *           type: string
 *           description: One-time password received via email
 *           example: "123456"
 *           minLength: 6
 *           maxLength: 6
 *           pattern: '^\d{6}$'
 *         newPassword:
 *           type: string
 *           format: password
 *           description: New strong password (min 8 chars with uppercase, lowercase, number, and special char)
 *           example: NewStrongP@ss123
 *           minLength: 8
 *     
 *     VerifyEmailRequest:
 *       type: object
 *       required:
 *         - email
 *         - otp
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Email address to verify
 *           example: student@university.edu
 *         otp:
 *           type: string
 *           description: One-time password received via email
 *           example: "123456"
 *           minLength: 6
 *           maxLength: 6
 *           pattern: '^\d{6}$'
 *     
 *     RegisterStudentRequest:
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
 *           description: Student's email address (must be a valid academic email)
 *           example: student@university.edu
 *         password:
 *           type: string
 *           format: password
 *           description: Strong password (min 8 chars with uppercase, lowercase, number, and special char)
 *           example: StrongP@ss123
 *           minLength: 8
 *         firstName:
 *           type: string
 *           description: Student's first name
 *           example: John
 *         lastName:
 *           type: string
 *           description: Student's last name
 *           example: Smith
 *         university:
 *           type: string
 *           description: Academic institution name
 *           example: Oxford University
 *     
 *     RegisterCompanyRequest:
 *       type: object
 *       required:
 *         - email
 *         - password
 *         - companyName
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Company email address
 *           example: contact@company.com
 *         password:
 *           type: string
 *           format: password
 *           description: Strong password (min 8 chars with uppercase, lowercase, number, and special char)
 *           example: StrongP@ss123
 *           minLength: 8
 *         companyName:
 *           type: string
 *           description: Registered company name
 *           example: Acme Corporation
 *         industry:
 *           type: string
 *           description: Company's industry or sector
 *           example: Technology
 *         website:
 *           type: string
 *           format: uri
 *           description: Company's website
 *           example: https://www.acmecorp.com
 *         contactNumber:
 *           type: string
 *           description: Company's contact phone number
 *           example: +44 1234 567890
 *         description:
 *           type: string
 *           description: Brief company description
 *           example: Leading provider of innovative technology solutions
 *         address:
 *           type: object
 *           properties:
 *             street:
 *               type: string
 *               example: 123 Tech Lane
 *             city:
 *               type: string
 *               example: London
 *             country:
 *               type: string
 *               example: United Kingdom
 *             postalCode:
 *               type: string
 *               example: EC1A 1BB
 *     
 *     AuthResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Authentication successful
 *         data:
 *           type: object
 *           properties:
 *             user:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   format: objectId
 *                   example: '60d21b4667d0d8992e610c85'
 *                 email:
 *                   type: string
 *                   format: email
 *                   example: user@example.com
 *                 role:
 *                   type: string
 *                   enum: [student, company, architect, admin]
 *                   example: student
 *             csrfToken:
 *               type: string
 *               description: CSRF protection token
 *               example: a1b2c3d4e5f6...
 *             token:
 *               type: string
 *               description: JWT authentication token (also set as HTTP-only cookie)
 *               example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *     
 *     RegistrationResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Registration successful
 *         data:
 *           type: object
 *           properties:
 *             user:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   format: objectId
 *                   example: '60d21b4667d0d8992e610c85'
 *                 email:
 *                   type: string
 *                   format: email
 *                   example: user@example.com
 *                 role:
 *                   type: string
 *                   enum: [student, company, architect, admin]
 *                   example: student
 *             profile:
 *               type: object
 *               description: Profile information (varies by user type)
 *             csrfToken:
 *               type: string
 *               description: CSRF protection token
 *               example: a1b2c3d4e5f6...
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *     
 *     SimpleSuccessResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Operation successful
 *         data:
 *           type: object
 *           example: {}
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
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
 */

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: API endpoints for user authentication and authorization
 */

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout current user
 *     description: Invalidates the current session and clears authentication cookies
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully logged out
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
 *                   example: Logged out successfully
 *                 data:
 *                   type: null
 *                   example: null
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       401:
 *         description: Unauthorized - User not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/me:
 *   get:
 *     summary: Get current user information
 *     description: Retrieves the profile information of the currently authenticated user
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user information
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
 *                   example: User profile retrieved successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                       format: objectId
 *                       example: '60d21b4667d0d8992e610c85'
 *                     email:
 *                       type: string
 *                       format: email
 *                       example: user@example.com
 *                     role:
 *                       type: string
 *                       enum: [student, company, architect, admin]
 *                       example: student
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       401:
 *         description: Unauthorized - User not authenticated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/student/register:
 *   post:
 *     summary: Register a new student account
 *     description: Creates a new student user account and profile. Validates email and password requirements.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterStudentRequest'
 *     responses:
 *       201:
 *         description: Student account created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RegistrationResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/student/login:
 *   post:
 *     summary: Authenticate student and get token
 *     description: Validates student credentials and returns JWT token for authentication. The token is also set as an HTTP-only cookie.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many login attempts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *
 * /auth/student/verify-email:
 *   post:
 *     summary: Verify student's email address
 *     description: Verifies a student's email address using the OTP sent during registration
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/VerifyEmailRequest'
 *     responses:
 *       200:
 *         description: Email verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Invalid or expired verification code
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/student/request-password-reset:
 *   post:
 *     summary: Request password reset for student
 *     description: Sends a password reset OTP to the student's university email address
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RequestPasswordResetRequest'
 *     responses:
 *       200:
 *         description: Password reset instructions sent if email exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/student/reset-password:
 *   post:
 *     summary: Reset student password with OTP
 *     description: Resets a student's password using the OTP sent to their email
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ResetPasswordRequest'
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Invalid or expired reset code or password doesn't meet requirements
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/company/register:
 *   post:
 *     summary: Register a new company account
 *     description: Creates a new company user account and profile. Validates email and password requirements.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterCompanyRequest'
 *     responses:
 *       201:
 *         description: Company account created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RegistrationResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/company/login:
 *   post:
 *     summary: Authenticate company and get token
 *     description: Validates company credentials and returns JWT token for authentication. The token is also set as an HTTP-only cookie.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many login attempts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/company/verify-email:
 *   post:
 *     summary: Verify company's business email
 *     description: Verifies a company's business email address using the OTP sent during registration
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/VerifyEmailRequest'
 *     responses:
 *       200:
 *         description: Business email verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Invalid or expired verification code
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/company/request-password-reset:
 *   post:
 *     summary: Request password reset for company
 *     description: Sends a password reset OTP to the company's business email address
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RequestPasswordResetRequest'
 *     responses:
 *       200:
 *         description: Password reset instructions sent if email exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/company/reset-password:
 *   post:
 *     summary: Reset company password with OTP
 *     description: Resets a company's password using the OTP sent to their business email
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ResetPasswordRequest'
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SimpleSuccessResponse'
 *       400:
 *         description: Invalid or expired reset code or password doesn't meet requirements
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/architect/login:
 *   post:
 *     summary: Authenticate architect and get token
 *     description: Validates architect credentials and returns JWT token for authentication. The token is also set as an HTTP-only cookie.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many login attempts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 * 
 * /auth/admin/login:
 *   post:
 *     summary: Authenticate admin and get token
 *     description: Validates admin credentials and returns JWT token for authentication. The token is also set as an HTTP-only cookie.
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ValidationError'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many login attempts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */