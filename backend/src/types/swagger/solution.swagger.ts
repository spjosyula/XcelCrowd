/**
 * @swagger
 * components:
 *   schemas:
 *     SolutionStatus:
 *       type: string
 *       enum:
 *         - draft
 *         - submitted
 *         - claimed
 *         - under_review
 *         - approved
 *         - rejected
 *         - selected
 *       description: Status of a solution submission
 *       example: submitted
 *     
 *     Solution:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Solution ID
 *           example: '60d21b4667d0d8992e610c91'
 *         challenge:
 *           type: string
 *           format: objectId
 *           description: ID of the challenge this solution addresses
 *           example: '60d21b4667d0d8992e610c92'
 *         student:
 *           type: string
 *           format: objectId
 *           description: ID of the student who submitted the solution
 *           example: '60d21b4667d0d8992e610c93'
 *         title:
 *           type: string
 *           description: Solution title
 *           example: 'Innovative Mobile App for Healthcare Coordination'
 *           maxLength: 100
 *         description:
 *           type: string
 *           description: Detailed solution description
 *           example: 'A comprehensive mobile application that addresses the challenge by...'
 *         submissionUrl:
 *           type: string
 *           description: Link to the actual solution files or repository
 *           example: 'https://github.com/student/healthcare-coordination-app'
 *         status:
 *           $ref: '#/components/schemas/SolutionStatus'
 *         feedback:
 *           type: string
 *           description: Comments or suggestions from reviewers
 *           example: 'This solution demonstrates strong technical knowledge and addresses the core requirements effectively...'
 *         reviewedBy:
 *           type: string
 *           format: objectId
 *           description: ID of architect who reviewed this solution
 *           example: '60d21b4667d0d8992e610c94'
 *         reviewedAt:
 *           type: string
 *           format: date-time
 *           description: When the solution was reviewed
 *           example: '2023-05-26T14:45:00.000Z'
 *         score:
 *           type: number
 *           minimum: 0
 *           maximum: 100
 *           description: Numerical assessment of the solution quality
 *           example: 85
 *         selectedAt:
 *           type: string
 *           format: date-time
 *           description: When the solution was selected as a winner
 *           example: '2023-05-28T10:00:00.000Z'
 *         selectedBy:
 *           type: string
 *           format: objectId
 *           description: ID of the company who selected this solution
 *           example: '60d21b4667d0d8992e610c95'
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Solution submission timestamp
 *           example: '2023-05-24T16:20:30.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Solution last update timestamp
 *           example: '2023-05-26T14:45:00.000Z'
 *       description: A solution submitted to a challenge
 *     
 *     SolutionWithStudent:
 *       allOf:
 *         - $ref: '#/components/schemas/Solution'
 *         - type: object
 *           properties:
 *             student:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   format: objectId
 *                   example: '60d21b4667d0d8992e610c93'
 *                 firstName:
 *                   type: string
 *                   example: 'John'
 *                 lastName:
 *                   type: string
 *                   example: 'Doe'
 *                 university:
 *                   type: string
 *                   example: 'University of Oxford'
 *                 profilePicture:
 *                   type: string
 *                   format: uri
 *                   example: 'https://example.com/profiles/john-doe.jpg'
 *       description: Solution with basic student information
 *     
 *     SolutionWithChallenge:
 *       allOf:
 *         - $ref: '#/components/schemas/Solution'
 *         - type: object
 *           properties:
 *             challenge:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   format: objectId
 *                   example: '60d21b4667d0d8992e610c92'
 *                 title:
 *                   type: string
 *                   example: 'Healthcare Coordination Platform'
 *                 company:
 *                   type: string
 *                   format: objectId
 *                   example: '60d21b4667d0d8992e610c95'
 *                 companyName:
 *                   type: string
 *                   example: 'HealthTech Solutions'
 *                 deadline:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-31T23:59:59.000Z'
 *                 status:
 *                   type: string
 *                   example: 'active'
 *       description: Solution with basic challenge information
 *     
 *     SubmitSolutionRequest:
 *       type: object
 *       required:
 *         - challenge
 *         - title
 *         - description
 *         - submissionUrl
 *       properties:
 *         challenge:
 *           type: string
 *           format: objectId
 *           description: ID of the challenge this solution addresses
 *           example: '60d21b4667d0d8992e610c92'
 *         title:
 *           type: string
 *           description: Solution title
 *           example: 'Innovative Mobile App for Healthcare Coordination'
 *           maxLength: 100
 *         description:
 *           type: string
 *           description: Detailed solution description
 *           example: 'A comprehensive mobile application that addresses the challenge by...'
 *         submissionUrl:
 *           type: string
 *           description: Link to the actual solution files or repository
 *           example: 'https://github.com/student/healthcare-coordination-app'
 *     
 *     UpdateSolutionRequest:
 *       type: object
 *       properties:
 *         title:
 *           type: string
 *           description: Solution title
 *           example: 'Improved Mobile App for Healthcare Coordination'
 *           maxLength: 100
 *         description:
 *           type: string
 *           description: Detailed solution description
 *           example: 'An updated comprehensive mobile application that addresses the challenge by...'
 *         submissionUrl:
 *           type: string
 *           description: Link to the actual solution files or repository
 *           example: 'https://github.com/student/healthcare-coordination-app-v2'
 *     
 *     ReviewSolutionRequest:
 *       type: object
 *       required:
 *         - status
 *         - feedback
 *       properties:
 *         status:
 *           type: string
 *           enum: [approved, rejected]
 *           description: Approval status for the solution
 *           example: approved
 *         feedback:
 *           type: string
 *           description: Detailed feedback and comments
 *           example: 'This solution demonstrates strong technical knowledge and addresses the core requirements effectively...'
 *         score:
 *           type: number
 *           minimum: 0
 *           maximum: 100
 *           description: Numerical score assigned to the solution
 *           example: 85
 *     
 *     SolutionResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Solution retrieved successfully
 *         data:
 *           $ref: '#/components/schemas/Solution'
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *     
 *     SolutionListResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Solutions retrieved successfully
 *         data:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/Solution'
 *         metadata:
 *           type: object
 *           properties:
 *             pagination:
 *               type: object
 *               properties:
 *                 page:
 *                   type: integer
 *                   example: 1
 *                 limit:
 *                   type: integer
 *                   example: 10
 *                 total:
 *                   type: integer
 *                   example: 42
 *                 totalPages:
 *                   type: integer
 *                   example: 5
 *                 hasNextPage:
 *                   type: boolean
 *                   example: true
 *                 hasPrevPage:
 *                   type: boolean
 *                   example: false
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 */

/**
 * @swagger
 * tags:
 *   name: Solutions
 *   description: Operations for managing challenge solutions
 */

/**
 * @swagger
 * /solutions:
 *   post:
 *     summary: Submit a solution to a challenge
 *     description: Allows a student to submit a solution to an active challenge. Validates that the student meets any institutional requirements for the challenge.
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SubmitSolutionRequest'
 *     responses:
 *       201:
 *         description: Solution successfully submitted
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         description: Student not eligible for this challenge or challenge not accepting submissions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Challenge not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Student has already submitted a solution to this challenge
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/student:
 *   get:
 *     summary: Get all solutions submitted by current student
 *     description: Retrieves all solutions submitted by the authenticated student user with optional filtering
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/SolutionStatus'
 *         description: Filter by solution status
 *     responses:
 *       200:
 *         description: List of student solutions
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/SolutionListResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/SolutionWithChallenge'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/architect:
 *   get:
 *     summary: Get solutions reviewed by current architect
 *     description: Retrieves all solutions reviewed by the authenticated architect with optional filtering
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/SolutionStatus'
 *         description: Filter by solution status
 *       - name: score
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *         description: Filter by minimum score
 *     responses:
 *       200:
 *         description: List of architect-reviewed solutions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionListResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/challenge/{challengeId}:
 *   get:
 *     summary: Get all solutions for a specific challenge
 *     description: Retrieves all solutions submitted to a specific challenge. Accessible to the challenge owner (company), architects, and admins.
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: challengeId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/SolutionStatus'
 *         description: Filter by solution status
 *       - name: score
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 100
 *         description: Filter by minimum score
 *     responses:
 *       200:
 *         description: List of challenge solutions
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/SolutionListResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/SolutionWithStudent'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/{id}:
 *   get:
 *     summary: Get solution by ID
 *     description: Retrieves a specific solution by its ID. Accessible to the solution owner (student), challenge owner (company), architects, and admins.
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Solution ID
 *     responses:
 *       200:
 *         description: Solution details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
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
 *     summary: Update a solution
 *     description: Updates an existing solution. Only accessible to the student who submitted the solution and only before the challenge deadline.
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Solution ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateSolutionRequest'
 *     responses:
 *       200:
 *         description: Solution updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Challenge deadline has passed or solution is already under review
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/{id}/claim:
 *   patch:
 *     summary: Claim a solution for review
 *     description: Allows an architect to claim a solution for review, making it exclusively available to that architect for review
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Solution ID
 *     responses:
 *       200:
 *         description: Solution claimed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Solution already claimed by another architect
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/{id}/review:
 *   patch:
 *     summary: Review a solution
 *     description: Allows the claiming architect to submit a review for a solution with feedback and score
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Solution ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ReviewSolutionRequest'
 *     responses:
 *       200:
 *         description: Solution reviewed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         description: Solution not claimed by this architect or already reviewed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /solutions/{id}/select:
 *   patch:
 *     summary: Select a solution as a winner
 *     description: Allows a company to select a solution as a winner for their challenge
 *     tags: [Solutions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Solution ID
 *     responses:
 *       200:
 *         description: Solution selected as winner
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SolutionResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Maximum number of winners already selected or solution not eligible for selection
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */