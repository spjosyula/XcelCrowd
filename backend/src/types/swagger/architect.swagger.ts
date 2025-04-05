/**
 * @swagger
 * components:
 *   schemas:
 *     ArchitectProfile:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Architect profile ID
 *           example: '60d21b4667d0d8992e610c89'
 *         user:
 *           type: string
 *           format: objectId
 *           description: Associated user ID
 *           example: '60d21b4667d0d8992e610c90'
 *         firstName:
 *           type: string
 *           description: Architect's first name
 *           example: Jane
 *         lastName:
 *           type: string
 *           description: Architect's last name
 *           example: Smith
 *         fullName:
 *           type: string
 *           description: Architect's full name (virtual field)
 *           example: Jane Smith
 *         specialization:
 *           type: string
 *           description: Area of technical specialization
 *           example: Full-stack Development
 *         yearsOfExperience:
 *           type: integer
 *           description: Years of professional experience
 *           example: 8
 *         bio:
 *           type: string
 *           description: Professional biography
 *           example: 'Experienced software architect with expertise in cloud solutions and distributed systems'
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           description: Technical skills and expertise areas
 *           example: ['Node.js', 'React', 'AWS', 'System Design', 'Database Architecture']
 *         certifications:
 *           type: array
 *           items:
 *             type: string
 *           description: Professional certifications
 *           example: ['AWS Certified Solutions Architect', 'Microsoft Certified: Azure Solutions Architect']
 *         profilePicture:
 *           type: string
 *           format: uri
 *           description: URL to profile picture
 *           example: 'https://example.com/images/jane-smith.jpg'
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Profile creation timestamp
 *           example: '2023-05-20T14:20:30.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Profile last update timestamp
 *           example: '2023-05-20T14:20:30.000Z'
 *
 *     ArchitectProfileRequest:
 *       type: object
 *       properties:
 *         firstName:
 *           type: string
 *           description: Architect's first name
 *           example: Jane
 *         lastName:
 *           type: string
 *           description: Architect's last name
 *           example: Smith
 *         specialization:
 *           type: string
 *           description: Area of technical specialization
 *           example: Full-stack Development
 *         yearsOfExperience:
 *           type: integer
 *           description: Years of professional experience
 *           example: 8
 *         bio:
 *           type: string
 *           description: Professional biography
 *           example: 'Experienced software architect with expertise in cloud solutions and distributed systems'
 *           maxLength: 500
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           description: Technical skills and expertise areas
 *           example: ['Node.js', 'React', 'AWS', 'System Design', 'Database Architecture']
 *         certifications:
 *           type: array
 *           items:
 *             type: string
 *           description: Professional certifications
 *           example: ['AWS Certified Solutions Architect', 'Microsoft Certified: Azure Solutions Architect']
 *         profilePicture:
 *           type: string
 *           format: uri
 *           description: URL to profile picture
 *           example: 'https://example.com/images/jane-smith.jpg'
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
 *           description: Associated challenge ID
 *           example: '60d21b4667d0d8992e610c92'
 *         student:
 *           type: string
 *           format: objectId
 *           description: Student user ID who submitted the solution
 *           example: '60d21b4667d0d8992e610c93'
 *         title:
 *           type: string
 *           description: Solution title
 *           example: 'Innovative Mobile App for Healthcare Coordination'
 *         description:
 *           type: string
 *           description: Detailed solution description
 *           example: 'A comprehensive mobile application that addresses the challenge by...'
 *         submissionUrl:
 *           type: string
 *           description: Link to the actual solution files or repository
 *           example: 'https://github.com/student/healthcare-coordination-app'
 *         status:
 *           type: string
 *           enum: ['draft', 'submitted', 'claimed', 'under_review', 'approved', 'rejected', 'selected']
 *           description: Current status of the solution
 *           example: 'submitted'
 *         feedback:
 *           type: string
 *           description: Detailed feedback and comments from reviewer
 *           example: 'This solution demonstrates strong technical knowledge and addresses the core requirements effectively...'
 *         reviewedBy:
 *           type: string
 *           format: objectId
 *           description: Architect who provided the review
 *           example: '60d21b4667d0d8992e610c94'
 *         reviewedAt:
 *           type: string
 *           format: date-time
 *           description: When the review was completed
 *           example: '2023-05-26T14:45:00.000Z'
 *         score:
 *           type: number
 *           minimum: 0
 *           maximum: 100
 *           description: Score assigned to solution (0-100)
 *           example: 85
 *         selectedAt:
 *           type: string
 *           format: date-time
 *           description: When the solution was selected as a winner
 *           example: '2023-05-28T10:00:00.000Z'
 *         selectedBy:
 *           type: string
 *           format: objectId
 *           description: Who selected this solution (usually company or architect)
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
 *
 *     Challenge:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Challenge ID
 *           example: '60d21b4667d0d8992e610c92'
 *         company:
 *           type: string
 *           format: objectId
 *           description: Company profile ID that created the challenge
 *           example: '60d21b4667d0d8992e610c95'
 *         title:
 *           type: string
 *           description: Challenge title
 *           example: 'Healthcare Coordination Platform'
 *         description:
 *           type: string
 *           description: Detailed challenge description
 *           example: 'Design a solution to improve coordination between healthcare providers...'
 *         requirements:
 *           type: array
 *           items:
 *             type: string
 *           description: Specific requirements for solutions
 *           example: ['Must be mobile-friendly', 'Should include authentication', 'Must be HIPAA compliant']
 *         resources:
 *           type: array
 *           items:
 *             type: string
 *           description: Resources provided to help with the challenge
 *           example: ['https://example.com/resources/healthcare-api.pdf']
 *         rewards:
 *           type: string
 *           description: Details about prizes or compensation
 *           example: '1st place: $1000, 2nd place: $500, 3rd place: $250'
 *         deadline:
 *           type: string
 *           format: date-time
 *           description: Submission deadline
 *           example: '2023-05-31T23:59:59.000Z'
 *         status:
 *           type: string
 *           enum: ['draft', 'active', 'closed', 'completed']
 *           description: Current status of the challenge
 *           example: 'active'
 *         difficulty:
 *           type: string
 *           enum: ['beginner', 'intermediate', 'advanced', 'expert']
 *           description: Difficulty level of the challenge
 *           example: 'intermediate'
 *         category:
 *           type: array
 *           items:
 *             type: string
 *           description: Categories the challenge belongs to
 *           example: ['Healthcare', 'Mobile Development']
 *         maxParticipants:
 *           type: integer
 *           description: Maximum allowed number of participants
 *           example: 100
 *         currentParticipants:
 *           type: integer
 *           description: Current count of participants
 *           example: 42
 *         completedAt:
 *           type: string
 *           format: date-time
 *           description: When the challenge was completed
 *           example: '2023-06-15T23:59:59.000Z'
 *         publishedAt:
 *           type: string
 *           format: date-time
 *           description: When the challenge was published
 *           example: '2023-05-01T00:00:00.000Z'
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           description: Keywords or tags associated with the challenge
 *           example: ['Healthcare', 'Mobile', 'API']
 *         claimedBy:
 *           type: string
 *           format: objectId
 *           description: ID of architect who claimed this challenge for review
 *           example: '60d21b4667d0d8992e610c94'
 *         claimedAt:
 *           type: string
 *           format: date-time
 *           description: When the challenge was claimed for review
 *           example: '2023-06-01T10:15:00.000Z'
 *         maxApprovedSolutions:
 *           type: integer
 *           description: Maximum number of solutions that can be approved
 *           example: 3
 *         approvedSolutionsCount:
 *           type: integer
 *           description: Current count of approved solutions
 *           example: 1
 *         visibility:
 *           type: string
 *           enum: ['public', 'private', 'anonymous']
 *           description: Controls who can see the challenge
 *           example: 'public'
 *         allowedInstitutions:
 *           type: array
 *           items:
 *             type: string
 *           description: List of institutions that can see private challenges
 *           example: ['University of Oxford', 'Imperial College London']
 *         isCompanyVisible:
 *           type: boolean
 *           description: Whether company identity is shown
 *           example: true
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Challenge creation timestamp
 *           example: '2023-04-15T14:20:30.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Challenge last update timestamp
 *           example: '2023-04-15T14:20:30.000Z'
 *
 *     ReviewSolutionRequest:
 *       type: object
 *       required:
 *         - status
 *         - feedback
 *         - score
 *       properties:
 *         status:
 *           type: string
 *           enum: ['approved', 'rejected']
 *           description: Decision on the solution
 *           example: 'approved'
 *         feedback:
 *           type: string
 *           description: Detailed feedback and comments
 *           example: 'This solution demonstrates strong technical knowledge and addresses the core requirements effectively...'
 *         score:
 *           type: number
 *           minimum: 0
 *           maximum: 100
 *           description: Score assigned to solution (0-100)
 *           example: 85
 *
 *     SelectSolutionsRequest:
 *       type: object
 *       required:
 *         - solutionIds
 *       properties:
 *         solutionIds:
 *           type: array
 *           items:
 *             type: string
 *             format: objectId
 *           description: IDs of selected winning solutions (in order of ranking)
 *           example: ['60d21b4667d0d8992e610c96', '60d21b4667d0d8992e610c97', '60d21b4667d0d8992e610c98']
 *         feedback:
 *           type: string
 *           description: Overall feedback about the selection
 *           example: 'These solutions were selected based on innovation, feasibility, and alignment with the challenge goals.'
 *
 *     ArchitectResponse:
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
 *           description: Response data
 *         timestamp:
 *           type: string
 *           format: date-time
 *           example: '2023-05-26T14:45:00.000Z'
 *         requestId:
 *           type: string
 *           example: '1a2b3c4d-5e6f-7g8h-9i0j'
 *
 *     PendingSolutionsResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Pending solutions retrieved successfully
 *         data:
 *           type: object
 *           properties:
 *             solutions:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Solution'
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
 *     PendingChallengesResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Pending challenges retrieved successfully
 *         data:
 *           type: object
 *           properties:
 *             challenges:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Challenge'
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
 */

/**
 * @swagger
 * tags:
 *   name: Architects
 *   description: Operations specific to architect users
 */

/**
 * @swagger
 * /architect/profile:
 *   get:
 *     summary: Get architect's profile information
 *     description: Retrieves the profile information of the authenticated architect
 *     tags: [Architects]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Profile information retrieved successfully
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
 *                   example: Architect profile retrieved successfully
 *                 data:
 *                   $ref: '#/components/schemas/ArchitectProfile'
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
 *   put:
 *     summary: Update architect's profile
 *     description: Updates the profile information of the authenticated architect
 *     tags: [Architects]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ArchitectProfileRequest'
 *     responses:
 *       200:
 *         description: Profile updated successfully
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
 *                   example: Architect profile updated successfully
 *                 data:
 *                   $ref: '#/components/schemas/ArchitectProfile'
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
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/solutions:
 *   get:
 *     summary: Get list of solutions pending review
 *     description: |
 *       Retrieves a list of solutions that are pending review.
 *       **Deprecated:** Use /architect/challenges endpoint instead.
 *     deprecated: true
 *     tags: [Architects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           type: string
 *           enum: ['submitted', 'claimed', 'under_review', 'approved', 'rejected', 'selected']
 *         description: Filter by solution status
 *     responses:
 *       200:
 *         description: List of pending solutions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PendingSolutionsResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/challenges:
 *   get:
 *     summary: Get list of challenges pending review
 *     description: Retrieves a list of challenges that are ready for review by architects
 *     tags: [Architects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           type: string
 *           enum: ['active', 'closed']
 *         description: Filter by challenge status
 *     responses:
 *       200:
 *         description: List of pending challenges
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PendingChallengesResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/solutions/{id}:
 *   get:
 *     summary: Get details of a specific solution
 *     description: Retrieves detailed information about a specific solution
 *     tags: [Architects]
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
 *         description: Solution details retrieved successfully
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
 *                   example: Solution retrieved successfully
 *                 data:
 *                   $ref: '#/components/schemas/Solution'
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
 * /architect/challenges/{challengeId}/claim:
 *   post:
 *     summary: Claim a challenge for review
 *     description: Allows an architect to claim a challenge for review, which includes all its solutions
 *     tags: [Architects]
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
 *     responses:
 *       200:
 *         description: Challenge claimed successfully
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
 *                   example: Challenge claimed successfully
 *                 data:
 *                   $ref: '#/components/schemas/Challenge'
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
 *       409:
 *         description: Challenge already claimed by another architect
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/challenges/claimed:
 *   get:
 *     summary: Get claimed challenges
 *     description: Retrieves all challenges claimed by the authenticated architect
 *     tags: [Architects]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *     responses:
 *       200:
 *         description: List of claimed challenges
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/PendingChallengesResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/solutions/{id}/claim:
 *   post:
 *     summary: Claim a solution for review
 *     description: |
 *       Allows an architect to claim a specific solution for review.
 *       **Deprecated:** Use /architect/challenges/{challengeId}/claim instead.
 *     deprecated: true
 *     tags: [Architects]
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
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Solution claimed successfully
 *                 data:
 *                   $ref: '#/components/schemas/Solution'
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
 *       409:
 *         description: Solution already claimed by another architect
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /architect/solutions/{id}/review:
 *   post:
 *     summary: Submit review for a solution
 *     description: Allows an architect to submit their review and feedback for a solution
 *     tags: [Architects]
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
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Solution reviewed successfully
 *                 data:
 *                   $ref: '#/components/schemas/Solution'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
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
 * /architect/challenges/{challengeId}/select-solutions:
 *   post:
 *     summary: Select winning solutions for a challenge
 *     description: Allows an architect to select the winning solutions for a challenge they have reviewed
 *     tags: [Architects]
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SelectSolutionsRequest'
 *     responses:
 *       200:
 *         description: Winning solutions selected successfully
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
 *                   example: Winning solutions selected successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     challenge:
 *                       $ref: '#/components/schemas/Challenge'
 *                     selectedSolutions:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Solution'
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   example: '2023-05-26T14:45:00.000Z'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         description: Challenge not claimed by this architect or already completed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: One or more solutions are not eligible or have not been reviewed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */