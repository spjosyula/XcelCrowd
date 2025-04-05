/**
 * @swagger
 * components:
 *   schemas:
 *     ChallengeStatus:
 *       type: string
 *       enum:
 *         - draft
 *         - active
 *         - closed
 *         - completed
 *       description: Status of a challenge
 *       example: 'active'
 *
 *     ChallengeDifficulty:
 *       type: string
 *       enum:
 *         - beginner
 *         - intermediate
 *         - advanced
 *         - expert
 *       description: Difficulty level of a challenge
 *       example: 'intermediate'
 *     
 *     ChallengeVisibility:
 *       type: string
 *       enum:
 *         - public
 *         - private
 *         - anonymous
 *       description: Visibility setting of a challenge
 *       example: 'public'
 *     
 *     Challenge:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Challenge ID
 *           example: '60d21b4667d0d8992e610c85'
 *         title:
 *           type: string
 *           description: Challenge title
 *           example: 'Sustainable Urban Mobility Solution'
 *         description:
 *           type: string
 *           description: Detailed challenge description
 *           example: 'Design an innovative solution for sustainable urban mobility that addresses traffic congestion and reduces carbon emissions.'
 *         company:
 *           type: string
 *           format: objectId
 *           description: ID of the company profile that created the challenge
 *           example: '60d21b4667d0d8992e610c86'
 *         requirements:
 *           type: array
 *           items:
 *             type: string
 *           description: Specific requirements for solution submissions
 *           example: ['Must be mobile-friendly', 'Should include a data collection component', 'Must address both public and private transportation']
 *         resources:
 *           type: array
 *           items:
 *             type: string
 *           description: Resources provided to help with the challenge
 *           example: ['https://example.com/resources/urban-mobility.pdf', 'https://example.com/datasets/traffic-data.csv']
 *         rewards:
 *           type: string
 *           description: Details about prizes or compensation
 *           example: '1st place: $2000, 2nd place: $1000, 3rd place: $500'
 *         deadline:
 *           type: string
 *           format: date-time
 *           description: Submission deadline
 *           example: '2023-07-15T23:59:59.000Z'
 *         status:
 *           $ref: '#/components/schemas/ChallengeStatus'
 *         difficulty:
 *           $ref: '#/components/schemas/ChallengeDifficulty'
 *         category:
 *           type: array
 *           items:
 *             type: string
 *           description: Categories the challenge belongs to
 *           example: ['Urban Planning', 'Transportation', 'Sustainability']
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
 *           description: Date when the challenge was completed
 *           example: '2023-08-01T10:00:00.000Z'
 *         publishedAt:
 *           type: string
 *           format: date-time
 *           description: Date when the challenge was published
 *           example: '2023-06-01T09:00:00.000Z'
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           description: Keywords or tags associated with the challenge
 *           example: ['Mobility', 'Smart City', 'Green Technology']
 *         claimedBy:
 *           type: string
 *           format: objectId
 *           description: ID of architect who claimed this challenge for review
 *           example: '60d21b4667d0d8992e610c87'
 *         claimedAt:
 *           type: string
 *           format: date-time
 *           description: When the challenge was claimed for review
 *           example: '2023-07-16T10:15:00.000Z'
 *         maxApprovedSolutions:
 *           type: integer
 *           description: Maximum number of solutions that can be approved
 *           example: 5
 *         approvedSolutionsCount:
 *           type: integer
 *           description: Current count of approved solutions
 *           example: 2
 *         visibility:
 *           $ref: '#/components/schemas/ChallengeVisibility'
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
 *         remainingSpots:
 *           type: integer
 *           description: Number of participation spots remaining
 *           example: 58
 *         timeRemaining:
 *           type: integer
 *           description: Time remaining until deadline (in milliseconds)
 *           example: 1209600000
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Challenge creation timestamp
 *           example: '2023-05-15T14:20:30.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Challenge last update timestamp
 *           example: '2023-05-16T09:30:45.000Z'
 *     
 *     CreateChallengeRequest:
 *       type: object
 *       required:
 *         - title
 *         - description
 *         - requirements
 *         - difficulty
 *         - category
 *         - deadline
 *       properties:
 *         title:
 *           type: string
 *           description: Challenge title
 *           example: 'Sustainable Urban Mobility Solution'
 *           maxLength: 100
 *         description:
 *           type: string
 *           description: Detailed challenge description
 *           example: 'Design an innovative solution for sustainable urban mobility that addresses traffic congestion and reduces carbon emissions.'
 *         requirements:
 *           type: array
 *           items:
 *             type: string
 *           description: Specific requirements for solution submissions
 *           example: ['Must be mobile-friendly', 'Should include a data collection component']
 *         resources:
 *           type: array
 *           items:
 *             type: string
 *           description: Resources provided to help with the challenge
 *           example: ['https://example.com/resources/urban-mobility.pdf']
 *         rewards:
 *           type: string
 *           description: Details about prizes or compensation
 *           example: '1st place: $2000, 2nd place: $1000, 3rd place: $500'
 *         deadline:
 *           type: string
 *           format: date-time
 *           description: Submission deadline
 *           example: '2023-07-15T23:59:59.000Z'
 *         difficulty:
 *           $ref: '#/components/schemas/ChallengeDifficulty'
 *         category:
 *           type: array
 *           items:
 *             type: string
 *           description: Categories the challenge belongs to
 *           example: ['Urban Planning', 'Transportation']
 *         maxParticipants:
 *           type: integer
 *           description: Maximum allowed number of participants
 *           minimum: 1
 *           example: 100
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           description: Keywords or tags associated with the challenge
 *           example: ['Mobility', 'Smart City', 'Green Technology']
 *         maxApprovedSolutions:
 *           type: integer
 *           minimum: 1
 *           description: Maximum number of solutions that can be approved
 *           example: 5
 *         visibility:
 *           $ref: '#/components/schemas/ChallengeVisibility'
 *         allowedInstitutions:
 *           type: array
 *           items:
 *             type: string
 *           description: List of institutions that can see private challenges (required for private visibility)
 *           example: ['University of Oxford', 'Imperial College London']
 *         isCompanyVisible:
 *           type: boolean
 *           description: Whether company identity is shown (default is true unless visibility is anonymous)
 *           example: true
 *     
 *     UpdateChallengeRequest:
 *       type: object
 *       properties:
 *         title:
 *           type: string
 *           description: Challenge title
 *           example: 'Sustainable Urban Mobility Solution - Updated'
 *           maxLength: 100
 *         description:
 *           type: string
 *           description: Detailed challenge description
 *           example: 'Design an innovative solution for sustainable urban mobility that addresses traffic congestion and reduces carbon emissions. Updated with new requirements.'
 *         requirements:
 *           type: array
 *           items:
 *             type: string
 *           description: Specific requirements for solution submissions
 *           example: ['Must be mobile-friendly', 'Should include a data collection component', 'Must integrate with IoT devices']
 *         resources:
 *           type: array
 *           items:
 *             type: string
 *           description: Resources provided to help with the challenge
 *           example: ['https://example.com/resources/urban-mobility.pdf', 'https://example.com/datasets/traffic-data.csv']
 *         rewards:
 *           type: string
 *           description: Details about prizes or compensation
 *           example: '1st place: $2500, 2nd place: $1200, 3rd place: $700'
 *         deadline:
 *           type: string
 *           format: date-time
 *           description: Submission deadline
 *           example: '2023-07-31T23:59:59.000Z'
 *         difficulty:
 *           $ref: '#/components/schemas/ChallengeDifficulty'
 *         category:
 *           type: array
 *           items:
 *             type: string
 *           description: Categories the challenge belongs to
 *           example: ['Urban Planning', 'Transportation', 'IoT']
 *         maxParticipants:
 *           type: integer
 *           minimum: 1
 *           description: Maximum allowed number of participants
 *           example: 150
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           description: Keywords or tags associated with the challenge
 *           example: ['Mobility', 'Smart City', 'IoT', 'Green Technology']
 *         maxApprovedSolutions:
 *           type: integer
 *           minimum: 1
 *           description: Maximum number of solutions that can be approved
 *           example: 7
 *         visibility:
 *           $ref: '#/components/schemas/ChallengeVisibility'
 *         allowedInstitutions:
 *           type: array
 *           items:
 *             type: string
 *           description: List of institutions that can see private challenges
 *           example: ['University of Oxford', 'Imperial College London', 'University of Cambridge']
 *         isCompanyVisible:
 *           type: boolean
 *           description: Whether company identity is shown
 *           example: true
 *     
 *     ChallengeStatistics:
 *       type: object
 *       properties:
 *         viewCount:
 *           type: integer
 *           description: Number of views
 *           example: 1250
 *         submissionCount:
 *           type: integer
 *           description: Number of submissions received
 *           example: 42
 *         currentParticipants:
 *           type: integer
 *           description: Number of students participating
 *           example: 65
 *         remainingSpots:
 *           type: integer
 *           description: Number of participation spots remaining
 *           example: 35
 *         timeRemaining:
 *           type: integer
 *           description: Time remaining until deadline (in milliseconds)
 *           example: 1209600000
 *         approvedSolutionsCount:
 *           type: integer
 *           description: Number of approved solutions
 *           example: 12
 *         submissionsByDay:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               date:
 *                 type: string
 *                 format: date
 *                 example: '2023-06-15'
 *               count:
 *                 type: integer
 *                 example: 5
 *           description: Submissions grouped by day
 *         submissionsByInstitution:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               institution:
 *                 type: string
 *                 example: 'University of Oxford'
 *               count:
 *                 type: integer
 *                 example: 12
 *           description: Submissions grouped by institution
 *         averageRating:
 *           type: number
 *           format: float
 *           example: 4.2
 *           description: Average rating of reviewed solutions
 *         topCategories:
 *           type: array
 *           items:
 *             type: object
 *             properties:
 *               category:
 *                 type: string
 *                 example: 'Transportation'
 *               count:
 *                 type: integer
 *                 example: 18
 *           description: Most common categories among submitted solutions
 *
 *     ChallengeResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           $ref: '#/components/schemas/Challenge'
 *         message:
 *           type: string
 *           example: Challenge retrieved successfully
 *
 *     ChallengeListResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           type: object
 *           properties:
 *             challenges:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Challenge'
 *             pagination:
 *               $ref: '#/components/schemas/Pagination'
 *         message:
 *           type: string
 *           example: Challenges retrieved successfully
 *
 *     ChallengeStatisticsResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           $ref: '#/components/schemas/ChallengeStatistics'
 *         message:
 *           type: string
 *           example: Challenge statistics retrieved successfully
 */

/**
 * @swagger
 * tags:
 *   name: Challenges
 *   description: Operations for managing company challenges
 */

/**
 * @swagger
 * /challenges:
 *   post:
 *     summary: Create a new challenge
 *     description: Creates a new challenge. Available only to company users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateChallengeRequest'
 *     responses:
 *       201:
 *         description: Challenge created successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - type: object
 *                   properties:
 *                     status:
 *                       type: string
 *                       example: success
 *                     data:
 *                       $ref: '#/components/schemas/Challenge'
 *                     message:
 *                       type: string
 *                       example: Challenge created successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   get:
 *     summary: Get all challenges
 *     description: Retrieves a list of challenges with optional filtering. Accessible to all authenticated users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/ChallengeStatus'
 *         description: Filter by challenge status
 *       - name: category
 *         in: query
 *         schema:
 *           type: string
 *         description: Filter by category
 *       - name: difficulty
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/ChallengeDifficulty'
 *         description: Filter by difficulty
 *       - name: skills
 *         in: query
 *         schema:
 *           type: string
 *         description: Comma-separated list of skills to filter by
 *       - name: search
 *         in: query
 *         schema:
 *           type: string
 *         description: Search term for challenge title or description
 *     responses:
 *       200:
 *         description: List of challenges
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeListResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/company:
 *   get:
 *     summary: Get all challenges for current company
 *     description: Retrieves all challenges created by the authenticated company user
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *       - $ref: '#/components/parameters/SortParam'
 *       - name: status
 *         in: query
 *         schema:
 *           $ref: '#/components/schemas/ChallengeStatus'
 *         description: Filter by challenge status
 *     responses:
 *       200:
 *         description: List of company challenges
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeListResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/{id}:
 *   get:
 *     summary: Get a challenge by ID
 *     description: Retrieves a specific challenge by its ID. Accessible to all authenticated users, but visibility may be restricted based on user role and challenge settings.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeResponse'
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
 *     summary: Update a challenge
 *     description: Updates an existing challenge. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
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
 *             $ref: '#/components/schemas/UpdateChallengeRequest'
 *     responses:
 *       200:
 *         description: Challenge updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Cannot update a challenge in its current status
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   delete:
 *     summary: Delete a challenge
 *     description: Deletes a challenge. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Challenge deleted successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Cannot delete a challenge with active submissions
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/{id}/close:
 *   patch:
 *     summary: Close a challenge for submissions
 *     description: Closes a challenge for new submissions. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge closed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Challenge is not in a status that can be closed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/{id}/complete:
 *   patch:
 *     summary: Complete a challenge
 *     description: Marks a challenge as completed after the review process. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge completed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Challenge is not in a status that can be completed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/{id}/statistics:
 *   get:
 *     summary: Get challenge statistics
 *     description: Retrieves detailed statistics about a challenge. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge statistics
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeStatisticsResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 * 
 * /challenges/{id}/publish:
 *   patch:
 *     summary: Publish a challenge
 *     description: Publishes a draft challenge, making it visible to students. Only accessible to the company that created the challenge or admin users.
 *     tags: [Challenges]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Challenge ID
 *     responses:
 *       200:
 *         description: Challenge published successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ChallengeResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         description: Challenge is not in DRAFT status
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */