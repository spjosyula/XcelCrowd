/**
 * @swagger
 * components:
 *   schemas:
 *     EvaluationStatus:
 *       type: string
 *       enum:
 *         - pending
 *         - in_progress
 *         - completed
 *         - failed
 *       description: Status of an AI evaluation
 *       example: 'completed'
 *     
 *     EvaluationPriority:
 *       type: string
 *       enum:
 *         - high
 *         - normal
 *         - low
 *       description: Priority of the evaluation in processing queue
 *       example: 'normal'
 *     
 *     EvaluationMode:
 *       type: string
 *       enum:
 *         - standard
 *         - detailed
 *         - quick
 *       description: Mode of the evaluation
 *       example: 'standard'
 *     
 *     EvaluationSkipStep:
 *       type: string
 *       enum:
 *         - spam
 *         - requirements
 *         - code
 *         - scoring
 *       description: Evaluation step that can be skipped
 *       example: 'spam'
 *     
 *     StartEvaluationRequest:
 *       type: object
 *       properties:
 *         priority:
 *           $ref: '#/components/schemas/EvaluationPriority'
 *         notifyOnCompletion:
 *           type: boolean
 *           description: Whether to notify the user when evaluation completes
 *           example: false
 *         evaluationMode:
 *           $ref: '#/components/schemas/EvaluationMode'
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           description: Tags for categorizing evaluation
 *           example: ['capstone', 'web-app']
 *         skipSteps:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/EvaluationSkipStep'
 *           description: Steps to skip in the evaluation process (max 2)
 *           example: ['spam']
 *     
 *     RetryEvaluationRequest:
 *       type: object
 *       properties:
 *         forceRestart:
 *           type: boolean
 *           description: Whether to force restart evaluation from beginning
 *           example: false
 *         priority:
 *           $ref: '#/components/schemas/EvaluationPriority'
 *         skipSteps:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/EvaluationSkipStep'
 *           description: Steps to skip in the retry process (max 2)
 *           example: ['spam']
 *
 *     EvaluationResult:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Evaluation ID
 *           example: '60d21b4667d0d8992e610c85'
 *         solutionId:
 *           type: string
 *           format: objectId
 *           description: ID of the evaluated solution
 *           example: '60d21b4667d0d8992e610c86'
 *         status:
 *           $ref: '#/components/schemas/EvaluationStatus'
 *         startedAt:
 *           type: string
 *           format: date-time
 *           description: When the evaluation was started
 *           example: '2023-07-15T14:30:00.000Z'
 *         completedAt:
 *           type: string
 *           format: date-time
 *           description: When the evaluation was completed
 *           example: '2023-07-15T14:35:00.000Z'
 *         score:
 *           type: number
 *           description: Overall score of the evaluation (0-100)
 *           example: 85.5
 *         feedback:
 *           type: object
 *           properties:
 *             overall:
 *               type: string
 *               description: Overall feedback summary
 *               example: 'A strong solution with good implementation but some areas for improvement in documentation.'
 *             strengths:
 *               type: array
 *               items:
 *                 type: string
 *               description: Identified strengths of the solution
 *               example: ['Excellent code structure', 'Good use of design patterns', 'Comprehensive test coverage']
 *             weaknesses:
 *               type: array
 *               items:
 *                 type: string
 *               description: Identified weaknesses or areas for improvement
 *               example: ['Documentation could be more detailed', 'Some edge cases not handled', 'Performance could be optimized']
 *             recommendations:
 *               type: array
 *               items:
 *                 type: string
 *               description: Specific recommendations for improvement
 *               example: ['Add more inline comments', 'Implement error handling for edge cases', 'Consider async processing for better performance']
 *         categoryScores:
 *           type: object
 *           properties:
 *             implementation:
 *               type: number
 *               description: Score for implementation quality (0-100)
 *               example: 90
 *             innovation:
 *               type: number
 *               description: Score for innovation (0-100)
 *               example: 85
 *             usability:
 *               type: number
 *               description: Score for usability (0-100)
 *               example: 80
 *             documentation:
 *               type: number
 *               description: Score for documentation quality (0-100)
 *               example: 75
 *         errorDetails:
 *           type: string
 *           description: Details of any errors that occurred during evaluation
 *           example: 'Timeout while analyzing repository structure'
 *         initiatedBy:
 *           type: string
 *           format: objectId
 *           description: ID of user who initiated the evaluation
 *           example: '60d21b4667d0d8992e610c87'
 *         createdAt:
 *           type: string
 *           format: date-time
 *           description: Evaluation creation timestamp
 *           example: '2023-07-15T14:29:45.000Z'
 *         updatedAt:
 *           type: string
 *           format: date-time
 *           description: Evaluation last update timestamp
 *           example: '2023-07-15T14:35:10.000Z'
 *     
 *     EvaluationStatusResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: 'success'
 *         data:
 *           type: object
 *           properties:
 *             evaluationId:
 *               type: string
 *               format: objectId
 *               description: ID of the evaluation
 *               example: '60d21b4667d0d8992e610c85'
 *             solutionId:
 *               type: string
 *               format: objectId
 *               description: ID of the solution being evaluated
 *               example: '60d21b4667d0d8992e610c86'
 *             status:
 *               $ref: '#/components/schemas/EvaluationStatus'
 *             progress:
 *               type: number
 *               description: Percentage completion of the evaluation process
 *               example: 75
 *             timeElapsed:
 *               type: number
 *               description: Time elapsed since start in seconds
 *               example: 120
 *             estimatedCompletion:
 *               type: string
 *               format: date-time
 *               description: Estimated completion time
 *               example: '2023-07-15T14:35:00.000Z'
 *         message:
 *           type: string
 *           example: 'Evaluation status retrieved successfully'
 *     
 *     EvaluationResultResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: 'success'
 *         data:
 *           $ref: '#/components/schemas/EvaluationResult'
 *         message:
 *           type: string
 *           example: 'Evaluation result retrieved successfully'
 *     
 *     EvaluationAnalyticsResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: 'success'
 *         data:
 *           type: object
 *           properties:
 *             totalEvaluations:
 *               type: number
 *               description: Total number of evaluations
 *               example: 250
 *             completedEvaluations:
 *               type: number
 *               description: Number of completed evaluations
 *               example: 200
 *             failedEvaluations:
 *               type: number
 *               description: Number of failed evaluations
 *               example: 20
 *             pendingEvaluations:
 *               type: number
 *               description: Number of pending evaluations
 *               example: 30
 *             averageScore:
 *               type: number
 *               description: Average evaluation score across all completed evaluations
 *               example: 78.5
 *             averageCompletionTime:
 *               type: number
 *               description: Average time to complete an evaluation in seconds
 *               example: 180
 *             evaluationsByDate:
 *               type: object
 *               additionalProperties:
 *                 type: number
 *               description: Count of evaluations by date
 *               example: {"2023-07-01": 15, "2023-07-02": 22}
 *             categoryAverages:
 *               type: object
 *               properties:
 *                 implementation:
 *                   type: number
 *                   example: 82.3
 *                 innovation:
 *                   type: number
 *                   example: 75.8
 *                 usability:
 *                   type: number
 *                   example: 80.1
 *                 documentation:
 *                   type: number
 *                   example: 68.9
 *         message:
 *           type: string
 *           example: 'Evaluation analytics retrieved successfully'
 */

/**
 * @swagger
 * tags:
 *   name: AI Evaluation
 *   description: Operations related to AI evaluation of student solutions
 */

/**
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/evaluate:
 *   post:
 *     summary: Start AI evaluation for a solution
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: ID of the solution to evaluate
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/StartEvaluationRequest'
 *     responses:
 *       200:
 *         description: Evaluation process started successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: 'success'
 *                 data:
 *                   type: object
 *                   properties:
 *                     evaluationId:
 *                       type: string
 *                       format: objectId
 *                       example: '60d21b4667d0d8992e610c85'
 *                     solutionId:
 *                       type: string
 *                       format: objectId
 *                       example: '60d21b4667d0d8992e610c86'
 *                     status:
 *                       type: string
 *                       example: 'pending'
 *                 message:
 *                   type: string
 *                   example: 'AI evaluation started successfully'
 *       400:
 *         description: Invalid input or solution in wrong state
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */

/**
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/result:
 *   get:
 *     summary: Get AI evaluation result for a solution
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: ID of the solution to get evaluation for
 *     responses:
 *       200:
 *         description: Evaluation result retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/EvaluationResultResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */

/**
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/status:
 *   get:
 *     summary: Check status of an in-progress evaluation
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: ID of the solution to check evaluation status
 *       - in: query
 *         name: includeDetails
 *         schema:
 *           type: boolean
 *           default: false
 *         description: Whether to include detailed information in the response
 *       - in: query
 *         name: fields
 *         schema:
 *           type: string
 *           description: Comma-separated list of fields to include
 *           example: "status,progress,timeElapsed"
 *     responses:
 *       200:
 *         description: Evaluation status retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/EvaluationStatusResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */

/**
 * @swagger
 * /ai-evaluation/analytics:
 *   get:
 *     summary: Get AI evaluation analytics
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *           example: "2023-01-01"
 *         description: Start date for filtering analytics (YYYY-MM-DD)
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *           example: "2023-12-31"
 *         description: End date for filtering analytics (YYYY-MM-DD)
 *       - in: query
 *         name: challengeId
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Filter analytics by challenge ID
 *       - in: query
 *         name: groupBy
 *         schema:
 *           type: string
 *           enum: [day, week, month, challenge, status]
 *           default: day
 *         description: How to group the analytics data
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 50
 *         description: Maximum number of records to return
 *     responses:
 *       200:
 *         description: Analytics data retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/EvaluationAnalyticsResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */

/**
 * @swagger
 * /ai-evaluation/solutions/{solutionId}/retry:
 *   post:
 *     summary: Retry a failed evaluation
 *     tags: [AI Evaluation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: solutionId
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: ID of the solution to retry evaluation
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RetryEvaluationRequest'
 *     responses:
 *       200:
 *         description: Evaluation retry initiated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: 'success'
 *                 data:
 *                   type: object
 *                   properties:
 *                     evaluationId:
 *                       type: string
 *                       format: objectId
 *                       example: '60d21b4667d0d8992e610c85'
 *                     solutionId:
 *                       type: string
 *                       format: objectId
 *                       example: '60d21b4667d0d8992e610c86'
 *                     status:
 *                       type: string
 *                       example: 'pending'
 *                 message:
 *                   type: string
 *                   example: 'Evaluation retry initiated successfully'
 *       400:
 *         description: Invalid request or evaluation not in failed state
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 */ 