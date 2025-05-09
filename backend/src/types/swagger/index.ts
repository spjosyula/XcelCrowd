/**
 * @swagger
 * components:
 *   schemas:
 *     PaginatedResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           type: object
 *           properties:
 *             data:
 *               type: array
 *               items:
 *                 type: object
 *             pagination:
 *               $ref: '#/components/schemas/Pagination'
 *         message:
 *           type: string
 *           example: Items retrieved successfully
 *     
 *     DetailResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           type: object
 *         message:
 *           type: string
 *           example: Item retrieved successfully
 */

// Import all swagger documentation files
import './user.swagger';
import './auth.swagger';
import './profile.swagger';
import './architect.swagger';
import './challenge.swagger';
import './solution.swagger';
import './ai-evaluation.swagger';
// Later, you'll add more imports as you create those files:
// import './dashboard.swagger';