/**
 * @swagger
 * components:
 *   schemas:
 *     StudentProfileEducation:
 *       type: object
 *       properties:
 *         institution:
 *           type: string
 *           description: Name of educational institution
 *           example: University of Oxford
 *         degree:
 *           type: string
 *           description: Degree type or name
 *           example: Bachelor of Science in Computer Science
 *         fieldOfStudy:
 *           type: string
 *           description: Field or major of study
 *           example: Computer Science
 *         startDate:
 *           type: string
 *           format: date
 *           description: Education start date
 *           example: '2020-09-01'
 *         endDate:
 *           type: string
 *           format: date
 *           description: Education end date (or expected graduation)
 *           example: '2024-06-30'
 *         grade:
 *           type: string
 *           description: Grade or GPA
 *           example: '3.8/4.0'
 *         description:
 *           type: string
 *           description: Additional details about education
 *           example: 'Specialization in Artificial Intelligence and Machine Learning'
 *
 *     StudentProfileExperience:
 *       type: object
 *       properties:
 *         title:
 *           type: string
 *           description: Job title or position
 *           example: Software Engineering Intern
 *         company:
 *           type: string
 *           description: Company or organization name
 *           example: Google
 *         location:
 *           type: string
 *           description: Job location
 *           example: London, UK
 *         startDate:
 *           type: string
 *           format: date
 *           description: Job start date
 *           example: '2022-06-01'
 *         endDate:
 *           type: string
 *           format: date
 *           description: Job end date (or 'Present' for current positions)
 *           example: '2022-08-31'
 *         description:
 *           type: string
 *           description: Job responsibilities and achievements
 *           example: 'Developed and implemented new features for Google Maps API'
 *
 *     StudentProfileProject:
 *       type: object
 *       properties:
 *         title:
 *           type: string
 *           description: Project title
 *           example: Autonomous Drone Navigation System
 *         description:
 *           type: string
 *           description: Project description
 *           example: 'Developed an AI-based drone navigation system using computer vision and reinforcement learning'
 *         technologies:
 *           type: array
 *           items:
 *             type: string
 *           description: Technologies used in the project
 *           example: ['Python', 'TensorFlow', 'OpenCV', 'ROS']
 *         url:
 *           type: string
 *           format: uri
 *           description: Project URL or repository link
 *           example: 'https://github.com/username/drone-navigation'
 *         startDate:
 *           type: string
 *           format: date
 *           description: Project start date
 *           example: '2021-10-01'
 *         endDate:
 *           type: string
 *           format: date
 *           description: Project end date
 *           example: '2022-03-15'
 *
 *     StudentProfile:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Profile ID
 *           example: '60d21b4667d0d8992e610c85'
 *         userId:
 *           type: string
 *           format: objectId
 *           description: Associated user ID
 *           example: '60d21b4667d0d8992e610c86'
 *         firstName:
 *           type: string
 *           description: Student's first name
 *           example: John
 *         lastName:
 *           type: string
 *           description: Student's last name
 *           example: Doe
 *         institution:
 *           type: string
 *           description: Current academic institution
 *           example: University of Oxford
 *         bio:
 *           type: string
 *           description: Brief biography
 *           example: 'Computer Science student passionate about AI and machine learning'
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           description: Technical and soft skills
 *           example: ['JavaScript', 'React', 'Node.js', 'Problem Solving', 'Team Collaboration']
 *         education:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileEducation'
 *           description: Educational background
 *         experience:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileExperience'
 *           description: Work experience
 *         projects:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileProject'
 *           description: Personal or academic projects
 *         profilePicture:
 *           type: string
 *           format: uri
 *           description: URL to profile picture
 *           example: 'https://example.com/images/profile.jpg'
 *         socialLinks:
 *           type: object
 *           properties:
 *             linkedin:
 *               type: string
 *               format: uri
 *               example: 'https://linkedin.com/in/johndoe'
 *             github:
 *               type: string
 *               format: uri
 *               example: 'https://github.com/johndoe'
 *             twitter:
 *               type: string
 *               format: uri
 *               example: 'https://twitter.com/johndoe'
 *           description: Social media profiles
 *         resumeUrl:
 *           type: string
 *           format: uri
 *           description: URL to uploaded resume/CV
 *           example: 'https://example.com/resumes/johndoe.pdf'
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
 *     CompanyProfileSocialMedia:
 *       type: object
 *       properties:
 *         linkedin:
 *           type: string
 *           format: uri
 *           description: LinkedIn company page
 *           example: 'https://linkedin.com/company/acme'
 *         twitter:
 *           type: string
 *           format: uri
 *           description: Twitter company profile
 *           example: 'https://twitter.com/acme'
 *         facebook:
 *           type: string
 *           format: uri
 *           description: Facebook company page
 *           example: 'https://facebook.com/acme'
 *
 *     CompanyProfile:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           format: objectId
 *           description: Profile ID
 *           example: '60d21b4667d0d8992e610c87'
 *         userId:
 *           type: string
 *           format: objectId
 *           description: Associated user ID
 *           example: '60d21b4667d0d8992e610c88'
 *         companyName:
 *           type: string
 *           description: Registered company name
 *           example: ACME Corporation
 *         industry:
 *           type: string
 *           description: Company's industry or sector
 *           example: Technology
 *         description:
 *           type: string
 *           description: Detailed company description
 *           example: 'Leading provider of innovative technology solutions for enterprise businesses'
 *         foundedYear:
 *           type: integer
 *           description: Year the company was founded
 *           example: 2005
 *         size:
 *           type: string
 *           description: Company size range
 *           example: '501-1000 employees'
 *         headquarters:
 *           type: string
 *           description: Company headquarters location
 *           example: 'London, UK'
 *         website:
 *           type: string
 *           format: uri
 *           description: Company website URL
 *           example: 'https://www.acmecorp.com'
 *         logoUrl:
 *           type: string
 *           format: uri
 *           description: URL to company logo
 *           example: 'https://example.com/images/acme-logo.png'
 *         contactEmail:
 *           type: string
 *           format: email
 *           description: Public contact email
 *           example: 'contact@acmecorp.com'
 *         contactPhone:
 *           type: string
 *           description: Public contact phone number
 *           example: '+44 1234 567890'
 *         socialMedia:
 *           $ref: '#/components/schemas/CompanyProfileSocialMedia'
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
 *     CreateStudentProfileRequest:
 *       type: object
 *       required:
 *         - firstName
 *         - lastName
 *         - institution
 *       properties:
 *         firstName:
 *           type: string
 *           description: Student's first name
 *           example: John
 *         lastName:
 *           type: string
 *           description: Student's last name
 *           example: Doe
 *         institution:
 *           type: string
 *           description: Current academic institution
 *           example: University of Oxford
 *         bio:
 *           type: string
 *           description: Brief biography
 *           example: 'Computer Science student passionate about AI and machine learning'
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           description: Technical and soft skills
 *           example: ['JavaScript', 'React', 'Node.js', 'Problem Solving']
 *         education:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileEducation'
 *           description: Educational background
 *         profilePicture:
 *           type: string
 *           format: uri
 *           description: URL to profile picture
 *           example: 'https://example.com/images/profile.jpg'
 *         socialLinks:
 *           type: object
 *           properties:
 *             linkedin:
 *               type: string
 *               format: uri
 *               example: 'https://linkedin.com/in/johndoe'
 *             github:
 *               type: string
 *               format: uri
 *               example: 'https://github.com/johndoe'
 *             twitter:
 *               type: string
 *               format: uri
 *               example: 'https://twitter.com/johndoe'
 *           description: Social media profiles
 * 
 *     UpdateStudentProfileRequest:
 *       type: object
 *       properties:
 *         firstName:
 *           type: string
 *           description: Student's first name
 *           example: John
 *         lastName:
 *           type: string
 *           description: Student's last name
 *           example: Doe
 *         institution:
 *           type: string
 *           description: Current academic institution
 *           example: University of Oxford
 *         bio:
 *           type: string
 *           description: Brief biography
 *           example: 'Computer Science student passionate about AI and machine learning'
 *         skills:
 *           type: array
 *           items:
 *             type: string
 *           description: Technical and soft skills
 *           example: ['JavaScript', 'React', 'Node.js', 'Problem Solving']
 *         education:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileEducation'
 *           description: Educational background
 *         experience:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileExperience'
 *           description: Work experience
 *         projects:
 *           type: array
 *           items:
 *             $ref: '#/components/schemas/StudentProfileProject'
 *           description: Personal or academic projects
 *         profilePicture:
 *           type: string
 *           format: uri
 *           description: URL to profile picture
 *           example: 'https://example.com/images/profile.jpg'
 *         socialLinks:
 *           type: object
 *           properties:
 *             linkedin:
 *               type: string
 *               format: uri
 *               example: 'https://linkedin.com/in/johndoe'
 *             github:
 *               type: string
 *               format: uri
 *               example: 'https://github.com/johndoe'
 *             twitter:
 *               type: string
 *               format: uri
 *               example: 'https://twitter.com/johndoe'
 *           description: Social media profiles
 *         resumeUrl:
 *           type: string
 *           format: uri
 *           description: URL to uploaded resume/CV
 *           example: 'https://example.com/resumes/johndoe.pdf'
 *
 *     CreateCompanyProfileRequest:
 *       type: object
 *       required:
 *         - companyName
 *         - industry
 *         - description
 *       properties:
 *         companyName:
 *           type: string
 *           description: Registered company name
 *           example: ACME Corporation
 *         industry:
 *           type: string
 *           description: Company's industry or sector
 *           example: Technology
 *         description:
 *           type: string
 *           description: Detailed company description
 *           example: 'Leading provider of innovative technology solutions for enterprise businesses'
 *         foundedYear:
 *           type: integer
 *           description: Year the company was founded
 *           example: 2005
 *         size:
 *           type: string
 *           description: Company size range
 *           example: '501-1000 employees'
 *         headquarters:
 *           type: string
 *           description: Company headquarters location
 *           example: 'London, UK'
 *         website:
 *           type: string
 *           format: uri
 *           description: Company website URL
 *           example: 'https://www.acmecorp.com'
 *         logoUrl:
 *           type: string
 *           format: uri
 *           description: URL to company logo
 *           example: 'https://example.com/images/acme-logo.png'
 *         contactEmail:
 *           type: string
 *           format: email
 *           description: Public contact email
 *           example: 'contact@acmecorp.com'
 *         contactPhone:
 *           type: string
 *           description: Public contact phone number
 *           example: '+44 1234 567890'
 *         socialMedia:
 *           $ref: '#/components/schemas/CompanyProfileSocialMedia'
 *
 *     UpdateCompanyProfileRequest:
 *       type: object
 *       properties:
 *         companyName:
 *           type: string
 *           description: Registered company name
 *           example: ACME Corporation
 *         industry:
 *           type: string
 *           description: Company's industry or sector
 *           example: Technology
 *         description:
 *           type: string
 *           description: Detailed company description
 *           example: 'Leading provider of innovative technology solutions for enterprise businesses'
 *         foundedYear:
 *           type: integer
 *           description: Year the company was founded
 *           example: 2005
 *         size:
 *           type: string
 *           description: Company size range
 *           example: '501-1000 employees'
 *         headquarters:
 *           type: string
 *           description: Company headquarters location
 *           example: 'London, UK'
 *         website:
 *           type: string
 *           format: uri
 *           description: Company website URL
 *           example: 'https://www.acmecorp.com'
 *         logoUrl:
 *           type: string
 *           format: uri
 *           description: URL to company logo
 *           example: 'https://example.com/images/acme-logo.png'
 *         contactEmail:
 *           type: string
 *           format: email
 *           description: Public contact email
 *           example: 'contact@acmecorp.com'
 *         contactPhone:
 *           type: string
 *           description: Public contact phone number
 *           example: '+44 1234 567890'
 *         socialMedia:
 *           $ref: '#/components/schemas/CompanyProfileSocialMedia'
 *
 *     ProfileResponse:
 *       type: object
 *       properties:
 *         status:
 *           type: string
 *           example: success
 *         data:
 *           type: object
 *           description: Response data containing profile information
 *         message:
 *           type: string
 *           example: Profile operation successful
 */

/**
 * @swagger
 * tags:
 *   name: Profiles
 *   description: User profile management operations
 */

/**
 * @swagger
 * /profiles/student/{userId}:
 *   post:
 *     summary: Create a student profile
 *     description: Creates a new profile for a student user. Only accessible by the student themselves.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Student user ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateStudentProfileRequest'
 *     responses:
 *       201:
 *         description: Student profile created successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/StudentProfile'
 *                     message:
 *                       example: Student profile created successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       409:
 *         description: Profile already exists for this user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   get:
 *     summary: Get a student profile
 *     description: Retrieves a student's profile. Accessible by the student themselves or by companies, architects, and admins.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Student user ID
 *     responses:
 *       200:
 *         description: Student profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/StudentProfile'
 *                     message:
 *                       example: Student profile retrieved successfully
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
 *     summary: Update a student profile
 *     description: Updates an existing student profile. Only accessible by the student themselves.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Student user ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateStudentProfileRequest'
 *     responses:
 *       200:
 *         description: Student profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/StudentProfile'
 *                     message:
 *                       example: Student profile updated successfully
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
 * /profiles/company/{userId}:
 *   post:
 *     summary: Create a company profile
 *     description: Creates a new profile for a company user. Only accessible by the company themselves.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Company user ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateCompanyProfileRequest'
 *     responses:
 *       201:
 *         description: Company profile created successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/CompanyProfile'
 *                     message:
 *                       example: Company profile created successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       403:
 *         $ref: '#/components/responses/ForbiddenError'
 *       409:
 *         description: Profile already exists for this user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         $ref: '#/components/responses/InternalServerError'
 *   
 *   get:
 *     summary: Get a company profile
 *     description: Retrieves a company's profile. Accessible by the company themselves or by architects and admins.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Company user ID
 *     responses:
 *       200:
 *         description: Company profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/CompanyProfile'
 *                     message:
 *                       example: Company profile retrieved successfully
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
 *     summary: Update a company profile
 *     description: Updates an existing company profile. Only accessible by the company themselves.
 *     tags: [Profiles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: userId
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: objectId
 *         description: Company user ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateCompanyProfileRequest'
 *     responses:
 *       200:
 *         description: Company profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/ProfileResponse'
 *                 - type: object
 *                   properties:
 *                     data:
 *                       $ref: '#/components/schemas/CompanyProfile'
 *                     message:
 *                       example: Company profile updated successfully
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
 */