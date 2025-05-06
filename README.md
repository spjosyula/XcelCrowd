# XcelCrowd

## Overview

XcelCrowd is a transformative platform that bridges the gap between academic potential and industry innovation. Our platform creates a verified, student-only ecosystem where university students can build professional profiles, connect with companies, and engage with real-world challenges.

## Features

-**Verified Student Ecosystem:** Only institutionally verified students can join, ensuring authenticity, trust, and a high-quality talent pool.

-**Real-World Challenge Participation:** Students engage with industry-grade problems posted by companies, applying their academic knowledge to practical, high-impact tasks.

-**Dynamic Company Profiles:** Companies showcase their brand, publish challenges, and gain direct access to top-performing, pre-vetted student talent.

-**Rich Student Portfolios:** Students build comprehensive profiles featuring skills, achievements, project work, and verified credentials—positioning themselves for real career opportunities.

The XcelCrowd **AI Evaluation System** is designed to automatically assess GitHub repository submissions for coding challenges and assignments. This system uses a multi-agent architecture to evaluate various aspects of submissions including validity, requirements compliance, and code quality.

## Evaluation Pipeline

Submissions are processed as a batch after the challenge deadline has passed. The evaluation workflow follows these stages:

1. **Spam Filtering Agent** - Acts as a first-pass filter to identify spam or invalid GitHub submissions
2. **Requirements Compliance Agent** - Thoroughly analyzes the company's challenge requirements and ensures submissions meet all specifications
3. **Code Quality Agent** - Analyzes code quality metrics but only rejects if code quality is explicitly part of the challenge requirements
4. **Scoring and Feedback Agent** - Integrates results from other agents to provide comprehensive scoring and prepares accepted submissions for architect review

## Key Workflow Rules

- **Batch Processing**: All solutions for a challenge are processed together after the submission deadline
- **No Resubmission**: Students can only edit their submissions until the deadline; no resubmissions are allowed after the deadline passes
- **Rejection Points**: Solutions can only be rejected at the Spam Filtering or Requirements Compliance stages
- **Code Quality Assessment**: Unless code quality is explicitly in the challenge requirements, this agent only provides informational scoring without rejecting submissions
- **Final Acceptance**: Any solution that reaches the Scoring and Feedback Agent is automatically accepted and sent to the architects' dashboard

## Scoring Methodology

The final evaluation score for each student's repository is determined using a weighted scoring model, which combines multiple assessment criteria, each assigned a specific weight to reflect its importance. This model ensures a balanced and objective evaluation by considering various aspects of the repository.

The components and their respective weights are as follows:

Spam Filtering (10%): This component assesses the legitimacy and relevance of the submission, ensuring that the repository is not spam and aligns with the intended purpose.

Requirements Compliance (40%): This evaluates how well the repository adheres to the specified project requirements, including functionality, features, and other stipulated criteria.

Code Quality (50%): This examines the code's style, security, performance, and overall maintainability, reflecting the technical proficiency demonstrated in the repository.

### Score Thresholds

The system uses the following score thresholds to categorize submissions:

- **Excellent (85-100)**: Exceeds expectations, high priority for architect review
- **Good (70-84)**: Meets all requirements with some areas for improvement
- **Acceptable (50-69)**: Meets basic requirements but needs significant improvements
- **Needs Improvement (0-49)**: May indicate issues, but solution still proceeds to architect review if it passes requirements

## Submission Flow

1. Student submits a GitHub repository link before the challenge deadline
2. Students can edit their submission until the deadline
3. After the deadline, all submissions are processed together through the AI evaluation pipeline
4. Solutions are evaluated in this sequence:
   - Spam Filtering (rejects invalid submissions)
   - Requirements Compliance (rejects submissions that don't meet requirements)
   - Code Quality Analysis (provides scoring but doesn't typically reject)
   - Final Scoring and Feedback (prepares submissions for architect review)
5. All submissions that pass the Requirements Compliance stage are accepted and forwarded to architects
6. Architects review all accepted submissions via their dashboard and provide final assessment

## Agent Responsibilities

### Spam Filtering Agent
- Validates GitHub repository legitimacy
- Checks for repository existence and accessibility
- Identifies spam or template repositories
- **Can reject submissions** if they don't meet basic validity criteria

### Requirements Compliance Agent
- Thoroughly analyzes the company's challenge description
- Extracts explicit and implicit requirements
- Performs comprehensive verification of all requirements
- Never makes assumptions about requirements
- **Can reject submissions** if they fail to meet essential requirements

### Code Quality Agent
- Evaluates code across 11 supported programming languages
- Provides detailed metrics on security, performance, and maintainability
- Identifies vulnerabilities and suggests remediation
- **Only rejects submissions if** code quality is explicitly listed as a challenge requirement

### Scoring and Feedback Agent
- Calculates final weighted scores from all preceding evaluations
- Generates comprehensive feedback for students
- Prioritizes submissions for architect review
- **Never rejects submissions** - all submissions reaching this stage are accepted

## Key Features

### GitHub Token Management

- Handles multiple GitHub API tokens with rotation strategy
- Increases rate limits from 60 to 5,000 requests per hour
- Tracks token usage and automatically handles rate limiting
- Deactivates and reactivates tokens based on errors and reset times

### Requirements Compliance

- Recursively analyzes repository structure and contents
- Extracts and validates requirements from challenge descriptions
- Checks for required files, dependencies, and proper structure
- Calculates weighted penalties for missing critical requirements

### Code Quality Analysis

- Supports 11 programming languages with language-specific metrics
- Detects security vulnerabilities using pattern matching
- Evaluates code complexity, maintainability, and performance
- Estimates test coverage and identifies duplication
- Provides actionable remediation advice

### Comprehensive Feedback

- Identifies specific strengths and weaknesses
- Prioritizes critical issues in feedback
- Provides actionable recommendations for improvement
- Creates personalized feedback based on submission quality

## Benefits

- **For Students**:
  - Clear understanding of evaluation criteria
  - Consistent and objective evaluation
  - Detailed feedback for future improvement
  - Fair assessment based strictly on defined requirements

- **For Architects**:
  - Reduced time spent on basic evaluations
  - Focus on higher-value review activities
  - Suggested expertise matching for submissions
  - Batch processing of accepted submissions

- **For Administrators**:
  - Higher throughput of evaluations
  - Consistent quality standards
  - Reduced manual review load
  - Detailed metrics and analytics on submissions

## System Requirements

- Node.js (v14+)
- MongoDB
- GitHub API tokens (configured in environment variables)
- Minimum 2GB RAM recommended for processing large repositories

## Getting Started

1. Clone the repository
2. Install dependencies with `npm install`
3. Configure environment variables (see `.env.example`)
4. Start the service with `npm run start`

## Configuration

The system can be configured through environment variables:

```
# GitHub API Tokens (comma-separated)
GITHUB_API_TOKENS=token1,token2,token3

# Scoring weights (optional, defaults shown)
SCORING_WEIGHT_SPAM=0.1
SCORING_WEIGHT_REQUIREMENTS=0.4  
SCORING_WEIGHT_CODE_QUALITY=0.5
```

---

# XcelCrowd_MVP-1

**XcelCrowd - Student Networking & Crowdsourcing Platform**

XcelCrowd is a transformative platform that bridges the gap between academic potential and industry innovation. Our platform creates a verified, student-only ecosystem where university students can build professional profiles, connect with companies, and engage with real-world challenges.

---

## 🚀 Project Overview

XcelCrowd serves two primary user groups with completely separate workflows:

### For Students
- **Verified Profiles:** Create a trusted professional profile using your institutional email.
- **Dynamic Portfolios:** Showcase your skills, resume, project experiences, and xcelled solutions.
- **Exclusive Challenges:** Discover and apply to real-world projects from various companies.
- **Professional Networking:** Connect with fellow students and industry experts.
- **Performance Metrics:** Track your progress with comprehensive analytics and valuable feedback.

### For Companies
- **Talent Hub:** Access a pool of verified student profiles.
- **Real-World Challenges:** Post projects to engage emerging talent.
- **Streamlined Review:** Efficiently evaluate worthy submissions, scrutinized by validators (architects).
- **Robust Analytics:** Gain deep insights through detailed metrics dashboards.
- **Innovative Recruitment:** Discover and nurture top talent seamlessly.

---

## 🛠️ Tech Stack

**Frontend:**
- **Next.js 15** with App Router architecture
- **React 19** with TypeScript
- **Tailwind CSS** for styling
- **shadcn/ui** for component library

**Backend:**
- **Node.js with Express**
- **TypeScript** for type safety
- **MongoDB** with Mongoose ODM
- **JWT** for authentication
- **Zod** for validation

---

## 🏁 Getting Started

### Prerequisites
- Node.js (v18+)
- MongoDB
- npm or yarn

### Backend Setup
1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Create a `.env` file:**  
   Copy the `.env.example` file and fill in the required values.
4. **Start the development server:**
   ```bash
   npm run dev
   ```

### Frontend Setup
1. **Navigate to the frontend directory:**
   ```bash
   cd frontend
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```
3. **Start the development server:**
   ```bash
   npm run dev
   ```

The application will be available at [http://localhost:3000](http://localhost:3000).

---
