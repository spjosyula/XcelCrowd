import { AIAgentFactory } from './AIAgentFactory';
import { SpamFilteringAgent } from './agents/SpamFilteringAgent';
import { RequirementsComplianceAgent } from './agents/RequirementsComplianceAgent';
import { CodeQualityAgent } from './agents/CodeQualityAgent';
import { ScoringFeedbackAgent } from './agents/ScoringFeedbackAgent';
import { AIEvaluationService } from './ai-evaluation.service';
import { EvaluationPipelineController } from './EvaluationPipelineController';
import { logger } from '../../utils/logger';

// Create the agent factory singleton
const agentFactory = AIAgentFactory.getInstance();

// Initialize all evaluation agents
const spamFilteringAgent = SpamFilteringAgent.getInstance();
const requirementsComplianceAgent = RequirementsComplianceAgent.getInstance();
const codeQualityAgent = CodeQualityAgent.getInstance();
const scoringFeedbackAgent = ScoringFeedbackAgent.getInstance();

// Register all agents with the factory
agentFactory.registerAgent(spamFilteringAgent);
agentFactory.registerAgent(requirementsComplianceAgent);
agentFactory.registerAgent(codeQualityAgent);
agentFactory.registerAgent(scoringFeedbackAgent);

// Create the pipeline controller singleton
const evaluationPipelineController = EvaluationPipelineController.getInstance();

// Create the AI evaluation service singleton
const aiEvaluationService = new AIEvaluationService();

// Log successful initialization
logger.info('AI Evaluation Services initialized', {
  registeredAgents: [
    spamFilteringAgent.name,
    requirementsComplianceAgent.name,
    codeQualityAgent.name,
    scoringFeedbackAgent.name
  ]
});

export {
  agentFactory,
  evaluationPipelineController,
  aiEvaluationService,
  spamFilteringAgent,
  requirementsComplianceAgent,
  codeQualityAgent,
  scoringFeedbackAgent
}; 