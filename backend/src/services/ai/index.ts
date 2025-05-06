import { AIEvaluationService } from './ai-evaluation.service';
import { AIAgentFactory } from './AIAgentFactory';
import { SpamFilteringAgent } from './agents/SpamFilteringAgent';
import { RequirementsComplianceAgent } from './agents/RequirementsComplianceAgent';
import { CodeQualityAgent } from './agents/CodeQualityAgent';
import { ScoringFeedbackAgent } from './agents/ScoringFeedbackAgent';
import { EvaluationPipelineController, evaluationPipelineController } from './EvaluationPipelineController';

// Create and export singleton instance of the evaluation service
const aiEvaluationService = new AIEvaluationService();

// Register all agents with the factory
const registerAgents = () => {
  const factory = AIAgentFactory.getInstance();
  
  // Register the four evaluation agents
  factory.registerAgent(new SpamFilteringAgent());
  factory.registerAgent(new RequirementsComplianceAgent());
  factory.registerAgent(new CodeQualityAgent());
  factory.registerAgent(new ScoringFeedbackAgent());
};

// Initialize the AI subsystem
const initializeAI = () => {
  // Register all AI agents
  registerAgents();
};

export {
  aiEvaluationService,
  AIEvaluationService,
  AIAgentFactory,
  registerAgents,
  initializeAI,
  evaluationPipelineController,
  EvaluationPipelineController
}; 