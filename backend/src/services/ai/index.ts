import { AIEvaluationService } from './ai-evaluation.service';
import { AIAgentFactory } from './AIAgentFactory';
import { spamFilteringAgent } from './agents/SpamFilteringAgent';
import { requirementsComplianceAgent } from './agents/RequirementsComplianceAgent';
import { codeQualityAgent } from './agents/CodeQualityAgent';
import { scoringFeedbackAgent } from './agents/ScoringFeedbackAgent';
import { evaluationPipelineController } from './EvaluationPipelineController';

// Create and export singleton instance of the evaluation service
const aiEvaluationService = new AIEvaluationService();

// Register all agents with the factory
const registerAgents = () => {
  const factory = AIAgentFactory.getInstance();
  
  // Register the four evaluation agents
  factory.registerAgent(spamFilteringAgent);
  factory.registerAgent(requirementsComplianceAgent);
  factory.registerAgent(codeQualityAgent);
  factory.registerAgent(scoringFeedbackAgent);
};

// Initialize AI services
const initializeAI = () => {
  // Register all agents
  registerAgents();
  
  // Initialize the pipeline controller
  // The controller is already initialized as a singleton in its own file
  
  // Log initialization
  console.log('AI evaluation system initialized');
};

// Export services and initialization function
export {
  aiEvaluationService,
  evaluationPipelineController,
  initializeAI
}; 