import { IAgentEvaluationResult, IEvaluationAgent } from '../../models/interfaces';
import { logger } from '../../utils/logger';
import { ApiError } from '../../utils/api.error';
import { HTTP_STATUS } from '../../models/interfaces';

/**
 * Factory class for creating and managing AI evaluation agents
 * Uses lazy loading and singleton pattern for agents
 */
export class AIAgentFactory {
  private static instance: AIAgentFactory;
  private agentRegistry: Map<string, IEvaluationAgent<IAgentEvaluationResult>> = new Map();
  
  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {}
  
  /**
   * Get the singleton instance of the factory
   */
  public static getInstance(): AIAgentFactory {
    if (!AIAgentFactory.instance) {
      AIAgentFactory.instance = new AIAgentFactory();
    }
    return AIAgentFactory.instance;
  }
  
  /**
   * Register an agent with the factory
   * @param agent - The agent instance to register
   */
  public registerAgent(agent: IEvaluationAgent<IAgentEvaluationResult>): void {
    if (this.agentRegistry.has(agent.name)) {
      logger.warn(`Agent ${agent.name} is already registered. Overwriting.`);
    }
    
    this.agentRegistry.set(agent.name, agent);
    logger.info(`Registered agent: ${agent.name}`);
  }
  
  /**
   * Get an agent by name
   * @param agentName - The name of the agent to retrieve
   * @returns The agent instance
   * @throws ApiError if the agent is not found
   */
  public getAgent<T extends IAgentEvaluationResult>(agentName: string): IEvaluationAgent<T> {
    const agent = this.agentRegistry.get(agentName);
    
    if (!agent) {
      logger.error(`Agent not found: ${agentName}`);
      throw new ApiError(
        HTTP_STATUS.NOT_FOUND,
        `AI evaluation agent not found: ${agentName}`,
        true,
        'AGENT_NOT_FOUND'
      );
    }
    
    return agent as IEvaluationAgent<T>;
  }
  
  /**
   * Get all registered agents
   * @returns Map of all registered agents
   */
  public getAllAgents(): Map<string, IEvaluationAgent<IAgentEvaluationResult>> {
    return new Map(this.agentRegistry);
  }
  
  /**
   * Check if an agent is registered
   * @param agentName - The name of the agent to check
   * @returns True if the agent is registered, false otherwise
   */
  public hasAgent(agentName: string): boolean {
    return this.agentRegistry.has(agentName);
  }
  
  /**
   * Unregister an agent from the factory
   * @param agentName - The name of the agent to unregister
   */
  public unregisterAgent(agentName: string): void {
    if (this.agentRegistry.has(agentName)) {
      this.agentRegistry.delete(agentName);
      logger.info(`Unregistered agent: ${agentName}`);
    } else {
      logger.warn(`Attempted to unregister non-existent agent: ${agentName}`);
    }
  }
} 