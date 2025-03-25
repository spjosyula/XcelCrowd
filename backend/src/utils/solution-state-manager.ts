import { SolutionStatus } from "../models";

// Define valid state transitions with proper type annotation
const STATE_TRANSITIONS: Record<SolutionStatus, SolutionStatus[]> = {
  [SolutionStatus.DRAFT]: [SolutionStatus.SUBMITTED],
  [SolutionStatus.SUBMITTED]: [SolutionStatus.CLAIMED, SolutionStatus.REJECTED],
  [SolutionStatus.CLAIMED]: [SolutionStatus.APPROVED, SolutionStatus.REJECTED, SolutionStatus.SUBMITTED],
  [SolutionStatus.APPROVED]: [SolutionStatus.SUBMITTED],
  [SolutionStatus.REJECTED]: [SolutionStatus.SUBMITTED],
  [SolutionStatus.UNDER_REVIEW]: [SolutionStatus.APPROVED, SolutionStatus.REJECTED],
  [SolutionStatus.SELECTED]: [SolutionStatus.APPROVED, SolutionStatus.REJECTED],
}; 

/**
 * Validates if a state transition is allowed
 */
export function isValidTransition(fromState: SolutionStatus, toState: SolutionStatus): boolean {
  const allowedTransitions = STATE_TRANSITIONS[fromState];
  return allowedTransitions ? allowedTransitions.includes(toState) : false;
}

/**
 * Attempts to transition a solution to a new state
 * @throws Error if the transition is invalid
 */
export function transitionSolutionState(solution: any, newState: SolutionStatus, userId: string): void {
  const currentState = solution.state as SolutionStatus;
  
  if (!isValidTransition(currentState, newState)) {
    throw new Error(`Invalid state transition from ${currentState} to ${newState}`);
  }
  
  // Update solution state
  solution.state = newState;
  solution.updatedAt = new Date();
  solution.updatedBy = userId;
  
  console.log(`Solution ${solution.id} state changed: ${currentState} -> ${newState} by ${userId}`);
}