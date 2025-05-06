import { ProgrammingLanguage } from "../../constants/common.tech.things";

/**
 * Shared interfaces for AI agent implementation
 * These interfaces are used across multiple agents
 */

// File information
export interface IFileInfo {
  path: string;
  name: string;
  extension: string;
  language?: ProgrammingLanguage;
  size: number;
  url: string;
  content?: string;
  hash?: string;
  metrics?: IFileMetrics;
  type?: 'file' | 'dir' | 'symlink' | 'submodule';
}

// Per-file metrics
export interface IFileMetrics {
  linesOfCode: number;
  commentLines: number;
  complexity: number;
  functions: number;
  classes: number;
  issues: ICodeIssue[];
}

// Code issue in a file
export interface ICodeIssue {
  type: 'style' | 'security' | 'performance' | 'maintainability';
  severity: 'info' | 'warning' | 'error' | 'critical';
  line: number;
  column?: number;
  message: string;
  rule?: string;
}

// Vulnerability scan result
export interface IVulnerabilityResult {
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  location?: string;
  languageSpecific: boolean;
  cwe?: string; // Common Weakness Enumeration ID
  remediation?: string;
}

// Repository analysis result
export interface IRepositoryAnalysis {
  files: IFileInfo[];
  directories: string[];
  languages: Map<ProgrammingLanguage, number>; // Language to byte count
  primaryLanguage: ProgrammingLanguage;
  testFiles: IFileInfo[];
  configFiles: IFileInfo[];
  readmeFile?: IFileInfo;
  vulnScanResults: IVulnerabilityResult[];
  totalSize: number;
  issueCount: number;
  commitCount: number;
  contributorCount: number;
  branchCount: number;
  // Code metrics
  linesOfCode: number;
  commentLines: number;
  complexity: number;
  duplication: number;
  testCoverage: number;
}

// Challenge requirement structure
export interface IChallengeRequirement {
  id: string;
  name: string;
  description: string;
  type: 'file' | 'feature' | 'package' | 'structure' | 'other' | 'quality';
  importance: 'critical' | 'important' | 'nice-to-have';
  // For file requirements
  filePath?: string;
  filePattern?: string;
  extensions?: string[];
  // For code requirements
  codePattern?: string;
  // For package requirements
  packageName?: string;
  packageType?: 'npm' | 'python' | 'ruby' | 'other';
  packageVersion?: string;
}

// Extended scoring feedback metadata
export interface IExtendedScoringFeedbackMetadata {
  componentScores: {
    spamFilter: number;
    requirements: number;
    codeQuality: number;
  };
  weightedScore: number;
  confidence: number;
  humanReviewRecommended: boolean;
  strengths: string[];
  weaknesses: string[];
  suggestedFeedback: string;
  suggestedArchitects: Array<{
    architectId: any; // Type will be refined when imported in the agent
    matchScore: number;
    expertise: string[];
  }>;
  priorityLevel: 'low' | 'medium' | 'high';
  decision: any; // Type will be refined when imported in the agent
}

// Cache structure
export interface ICachedRepositoryAnalysis {
  timestamp: number;
  analysis: IRepositoryAnalysis;
}

// Vulnerability pattern
export interface IVulnerabilityPattern {
  pattern: RegExp;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  language: ProgrammingLanguage | 'all';
} 