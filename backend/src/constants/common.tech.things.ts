/**
 * Supported programming languages for analysis
 */
export enum ProgrammingLanguage {
  JAVASCRIPT = 'javascript',
  TYPESCRIPT = 'typescript',
  PYTHON = 'python',
  JAVA = 'java',
  CSHARP = 'csharp',
  GO = 'go',
  RUBY = 'ruby',
  PHP = 'php',
  SWIFT = 'swift',
  KOTLIN = 'kotlin',
  RUST = 'rust',
  UNKNOWN = 'unknown'
}

/**
 * File extension to language mapping
 */
export const FILE_EXTENSION_TO_LANGUAGE: Record<string, ProgrammingLanguage> = {
  '.js': ProgrammingLanguage.JAVASCRIPT,
  '.jsx': ProgrammingLanguage.JAVASCRIPT,
  '.ts': ProgrammingLanguage.TYPESCRIPT,
  '.tsx': ProgrammingLanguage.TYPESCRIPT,
  '.py': ProgrammingLanguage.PYTHON,
  '.java': ProgrammingLanguage.JAVA,
  '.cs': ProgrammingLanguage.CSHARP,
  '.go': ProgrammingLanguage.GO,
  '.rb': ProgrammingLanguage.RUBY,
  '.php': ProgrammingLanguage.PHP,
  '.swift': ProgrammingLanguage.SWIFT,
  '.kt': ProgrammingLanguage.KOTLIN,
  '.rs': ProgrammingLanguage.RUST
}; 

/**
 * Common technologies
 */
export const commonTechnologies = [
  'react', 'vue', 'angular', 'node', 'express', 'mongodb', 'mysql',
  'postgresql', 'django', 'flask', 'laravel', 'spring', 'dotnet', '.net',
  'javascript', 'typescript', 'python', 'java', 'c#', 'php', 'ruby',
  'docker', 'kubernetes', 'aws', 'azure', 'firebase', 'redux', 'bootstrap',
  'tailwind', 'material-ui', 'jest', 'pytest', 'junit'
];