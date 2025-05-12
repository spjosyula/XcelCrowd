import mongoose, { Schema, model, Model } from 'mongoose';
import { ISolution, SolutionStatus } from './interfaces';
import validator from 'validator';
import { MongoSanitizer } from '../utils/mongo.sanitize';

/**
 * Solution schema definition
 * Represents student solutions to company challenges, which are reviewed by architects
 */
const solutionSchema = new Schema<ISolution>({
  challenge: {
    type: Schema.Types.ObjectId,
    ref: 'Challenge',
    required: [true, 'Challenge reference is required']
  },
  student: {
    type: Schema.Types.ObjectId,
    ref: 'StudentProfile',
    required: [true, 'Student reference is required']
  },
  title: {
    type: String,
    required: [true, 'Solution title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Solution description is required'],
    trim: true
  },
  submissionUrl: {
    type: String,
    required: [true, 'Submission URL is required'],
    trim: true,
    validate: {
      validator: function(v: string) {
        // This includes protection against ReDoS and other URL-based attacks
        const sanitized = MongoSanitizer.sanitizeGitHubUrl(v);    
        if (!sanitized) {
          return false;
        }
        // Additional GitHub repository format validation
        // Match only github.com/username/repository format
        const safeGithubRepoRegex = /^https:\/\/(?:www\.)?github\.com\/[a-zA-Z0-9_-]{1,39}\/[a-zA-Z0-9_.-]{1,100}(?:\/)?(?:\?.*)?$/;
        
        return safeGithubRepoRegex.test(sanitized);
      },
      message: props => `${props.value} is not a valid GitHub repository URL. Please provide a direct link to a GitHub repository.`
    }
  },
  status: {
    type: String,
    enum: Object.values(SolutionStatus),
    default: SolutionStatus.SUBMITTED,
    required: [true, 'Solution status is required']
  },
  feedback: {
    type: String,
    trim: true
  },
  reviewedBy: {
    type: Schema.Types.ObjectId,
    ref: 'ArchitectProfile'
  },
  reviewedAt: {
    type: Date
  },
  score: {
    type: Number,
    min: [0, 'Score cannot be negative'],
    max: [100, 'Score cannot exceed 100']
  },
  // AI evaluation related fields
  aiScore: {
    type: Number,
    min: [0, 'AI score cannot be negative'],
    max: [100, 'AI score cannot exceed 100']
  },
  evaluationScores: {
    type: Map,
    of: Number,
    default: {}
  },
  reviewPriority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  rejectionReason: {
    type: String,
    trim: true
  },
  // Solution context for AI and workflow
  context: {
    type: Schema.Types.Mixed,
    default: {}
  },
  // Architect notes
  notes: {
    type: String,
    trim: true
  },
  lastUpdatedAt: {
    type: Date,
    default: Date.now
  },
  // Add submittedAt field
  submittedAt: {
    type: Date
  },
  // Add fields for enhanced workflow
  selectedAt: {
    type: Date
  },
  selectedBy: {
    type: Schema.Types.ObjectId,
    ref: 'CompanyProfile'
  },
  companyFeedback: {
    type: String,
    trim: true
  },
  selectionReason: {
    type: String,
    trim: true
  }
}, {
  timestamps: true,
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Pre-save middleware to update status when reviewed
 */
solutionSchema.pre('save', function(next) {
  // Need to use type assertion because mongoose doesn't properly type these fields
  const solution = this as unknown as {
    isModified: (path: string) => boolean;
    reviewedBy?: mongoose.Types.ObjectId;
    reviewedAt?: Date;
    status?: string;
    selectedAt?: Date;
    lastUpdatedAt: Date;
  };

  if (solution.isModified('reviewedBy') && solution.reviewedBy && !solution.reviewedAt) {
    solution.reviewedAt = new Date();
  }
  
  // Set selectedAt when status changes to SELECTED
  if (solution.isModified('status') && solution.status === SolutionStatus.SELECTED && !solution.selectedAt) {
    solution.selectedAt = new Date();
  }
  
  // Update lastUpdatedAt whenever the solution is modified
  solution.lastUpdatedAt = new Date();
  
  next();
});

/**
 * Index for efficient querying
 */
solutionSchema.index({ challenge: 1, student: 1 }, { unique: true });
solutionSchema.index({ status: 1 });
solutionSchema.index({ reviewedBy: 1 });
solutionSchema.index({ selectedBy: 1 });
solutionSchema.index({ reviewedBy: 1, status: 1 });
solutionSchema.index({ reviewedAt: -1 });
solutionSchema.index({ student: 1 });
solutionSchema.index({ challenge: 1 });
solutionSchema.index({ challenge: 1, status: 1 });
solutionSchema.index({ aiScore: -1 });
solutionSchema.index({ reviewPriority: 1 });
solutionSchema.index({ lastUpdatedAt: -1 });

/**
 * Create and export the Solution model
 */
const Solution: Model<ISolution> = mongoose.models.Solution || 
  model<ISolution>('Solution', solutionSchema);

export default Solution; 