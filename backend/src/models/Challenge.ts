import mongoose, { Schema, model, Model } from 'mongoose';
import { IChallenge, ChallengeStatus, ChallengeDifficulty, ChallengeVisibility } from './interfaces';

/**
 * Challenge schema definition
 * Represents company-posted challenges that students can solve
 */
const challengeSchema = new Schema<IChallenge>({
  title: {
    type: String,
    required: [true, 'Challenge title is required'],
    trim: true,
    maxlength: [100, 'Title cannot exceed 100 characters']
  },
  description: {
    type: String,
    required: [true, 'Challenge description is required'],
    trim: true
  },
  company: {
    type: Schema.Types.ObjectId,
    ref: 'CompanyProfile',
    required: [true, 'Company reference is required']
  },
  requirements: [{
    type: String,
    required: [true, 'At least one requirement is needed']
  }],
  resources: [{
    type: String
  }],
  rewards: {
    type: String
  },
  deadline: {
    type: Date,
    validate: {
      validator: function(this: IChallenge, value: Date) {
        return !value || value > new Date();
      },
      message: 'Deadline must be in the future'
    }
  },
  status: {
    type: String,
    enum: Object.values(ChallengeStatus),
    default: ChallengeStatus.DRAFT,
    required: [true, 'Challenge status is required']
  },
  difficulty: {
    type: String,
    enum: Object.values(ChallengeDifficulty),
    required: [true, 'Challenge difficulty is required']
  },
  category: [{
    type: String,
    required: [true, 'At least one category is required']
  }],
  maxParticipants: {
    type: Number,
    min: [1, 'Maximum participants must be at least 1']
  },
  currentParticipants: {
    type: Number,
    default: 0,
    min: [0, 'Current participants cannot be negative']
  },
  tags: [{
    type: String,
    trim: true
  }],
  // Added fields for enhanced workflow
  maxApprovedSolutions: {
    type: Number,
    default: 5,
    min: [1, 'Maximum approved solutions must be at least 1']
  },
  approvedSolutionsCount: {
    type: Number,
    default: 0,
    min: [0, 'Approved solutions count cannot be negative']
  },
  visibility: {
    type: String,
    enum: Object.values(ChallengeVisibility),
    default: ChallengeVisibility.PUBLIC,
    required: [true, 'Challenge visibility setting is required']
  },
  allowedInstitutions: [{
    type: String,
    required: function(this: any) {
      return this.visibility === ChallengeVisibility.PRIVATE;
    }
  }],
  isCompanyVisible: {
    type: Boolean,
    default: function(this: any) {
      return this.visibility !== ChallengeVisibility.ANONYMOUS;
    }
  },
}, {
  timestamps: true,
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Virtual for remaining spots
 */
challengeSchema.virtual('remainingSpots').get(function() {
  if (!this.maxParticipants) return Infinity;
  return Math.max(0, this.maxParticipants - this.currentParticipants);
});

/**
 * Virtual for time remaining
 */
challengeSchema.virtual('timeRemaining').get(function() {
  if (!this.deadline) return Infinity;
  const now = new Date();
  return Math.max(0, this.deadline.getTime() - now.getTime());
});

/**
 * Virtual for solutions (to be populated)
 */
challengeSchema.virtual('solutions', {
  ref: 'Solution',
  localField: '_id',
  foreignField: 'challenge'
});

/**
 * Method to check if deadline has passed
 */
challengeSchema.methods.isDeadlinePassed = function(): boolean {
  if (!this.deadline) return false;
  return new Date() > this.deadline;
};

/**
 * Method to check if approval limit is reached
 */
challengeSchema.methods.isApprovalLimitReached = function(): boolean {
  if (!this.maxApprovedSolutions) return false;
  return this.approvedSolutionsCount >= this.maxApprovedSolutions;
};

/**
 * Index for efficient querying
 */
challengeSchema.index({ status: 1, deadline: 1 });
challengeSchema.index({ company: 1 });
challengeSchema.index({ category: 1 });
challengeSchema.index({ tags: 1 });

/**
 * Create and export the Challenge model
 */
const Challenge: Model<IChallenge> = mongoose.models.Challenge || 
  model<IChallenge>('Challenge', challengeSchema);

export default Challenge; 