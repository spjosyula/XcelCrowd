import mongoose, { Schema, model, Model } from 'mongoose';
import { ISolution, SolutionStatus } from './interfaces';
import validator from 'validator';

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
        // URL validation with 3rd party library for security
        // and input length check to prevent DoS attacks
        return v.length <= 2048 && validator.isURL(v, {
          protocols: ['http', 'https'],
          require_protocol: true,
          require_valid_protocol: true,
          require_tld: true,
          allow_trailing_dot: false,
          allow_protocol_relative_urls: false,
          disallow_auth: true
        });
      },
      message: props => `${props.value} is not a valid URL or exceeds maximum length`
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
  // Added fields for enhanced workflow
  selectedAt: {
    type: Date
  },
  selectedBy: {
    type: Schema.Types.ObjectId,
    ref: 'CompanyProfile'
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
  if (this.isModified('reviewedBy') && this.reviewedBy && !this.reviewedAt) {
    this.reviewedAt = new Date();
  }
  
  // Set selectedAt when status changes to SELECTED
  if (this.isModified('status') && this.status === SolutionStatus.SELECTED && !this.selectedAt) {
    this.selectedAt = new Date();
  }
  
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

/**
 * Create and export the Solution model
 */
const Solution: Model<ISolution> = mongoose.models.Solution || 
  model<ISolution>('Solution', solutionSchema);

export default Solution; 