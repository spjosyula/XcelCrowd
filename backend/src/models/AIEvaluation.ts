import mongoose, { Schema, model, Model } from 'mongoose';
import { IAIEvaluation } from './interfaces';

/**
 * AI Evaluation schema definition
 * Stores results from the AI evaluation pipeline for GitHub solution submissions
 */
const aiEvaluationSchema = new Schema<IAIEvaluation>({
  solution: {
    type: Schema.Types.ObjectId,
    ref: 'Solution',
    required: [true, 'Solution reference is required'],
  },

  // Individual agent evaluation results
  spamFiltering: {
    type: {
      score: Number,
      feedback: String,
      metadata: Schema.Types.Mixed,
      evaluatedAt: Date
    },
    _id: false
  },

  requirementsCompliance: {
    type: {
      score: Number,
      feedback: String,
      metadata: Schema.Types.Mixed,
      evaluatedAt: Date
    },
    _id: false
  },

  codeQuality: {
    type: {
      score: Number,
      feedback: String,
      metadata: Schema.Types.Mixed,
      evaluatedAt: Date
    },
    _id: false
  },

  scoringFeedback: {
    type: {
      score: Number,
      feedback: String,
      metadata: Schema.Types.Mixed,
      evaluatedAt: Date
    },
    _id: false
  },

  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'failed'],
    default: 'pending',
    required: true,
    index: true
  },

  failureReason: {
    type: String
  },

  completedAt: {
    type: Date
  },
  retryCount: {
    type: Number,
    default: 0
  },

  metadata: {
    type: Schema.Types.Mixed,
    default: {}
  }
}, {
  timestamps: true,
  versionKey: false
});

// Index for efficient queries
aiEvaluationSchema.index({ 'solution': 1 }, { unique: true });
aiEvaluationSchema.index({ 'status': 1, 'createdAt': 1 });

/**
 * Create and export the AIEvaluation model
 */
const AIEvaluation: Model<IAIEvaluation> = mongoose.models.AIEvaluation ||
  model<IAIEvaluation>('AIEvaluation', aiEvaluationSchema);

export default AIEvaluation; 