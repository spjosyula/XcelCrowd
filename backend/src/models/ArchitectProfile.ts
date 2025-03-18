import mongoose, { Schema, model, Model } from 'mongoose';
import { IArchitectProfile } from './interfaces';

/**
 * Architect Profile schema definition
 * Represents the profile information for architects (validators) in the system
 */
const architectProfileSchema = new Schema<IArchitectProfile>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User reference is required'],
    unique: true
  },
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  specialization: {
    type: String,
    trim: true
  },
  yearsOfExperience: {
    type: Number,
    min: [0, 'Years of experience cannot be negative']
  },
  bio: {
    type: String,
    maxlength: [500, 'Bio cannot exceed 500 characters']
  },
  profilePicture: {
    type: String
  },
  skills: [{
    type: String,
    trim: true
  }],
  certifications: [{
    type: String,
    trim: true
  }]
}, {
  timestamps: true,
  versionKey: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Virtual for full name
 */
architectProfileSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.firstName || this.lastName || 'Unnamed Architect';
});

/**
 * Create and export the ArchitectProfile model
 */
const ArchitectProfile: Model<IArchitectProfile> = mongoose.models.ArchitectProfile || 
  model<IArchitectProfile>('ArchitectProfile', architectProfileSchema);

export default ArchitectProfile; 