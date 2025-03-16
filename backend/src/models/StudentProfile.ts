import mongoose, { Schema, model, Model } from 'mongoose';
import { IStudentProfile } from './interfaces';

/**
 * Student profile schema definition
 */
const studentProfileSchema = new Schema<IStudentProfile>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User reference is required'],
    unique: true,
    index: true
  },
  firstName: {
    type: String,
    trim: true
  },
  lastName: {
    type: String,
    trim: true
  },
  university: {
    type: String,
    trim: true
  },
  resumeUrl: {
    type: String,
    trim: true
  },
  bio: {
    type: String,
    trim: true,
    maxlength: [500, 'Bio cannot be more than 500 characters']
  },
  profilePicture: {
    type: String,
    trim: true
  },
  skills: [{
    type: String,
    trim: true
  }],
  followers: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  following: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }]
}, {
  timestamps: true,
  versionKey: false
});

// Create compound index for efficient querying
studentProfileSchema.index({ skills: 1, university: 1 });

// Create and export the StudentProfile model
const StudentProfile: Model<IStudentProfile> = 
  mongoose.models.StudentProfile || model<IStudentProfile>('StudentProfile', studentProfileSchema);

export default StudentProfile;
