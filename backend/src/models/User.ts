import mongoose, { Schema, model, Model } from 'mongoose';
import bcrypt from 'bcryptjs';
import { IUser, UserRole } from './interfaces';

/**
 * User schema definition
 */
const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please use a valid email address']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false // Don't include password in query results by default
  },
  role: {
    type: String,
    enum: Object.values(UserRole),
    required: [true, 'User role is required']
  }
}, { 
  timestamps: true,
  versionKey: false,
  toJSON: {
    transform: (_, ret) => {
      delete ret.password;
      return ret;
    }
  }
});

/**
 * Password hashing middleware
 */
userSchema.pre('save', async function(next) {
  // Only hash the password if it's modified or new
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error: any) {
    next(error);
  }
});

/**
 * Method to compare password
 */
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

/**
 * Method to get user ID as string
 */
userSchema.methods.getId = function(): string {
  return this._id.toString();
};

// Create and export the User model
const User: Model<IUser> = mongoose.models.User || model<IUser>('User', userSchema);

export default User;