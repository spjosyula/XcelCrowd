import mongoose, { Schema, model, Model } from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
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
  },
  // firstName: {
  //   type: String,
  //   trim: true
  // },
  // lastName: {
  //   type: String,
  //   trim: true
  // },
  // companyName: {
  //   type: String,
  //   trim: true
  // },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationTokenExpires: Date,
  passwordResetToken: String,
  passwordResetTokenExpires: Date
}, { 
  timestamps: true,
  versionKey: false,
  toJSON: {
    transform: (_, ret) => {
      delete ret.password;
      delete ret.emailVerificationToken;
      delete ret.emailVerificationTokenExpires;
      delete ret.passwordResetToken;
      delete ret.passwordResetTokenExpires;
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

/**
 * Generate email verification token
 */
userSchema.methods.generateEmailVerificationToken = function(): string {
  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Hash the OTP and store it
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  
  this.emailVerificationToken = hash;
  this.emailVerificationTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  
  return otp;
};

/**
 * Verify email verification token
 */
userSchema.methods.verifyEmailToken = function(otp: string): boolean {
  // If token is expired, return false
  if (!this.emailVerificationTokenExpires || this.emailVerificationTokenExpires < new Date()) {
    return false;
  }
  
  // Hash the provided OTP and compare with stored hash
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  return this.emailVerificationToken === hash;
};

/**
 * Generate password reset token
 */
userSchema.methods.generatePasswordResetToken = function(): string {
  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Hash the OTP and store it
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  
  this.passwordResetToken = hash;
  this.passwordResetTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  
  return otp;
};

/**
 * Verify password reset token
 */
userSchema.methods.verifyPasswordResetToken = function(otp: string): boolean {
  // If token is expired, return false
  if (!this.passwordResetTokenExpires || this.passwordResetTokenExpires < new Date()) {
    return false;
  }
  
  // Hash the provided OTP and compare with stored hash
  const hash = crypto.createHash('sha256').update(otp).digest('hex');
  return this.passwordResetToken === hash;
};

// Create and export the User model
const User: Model<IUser> = mongoose.models.User || model<IUser>('User', userSchema);

export default User;