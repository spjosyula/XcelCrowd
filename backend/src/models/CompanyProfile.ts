import mongoose, { Schema, model, Model } from 'mongoose';
import { ICompanyProfile } from './interfaces';

/**
 * Company profile schema definition
 */
const companyProfileSchema = new Schema<ICompanyProfile>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User reference is required'],
    unique: true,
    index: true
  },
  companyName: {
    type: String,
    trim: true
  },
  website: {
    type: String,
    trim: true,
    match: [/^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})(\/[\w\-\.~:/?#[\]@!$&'()*+,;=]*)?$/, 'Please enter a valid URL']
  },
  contactNumber: {
    type: String,
    trim: true
  },
  industry: {
    type: String,
    trim: true
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, 'Description cannot be more than 1000 characters']
  },
  address: {
    type: String,
    trim: true
  }
}, {
  timestamps: true,
  versionKey: false
});

// Create index for efficient querying by industry
companyProfileSchema.index({ industry: 1 });

// Create and export the CompanyProfile model
const CompanyProfile: Model<ICompanyProfile> = 
  mongoose.models.CompanyProfile || model<ICompanyProfile>('CompanyProfile', companyProfileSchema);

export default CompanyProfile;