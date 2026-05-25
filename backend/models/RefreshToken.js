import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  token: {
    type: String,
    required: true,
  }
}, { timestamps: true });

export const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);
