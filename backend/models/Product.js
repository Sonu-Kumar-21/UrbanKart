import mongoose from 'mongoose';

const reviewSchema = new mongoose.Schema({
  rating: { type: Number, required: true },
  author: { type: String, required: true },
  date: { type: String, required: true },
  comment: { type: String, required: true }
});

const productSchema = new mongoose.Schema({
  id: {
    type: String,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  image: {
    type: String,
    default: 'https://placehold.co/600x600',
  },
  description: {
    type: String,
    default: '',
  },
  featured: {
    type: Boolean,
    default: false,
  },
  reviews: [reviewSchema]
}, { timestamps: true });

export const Product = mongoose.model('Product', productSchema);
