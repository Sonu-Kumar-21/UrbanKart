import mongoose from 'mongoose';

const cartItemSchema = new mongoose.Schema({
  productId: { type: String, required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true },
  quantity: { type: Number, required: true, default: 1 }
});

const cartSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
  },
  items: [cartItemSchema]
}, { timestamps: true });

export const Cart = mongoose.model('Cart', cartSchema);
