import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

// Load environment variables
dotenv.config();

// Import Models
import { User } from './models/User.js';
import { Product } from './models/Product.js';
import { Cart } from './models/Cart.js';
import { Order } from './models/Order.js';
import { RefreshToken } from './models/RefreshToken.js';

const app = express();
const PORT = process.env.PORT || 5000;

// JWT Secrets
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

// Razorpay Configuration
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';

// --- Middlewares ---
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'https://urban-kart-356i.vercel.app'
    ];
    // Allow requests with no origin (like mobile apps or curl requests)
    // and allow any frontend hosted on Render
    if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.onrender.com')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());

// --- Database Connection ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// --- Helper Functions ---
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role || 'user' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
}

// --- Authentication Middleware ---
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Fetch fresh user data from database to get current role
    const currentUser = await User.findOne({ id: decoded.id });
    
    if (!currentUser) {
      return res.status(403).json({ message: 'User not found' });
    }
    
    req.user = {
      ...decoded,
      role: currentUser.role || 'user'
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired', expired: true });
    }
    return res.status(403).json({ message: 'Invalid token' });
  }
}

// Admin Middleware
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

// --- API Routes ---

app.get('/', (req, res) => {
  res.send('UrbanKart Backend API - All Systems Active 🚀');
});

// ==================== AUTHENTICATION ROUTES ====================

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  try {
    const userExists = await User.findOne({ email: email.toLowerCase() });
    if (userExists) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Date.now().toString();

    const newUser = new User({
      id: userId,
      name,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'user'
    });

    await newUser.save();
    
    // Initialize empty cart for new user
    const newCart = new Cart({
      userId: userId,
      items: []
    });
    await newCart.save();

    const accessToken = generateAccessToken(newUser);
    const refreshToken = generateRefreshToken(newUser);

    const newRefreshToken = new RefreshToken({
      userId: userId,
      token: refreshToken
    });
    await newRefreshToken.save();

    console.log('✅ New user signed up:', newUser.email, 'Role:', newUser.role);

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const newRefreshToken = new RefreshToken({
      userId: user.id,
      token: refreshToken
    });
    await newRefreshToken.save();

    console.log('✅ User logged in:', user.email, 'Role:', user.role);

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user'
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }

  try {
    const tokenExists = await RefreshToken.findOne({ token: refreshToken });
    if (!tokenExists) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const user = await User.findOne({ id: decoded.id });
    if (!user) {
      return res.status(403).json({ message: 'User not found' });
    }

    const newAccessToken = generateAccessToken(user);

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ message: 'Refresh token expired. Please login again' });
    }
    return res.status(403).json({ message: 'Invalid refresh token' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body;

  try {
    await RefreshToken.deleteOne({ token: refreshToken });

    console.log('✅ User logged out:', req.user.email);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error during logout' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ id: req.user.id });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user',
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { name } = req.body;

  if (!name || name.trim() === '') {
    return res.status(400).json({ message: 'Name is required' });
  }

  try {
    const user = await User.findOne({ id: req.user.id });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.name = name.trim();
    await user.save();

    console.log('✅ User profile updated:', req.user.email);

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Current password and new password are required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'New password must be at least 6 characters' });
  }

  try {
    const user = await User.findOne({ id: req.user.id });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    await RefreshToken.deleteMany({ userId: user.id });

    console.log('✅ Password changed for:', user.email);

    res.json({
      message: 'Password changed successfully. Please login again with your new password.'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== PRODUCT ROUTES ====================

app.get('/api/products', async (req, res) => {
  try {
    const { category, search, featured, minPrice, maxPrice } = req.query;
    let query = {};

    if (category && category !== 'all') {
      query.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    if (featured === 'true') {
      query.featured = true;
    }

    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = Number(minPrice);
      if (maxPrice) query.price.$lte = Number(maxPrice);
    }

    const products = await Product.find(query);
    res.json(products);
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findOne({ id: req.params.id });

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.json(product);
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== CART ROUTES ====================

app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    let userCart = await Cart.findOne({ userId: req.user.id });

    if (!userCart) {
      userCart = new Cart({ userId: req.user.id, items: [] });
      await userCart.save();
    }

    res.json({ items: userCart.items });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/cart/add', authenticateToken, async (req, res) => {
  const { productId, quantity = 1 } = req.body;

  if (!productId) {
    return res.status(400).json({ message: 'Product ID is required' });
  }

  try {
    const product = await Product.findOne({ id: productId });

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    let userCart = await Cart.findOne({ userId: req.user.id });
    
    if (!userCart) {
      userCart = new Cart({ userId: req.user.id, items: [] });
    }

    const existingItemIndex = userCart.items.findIndex(item => item.productId === productId);

    if (existingItemIndex > -1) {
      userCart.items[existingItemIndex].quantity += quantity;
    } else {
      userCart.items.push({
        productId: product.id,
        name: product.name,
        price: product.price,
        image: product.image,
        quantity: quantity
      });
    }

    await userCart.save();

    console.log(`✅ Added to cart: ${product.name} for user ${req.user.email}`);
    res.json({ message: 'Item added to cart', cart: userCart.items });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/cart/update', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;

  if (!productId || quantity === undefined) {
    return res.status(400).json({ message: 'Product ID and quantity are required' });
  }

  if (quantity < 0) {
    return res.status(400).json({ message: 'Quantity cannot be negative' });
  }

  try {
    const userCart = await Cart.findOne({ userId: req.user.id });

    if (!userCart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    if (quantity === 0) {
      userCart.items = userCart.items.filter(item => item.productId !== productId);
    } else {
      const item = userCart.items.find(item => item.productId === productId);
      if (item) {
        item.quantity = quantity;
      } else {
        return res.status(404).json({ message: 'Item not found in cart' });
      }
    }

    await userCart.save();

    res.json({ message: 'Cart updated', cart: userCart.items });
  } catch (error) {
    console.error('Update cart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/cart/remove/:productId', authenticateToken, async (req, res) => {
  const { productId } = req.params;

  try {
    const userCart = await Cart.findOne({ userId: req.user.id });

    if (!userCart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    userCart.items = userCart.items.filter(item => item.productId !== productId);
    await userCart.save();

    console.log(`✅ Removed from cart: ${productId} for user ${req.user.email}`);
    res.json({ message: 'Item removed from cart', cart: userCart.items });
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/cart/clear', authenticateToken, async (req, res) => {
  try {
    const userCart = await Cart.findOne({ userId: req.user.id });

    if (userCart) {
      userCart.items = [];
      await userCart.save();
    }

    console.log(`✅ Cart cleared for user ${req.user.email}`);
    res.json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== PAYMENT ROUTES ====================

app.get('/api/payment/key', (req, res) => {
  res.json({ key: RAZORPAY_KEY_ID });
});

app.post('/api/payment/create-order', authenticateToken, async (req, res) => {
  const { amount } = req.body;

  if (!amount || amount <= 0) {
    return res.status(400).json({ message: 'Invalid amount' });
  }

  try {
    const orderId = `order_${Date.now()}`;
    
    console.log(`💳 Payment order created: ${orderId} for ₹${amount}`);
    
    res.json({
      orderId: orderId,
      amount: amount,
      currency: 'INR',
      key: RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ message: 'Failed to create payment order' });
  }
});

app.post('/api/payment/verify', authenticateToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  if (!razorpay_payment_id) {
    return res.status(400).json({ message: 'Payment ID is required' });
  }

  try {
    console.log(`✅ Payment verified: ${razorpay_payment_id}`);
    
    res.json({
      success: true,
      message: 'Payment verified successfully',
      paymentId: razorpay_payment_id
    });
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

// ==================== ORDER ROUTES ====================

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, shippingAddress, paymentMethod, totalAmount, paymentId } = req.body;

  if (!items || items.length === 0) {
    return res.status(400).json({ message: 'Cart is empty' });
  }

  if (!shippingAddress || !paymentMethod) {
    return res.status(400).json({ message: 'Shipping address and payment method are required' });
  }

  try {
    const newOrder = new Order({
      id: `ORD-${Date.now()}`,
      userId: req.user.id,
      items: items,
      shippingAddress: shippingAddress,
      paymentMethod: paymentMethod,
      paymentId: paymentId || null,
      totalAmount: totalAmount || items.reduce((sum, item) => sum + (item.price * item.quantity), 0),
      status: 'pending',
      paymentStatus: paymentMethod === 'cod' ? 'pending' : 'paid'
    });

    await newOrder.save();

    const userCart = await Cart.findOne({ userId: req.user.id });
    if (userCart) {
      userCart.items = [];
      await userCart.save();
    }

    console.log(`✅ Order created: ${newOrder.id} for user ${req.user.email}`);
    res.status(201).json({ message: 'Order placed successfully', order: newOrder });
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const userOrders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(userOrders);
  } catch (error) {
    console.error('Get orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({ id: req.params.id, userId: req.user.id });

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    res.json(order);
  } catch (error) {
    console.error('Get order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/orders', authenticateToken, isAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error('Get all orders error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/admin/orders/:id', authenticateToken, isAdmin, async (req, res) => {
  const { status, paymentStatus } = req.body;

  try {
    const order = await Order.findOne({ id: req.params.id });

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    if (status) order.status = status;
    if (paymentStatus) order.paymentStatus = paymentStatus;
    
    await order.save();

    console.log(`✅ Order updated: ${order.id}`);
    res.json({ message: 'Order updated', order });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/products', authenticateToken, isAdmin, async (req, res) => {
  const { name, price, category, image, description, featured } = req.body;

  if (!name || !price || !category) {
    return res.status(400).json({ message: 'Name, price, and category are required' });
  }

  try {
    const newProduct = new Product({
      id: `p${Date.now()}`,
      name,
      price: Number(price),
      category,
      image: image || 'https://placehold.co/600x600',
      description: description || '',
      featured: featured || false,
      reviews: []
    });

    await newProduct.save();

    console.log(`✅ Product added: ${newProduct.name}`);
    res.status(201).json({ message: 'Product added', product: newProduct });
  } catch (error) {
    console.error('Add product error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});