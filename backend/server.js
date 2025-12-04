const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/couple-activities', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  coupleName1: { type: String, default: 'Captain Paradox' },
  coupleName2: { type: String, default: 'Yiyo' },
});

// Category Schema
const categorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  image: String,
  items: [String],
  createdAt: { type: Date, default: Date.now }
});

// Completed Activity Schema
const completedActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  activity: { type: String, required: true },
  category: { type: String, required: true },
  date: { type: Date, default: Date.now },
  rating: { type: Number, min: 0, max: 5, default: 0 },
  image: String,
  notes: String
});

// Models
const User = mongoose.model('User', userSchema);
const Category = mongoose.model('Category', categorySchema);
const CompletedActivity = mongoose.model('CompletedActivity', completedActivitySchema);

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = await User.findById(verified.id);
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, coupleName1, coupleName2 } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      coupleName1: coupleName1 || 'Captain Paradox',
      coupleName2: coupleName2 || 'Yiyo'
    });
    
    await user.save();
    
    // Create token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        coupleName1: user.coupleName1,
        coupleName2: user.coupleName2
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Create token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        coupleName1: user.coupleName1,
        coupleName2: user.coupleName2
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all data for authenticated user
app.get('/api/data', authenticateToken, async (req, res) => {
  try {
    const categories = await Category.find({ userId: req.user._id });
    const completedActivities = await CompletedActivity.find({ userId: req.user._id })
      .sort({ date: -1 });
    
    // Convert categories to old format for compatibility
    const categoriesObject = {};
    categories.forEach(cat => {
      categoriesObject[cat.name] = {
        _id: cat._id,
        items: cat.items || [],
        image: cat.image || ''
      };
    });
    
    res.json({
      categories: categoriesObject,
      completedActivities,
      user: {
        coupleName1: req.user.coupleName1,
        coupleName2: req.user.coupleName2
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Categories CRUD
app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name, image } = req.body;
    const category = new Category({
      userId: req.user._id,
      name,
      image,
      items: []
    });
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/categories/:id', authenticateToken, async (req, res) => {
  try {
    const { name, image, items } = req.body;
    const category = await Category.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { name, image, items },
      { new: true }
    );
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  try {
    const category = await Category.findOne({ _id: req.params.id, userId: req.user._id });
    if (category) {
      await CompletedActivity.deleteMany({ 
        userId: req.user._id, 
        category: category.name 
      });
    }
    await Category.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    res.json({ message: 'Category deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Completed Activities CRUD
app.post('/api/completed', authenticateToken, async (req, res) => {
  try {
    const { activity, category, image, rating, notes } = req.body;
    const completedActivity = new CompletedActivity({
      userId: req.user._id,
      activity,
      category,
      image,
      rating: rating || 0,
      notes,
      date: new Date()
    });
    await completedActivity.save();
    res.status(201).json(completedActivity);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/completed/:id', authenticateToken, async (req, res) => {
  try {
    const { rating, image, notes } = req.body;
    const completedActivity = await CompletedActivity.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { rating, image, notes },
      { new: true }
    );
    res.json(completedActivity);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/completed/:id', authenticateToken, async (req, res) => {
  try {
    await CompletedActivity.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
    res.json({ message: 'Activity deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});