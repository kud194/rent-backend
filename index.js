// Backend: Express + MongoDB + Authentication

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/rentApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const tenantSchema = new mongoose.Schema({
  name: String,
  phone: String,
  houseNumber: String,
  rentAmount: Number,
  paymentHistory: [
    {
      amount: Number,
      month: String,
      date: String,
    },
  ],
  ownerId: mongoose.Schema.Types.ObjectId,
});

const landlordSchema = new mongoose.Schema({
  name: String,
  phone: String,
  password: String,
});

const Tenant = mongoose.model('Tenant', tenantSchema);
const Landlord = mongoose.model('Landlord', landlordSchema);

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
};

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  const { name, phone, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const landlord = new Landlord({ name, phone, password: hashedPassword });
  await landlord.save();
  res.json({ message: 'Registered successfully' });
});

app.post('/api/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  const landlord = await Landlord.findOne({ phone });
  if (!landlord) return res.status(404).json({ message: 'User not found' });
  const match = await bcrypt.compare(password, landlord.password);
  if (!match) return res.status(401).json({ message: 'Incorrect password' });
  const token = jwt.sign({ id: landlord._id }, process.env.JWT_SECRET || 'secretkey');
  res.json({ token });
});

// Tenant routes
app.get('/api/tenants', authMiddleware, async (req, res) => {
  const tenants = await Tenant.find({ ownerId: req.user.id });
  res.json(tenants);
});

app.post('/api/tenants', authMiddleware, async (req, res) => {
  const tenant = new Tenant({ ...req.body, ownerId: req.user.id });
  await tenant.save();
  res.json(tenant);
});

app.put('/api/tenants/:id', authMiddleware, async (req, res) => {
  const tenant = await Tenant.findOneAndUpdate(
    { _id: req.params.id, ownerId: req.user.id },
    req.body,
    { new: true }
  );
  res.json(tenant);
});

app.delete('/api/tenants/:id', authMiddleware, async (req, res) => {
  await Tenant.findOneAndDelete({ _id: req.params.id, ownerId: req.user.id });
  res.sendStatus(204);
});

app.post('/api/tenants/:id/payment', authMiddleware, async (req, res) => {
  const tenant = await Tenant.findOne({ _id: req.params.id, ownerId: req.user.id });
  tenant.paymentHistory.push(req.body);
  await tenant.save();
  res.json(tenant);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
