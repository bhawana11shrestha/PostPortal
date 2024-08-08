// models/Linkedin.js

const mongoose = require('mongoose');

const CanvaSchema = new mongoose.Schema({
  accessToken: {
    type: String,
    required: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

module.exports = mongoose.model('Canva', CanvaSchema);
