const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: {type: String, required: true, unique: true },
  validated: { type: Boolean, default: false },
  location: String,
  age: Number,
  otp: Number,
  workDetails: String,
});

const User = mongoose.model('User', userSchema);

module.exports = User;
