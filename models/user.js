const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters long'],
    validate: {
      validator: function(v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(v);
      },
      message: props => `Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long`
    }
  },
  validated: { type: Boolean, default: false },
  location: String,
  age: Number,
  otp: String,
  workDetails: String,
});

const User = mongoose.model('User', userSchema);

module.exports = User;
