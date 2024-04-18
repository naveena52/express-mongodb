const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'navina2k.ponna@gmail.com',
    pass: 'rryc ktvd tjfr auqx',
  },
});

const registerUser = async (req, res) => {
  try 
  {
    const { email, password } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000);
    const hashedPassword = await bcrypt.hash(password, 12);
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }
    // Create new user instance
    const user = new User({ email, password: hashedPassword, otp });

    // Save user to the database
    await user.save();
    const mailOptions = {
      from: 'navina2k.ponna@gmail.com',
      to: email,
      subject: 'OTP Verification',
      text: `Your OTP for registration is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ message: 'Failed to send OTP' });
      } else {
        console.log('Email sent: ' + info.response);
        return res.status(200).json({ message: 'OTP sent to your email' });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};
  
const validateopt = async (req, res) => {
    try {
      const { email, otp } = req.body;
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const storedOTP = user.otp;
      if (otp !== storedOTP) {
        return res.status(400).json({ message: 'Invalid OTP' });
      }
      user.validated = true;
      await user.save();
  
      res.status(200).json({ message: 'User validated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  };
  const loginUser = async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email) {
        return res.status(400).json({ message: 'Email is required' });
      }
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Invalid email ' });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
      }
      const token = jwt.sign({ email: user.email }, 'x-access-token', { expiresIn: '1h' });
      res.status(200).json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  };
  const updateUserInformation = async (req, res) => {
    try {
      const { location, age, workDetails } = req.body;
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ message: 'Authorization header missing' });
      }
  
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).json({ message: 'Token missing in Authorization header' });
      }
  
      const decodedToken = jwt.verify(token, 'x-access-token');
      const userEmail = decodedToken.email;
      const user = await User.findOneAndUpdate(
        { email: userEmail },
        { $set: { location, age, workDetails, validated: true } },
        { new: true }
      );
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      res.status(200).json({ message: 'User information updated successfully' });
    } catch (error) {
      console.error(error);
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: 'Invalid token' });
      }
      res.status(500).json({ message: 'Internal server error' });
    }
  };
module.exports = { registerUser,validateopt,loginUser,updateUserInformation};