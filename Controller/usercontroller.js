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
module.exports = { registerUser};