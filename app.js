const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
require('dotenv').config(); 
const app = express();
const PORT = process.env.PORT || 3000;
app.use(bodyParser.json());
mongoose.connect(process.env.MONGODB_URI, { 
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT} 🚀`);
});
