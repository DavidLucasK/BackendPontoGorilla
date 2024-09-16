const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors({
    origin: ['https://pontogorillaback.vercel.app', 'http://127.0.0.1:5500']
}));
app.use(express.json());

const authRoutes = require('./auth');
app.use('/api/auth', authRoutes);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
