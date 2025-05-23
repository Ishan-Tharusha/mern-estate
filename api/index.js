import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import userRouter from './routes/user.route.js';
import authRouter from './routes/auth.route.js';

dotenv.config();

mongoose.connect(process.env.MONGO)
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.log(err);
    });

const app = express();

// Middleware
app.use(express.json());

// Routes
app.use("/api/user", userRouter);
app.use("/api/auth", authRouter);

// Error Handling Middleware
app.use((err, req, res, next) => {
    const statusCode = err.statusCode || 500; 
    const message = err.message || 'Internal Server Error';
    return res.status(statusCode).json({
        success: false,
        statusCode,
        message,
    });
});

// Start Server (Move to the Bottom)
app.listen(3000, () => {
    console.log('Server is running on port 3000...');
});
