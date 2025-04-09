import User from '../models/user.model.js';
import bcryptjs from 'bcryptjs';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken';

// Signup Controller
export const signup = async (req, res, next) => {  // Fixed async typo
    try {
        const { userName, email, password } = req.body;

        // Ensure password is provided
        if (!password) return next(errorHandler(400, 'Password is required'));

        // Hash the password
        const hashedPassword = bcryptjs.hashSync(password, 10);

        // Create a new user
        const newUser = new User({ userName, email, password: hashedPassword });

        // Save the user
        await newUser.save();
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        next(error);
    }
};

export const signin = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        const validUser = await User.findOne({ email });
        if (!validUser) return next(errorHandler(404, 'User not found'));

        const validPassword = bcryptjs.compareSync(password, validUser.password);
        if (!validPassword) return next(errorHandler(400, 'Wrong credentials'));

        const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const {password: pass , ...rest} = validUser._doc;

        res.cookie('access_token', token, { httpOnly: true })
           .status(200)
           .json({rest});

    } catch (error) {
        next(error);
    }
};

export const google = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email });

        if (user) {
            // If user exists, generate JWT token
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Destructure the user object and exclude the password
            const { password: pass, ...rest } = user._doc;

            // Send the token in a cookie and return the user data
            res.cookie('access_token', token, { httpOnly: true })
                .status(200)
                .json({ ...rest });
        } else {
            // If user doesn't exist, create a new user
            const generatedPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
            const hashedPassword = bcryptjs.hashSync(generatedPassword);

            const newUser = new User({
                userName: req.body.name.split(" ").join("").toLowerCase() + Math.random().toString(36).slice(-4),
                email: req.body.email,
                password: hashedPassword,
                avatar: req.body.photo
            });

            // Save the new user to the database
            await newUser.save();

            // Generate a JWT token for the new user
            const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Destructure the new user object and exclude the password
            const { password: pass, ...rest } = newUser._doc;

            // Send the token in a cookie and return the user data
            res.cookie('access_token', token, { httpOnly: true })
                .status(200)
                .json({ ...rest });
        }
    } catch (error) {
        next(error);
    }
};
