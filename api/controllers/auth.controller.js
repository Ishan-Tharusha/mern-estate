import User from '../models/user.model.js'
import bcryptjs from 'bcryptjs';

export const signup = async(req, res) => {
    const {userName, email, password} = req.body;
    const hashPassword = bcryptjs.hashSync(password, 10);
    const newuser = new User ({userName, email, password:hashPassword});
    try{
        await newuser.save();
        res.status(201).json('user created ssuccessfully');
    }catch(error){
        res.status(500).json(error.message);
    }
};