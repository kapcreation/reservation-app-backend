import User from "../models/User.js"
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

export const register = async (req, res) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

    const existingUser = await User.find({ username: req.body.username })

    if (existingUser.length > 0) return res.status(409).json("User already exist!")

    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      password: hash,
    })

    const savedUser = await newUser.save()

    const token = jwt.sign({ id: savedUser._id, isAdmin: savedUser.isAdmin }, process.env.JWT_SECRET)

    const { password, ...otherDetails } = savedUser._doc

    res.status(200).json({ ...otherDetails, token })
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const login = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username })

    if (!user) return res.status(404).json("User not found!")

    const passwordIsCorrect = await bcrypt.compare(req.body.password, user.password)

    if (!passwordIsCorrect) return res.status(400).json("Wrong password!")

    const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET)

    const { password, ...otherDetails } = user._doc

    res.status(200).json({ ...otherDetails, token })
  } catch (error) {
    res.status(500).json(error.message)
  }
}