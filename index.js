import express from 'express'
import dotenv from 'dotenv'
import mongoose from 'mongoose'
import cors from 'cors'
import authRoute from './routes/auth.js'
import hotelsRoute from './routes/hotels.js'
import roomsRoute from './routes/rooms.js'
import usersRoute from './routes/users.js'

dotenv.config()
mongoose.set("strictQuery", false);
const app = express()
const port = 5000
app.use(express.json())
app.use(cors());

const connect = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
  } catch (error) {
    console.error(error);
  }
}

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.use('/auth', authRoute)
app.use('/hotels', hotelsRoute)
app.use('/rooms', roomsRoute)
app.use('/users', usersRoute)

app.listen(port, () => {
  connect()
  console.log(`App listening on port ${port}`)
})