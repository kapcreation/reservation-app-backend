import Room from "../models/Room.js";
import Hotel from '../models/Hotel.js'

export const createRoom = async (req, res) => {
  try {
    const roomNumbers = req.body.roomNumbers.split(",").map(number=> {
      return { number }
    })

    const newRoom = new Room({...req.body, roomNumbers})

    const savedRoom = await newRoom.save()

    res.status(200).json(savedRoom)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const updateRoom = async (req, res) => {
  try {
    const updatedRoom = await Room.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
    
    res.status(200).json(updatedRoom)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const deleteRoom = async (req, res) => {
  try {
    await Room.findByIdAndDelete(req.params.id)
    
    res.status(200).json("Room has been deleted.")
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const getRoom = async (req, res) => {
  try {
    const room = await Room.findById(req.params.id)
    
    res.status(200).json(room)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const getRooms = async (req, res) => {
  try {
    const rooms = await Room.find()
    
    res.status(200).json(rooms)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const setAvailable = async (req, res) => {
  try {
    const ids = req.query.ids.split(",")
    
    await Promise.all(ids.map(id=>{
      return Room.updateOne(
        { "roomNumbers._id": id },
        { $push: { "roomNumbers.$.unavailableDates": req.body.dates } }
      )
    }))
    
    res.status(200).json("Rooms updated!")
  } catch (error) {
    res.status(500).json(error.message)
  }
}