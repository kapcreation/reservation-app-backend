import Hotel from '../models/Hotel.js'
import Room from '../models/Room.js'

export const createHotel = async (req, res) => {
  try {
    const newHotel = new Hotel(req.body)
    
    const savedHotel = await newHotel.save()

    res.status(200).json(savedHotel)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const updateHotel = async (req, res) => {
  try {
    const updatedHotel = await Hotel.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true })
    
    res.status(200).json(updatedHotel)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const deleteHotel = async (req, res) => {
  try {
    await Hotel.findByIdAndDelete(req.params.id)
    
    res.status(200).json("Hotel has been deleted.")
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const getHotel = async (req, res) => {
  try {
    const hotel = await Hotel.findById(req.params.id)
    
    res.status(200).json(hotel)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const getHotels = async (req, res) => {
  try {
    const { limit = 25, min = 1, max = 999,  ...query } = req.query
    
    const hotels = await Hotel.find({ 
      cheapestPrice: { $gte: min, $lte: max}, 
      ...query 
    }).limit(limit)
    
    res.status(200).json(hotels)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const getRooms = async (req, res) => {
  try {
    const rooms = await Room.find({ hotelId: req.params.hotelId })

    res.status(200).json(rooms)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const countHotelByCity = async (req, res) => {
  try {
    const cities = req.query.cities.split(",")
    const list = await Promise.all(cities.map(city=>{
      return Hotel.countDocuments({city: city})
    }))
    
    res.status(200).json(list)
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const countHotelByType = async (req, res) => {
  try {
    const hotelCount = await Hotel.countDocuments({ type: "Hotel" })
    const apartmentCount = await Hotel.countDocuments({ type: "Apartment" })
    const resortCount = await Hotel.countDocuments({ type: "Resort" })
    const villaCount = await Hotel.countDocuments({ type: "villa" })
   
    const list = [
      { type: "Hotel", count: hotelCount },
      { type: "Apartment", count: apartmentCount },
      { type: "Resort", count: resortCount },
      { type: "Villa", count: villaCount },
    ]
    
    res.status(200).json(list)
  } catch (error) {
    res.status(500).json(error.message)
  }
}