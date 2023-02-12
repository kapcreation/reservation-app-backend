import express from "express";
import { createHotel, updateHotel, deleteHotel, getHotel, getHotels, countHotelByCity, countHotelByType, getRooms } from "../controllers/hotel.js";
import { verifyAdmin } from "../utils/verifyToken.js";

const router = express.Router()

router.post('/', verifyAdmin, createHotel)
router.put('/:id', verifyAdmin, updateHotel)
router.delete('/:id', verifyAdmin, deleteHotel)
router.get('/:id', getHotel)
router.get('/', getHotels)
router.get('/:hotelId/rooms', getRooms)

router.get('/count/city', countHotelByCity)
router.get('/count/type', countHotelByType)
// router.get('/countByType', )

export default router