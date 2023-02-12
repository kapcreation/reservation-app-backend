import express from "express";
import { createRoom, updateRoom, deleteRoom, getRoom, getRooms, setAvailable } from "../controllers/room.js";
import { verifyAdmin } from "../utils/verifyToken.js";

const router = express.Router()

router.post('/', verifyAdmin, createRoom)
router.put('/:id', verifyAdmin, updateRoom)
router.delete('/:id', verifyAdmin, deleteRoom)
router.get('/:id', getRoom)
router.get('/', getRooms)
router.put('/roomNumbers/setAvailable', setAvailable)

export default router