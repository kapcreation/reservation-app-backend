import express from "express";
import { updateUser, deleteUser, getUser, getUsers } from "../controllers/user.js";
import { verifyUser, verifyAdmin } from "../utils/verifyToken.js";

const router = express.Router()

router.get('/checkowner/:id', verifyUser, (req, res) => {
  res.send(`${req.user.id} authenticated.`)
})

router.put('/:id', verifyUser, updateUser)
router.delete('/:id', verifyUser, deleteUser)
router.get('/:id', verifyUser, getUser)
router.get('/', verifyAdmin, getUsers)

export default router