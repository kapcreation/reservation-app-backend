import jwt from 'jsonwebtoken'

export const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1]

    if (!token) return res.status(401).json("Not authenticated!")

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json("Invalid token!")

      req.user = user
      next()
    })
  } catch (error) {
    res.status(500).json(error.message)
  }
}

export const verifyUser = async (req, res, next) => {
  await verifyToken(req, res, () => {
    if (req.user.id === req.params.id || req.user.isAdmin) {
      next();
    } else {
      res.status(403).json("Unauthorized!")
    }
  });
};

export const verifyAdmin = async (req, res, next) => {
  await verifyToken(req, res, () => {
    if (req.user.isAdmin) {
      next();
    } else {
      res.status(403).json("Unauthorized!")
    }
  });
};