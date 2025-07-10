const express = require("express")
const path = require("path")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const Database = require("better-sqlite3")

const app = express()
app.use(cors())
app.use(express.json())

const PORT = process.env.PORT || 8000


const dbPath = path.join(__dirname, "userDetails.db")
const db = new Database(dbPath)


app.listen(PORT, () => {
  console.log(`Server running at port ${PORT}`)
})

app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body
    const hashedPassword = await bcrypt.hash(password, 10)

    const searchUserQuery = `
      SELECT * FROM user WHERE username = ?;
    `
    const dbUser = db.prepare(searchUserQuery).get(username)

    if (dbUser === undefined || dbUser === null) {
      const newUserQuery = `
        INSERT INTO user (username, email, password)
        VALUES (?, ?, ?);
      `
      db.prepare(newUserQuery).run(username, email, hashedPassword)
      res.status(200).json("User created successfully")
    } else {
      res.status(400).json("User already exists")
    }
  } catch (e) {
    console.error("Register Error:", e.message)
    res.status(500).json("Internal server error")
  }
})

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body
    const searchUserQuery = `
      SELECT * FROM user WHERE username = ?;
    `
    const dbUser = db.prepare(searchUserQuery).get(username)

    if (!dbUser) {
      return res.status(400).json({ error: "User not found" })
    }

    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (!isPasswordMatched) {
      return res.status(401).json({ error: "Invalid password" })
    }

    const payload = { username }
    const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN")
    res.json({ jwtToken })
  } catch (e) {
    console.error("Login Error:", e.message)
    res.status(500).json({ error: "Internal server error" })
  }
})

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const jwtToken = authHeader && authHeader.split(" ")[1]

  if (!jwtToken) {
    return res.status(401).json("Invalid JWT Token")
  }

  jwt.verify(jwtToken, "MY_SECRET_TOKEN", (error, payload) => {
    if (error) {
      return res.status(401).json("Invalid JWT Token")
    }
    req.username = payload.username
    next()
  })
}


