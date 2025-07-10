const express = require("express")
const {open} = require("sqlite")
const sqlite3 = require("sqlite3")
const path = require("path")
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
const cors = require('cors');
app.use(cors());
app.use(express.json())

let dbPath = path.join(__dirname, "userDetails.db")
let db = null

const initializeDbAndServer = async () => {
    try {
        db = await open(
            {
                filename: dbPath,
                driver: sqlite3.Database
            }
        )
        app.listen(8000, () => {
            console.log("server running at port 8000")
        })
    } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(-1)
  }
}
initializeDbAndServer()

app.post("/register", async (req, res) => {
    const {username, email, password} = req.body
    const hashedPassword = await bcrypt.hash(password, 10)
    const searchUserQuery = `
    SELECT * FROM user WHERE username = '${username}'
    `
    const dbUser = await db.get(searchUserQuery)
    if (dbUser === undefined){
        const newUserQuery = `
        INSERT INTO 
        user(username, email, password)
        VALUES (
         '${username}',
         '${email}',
         '${hashedPassword}'
        );
        `
        await db.run(newUserQuery)
        res.status(200).json(`User created successfully`)
    } else {
        res.status(400).json("User already exists")
    }
})

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const searchUserQuery = `SELECT * FROM user WHERE username = ?`;
    const dbUser = await db.get(searchUserQuery, [username]);

    if (!dbUser) {
      return res.status(400).json({ error: "User not found" });
    }

    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordMatched) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
    res.json({ jwtToken });

  } catch (e) {
    console.error("Login handler error:", e);
    res.status(500).json({ error: "Internal server error" });
  }
});


const authenticateToken = (req, res, next) => {
  let jwtToken
  const authHeader = req.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }
  if (jwtToken === undefined) {
    res.status(401)
    res.json('Invalid JWT Token')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        res.status(401)
        res.json('Invalid JWT Token')
      } else {
        req.username = payload.username
        next()
      }
    })
  }
}