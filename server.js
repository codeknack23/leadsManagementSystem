import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

dotenv.config();
const app = express();

let prisma;
if (process.env.NODE_ENV === "production") {
  prisma = new PrismaClient();
} else {
  if (!global.prisma) {
    global.prisma = new PrismaClient();
  }
  prisma = global.prisma;
}

app.use(cors());
app.use(express.json());


function authMiddleware(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "No token" });
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}


app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({ data: { email, password: hashed } });
    res.json(user);
  } catch (e) {
    res.status(400).json({ error: "User exists" });
  }
});


app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/api/leads", authMiddleware, async (req, res) => {
  const page = parseInt(req.query.page) || 1;     
  const limit = parseInt(req.query.limit) || 5;    
  const skip = (page - 1) * limit;

  try {
    const total = await prisma.lead.count();
    const leads = await prisma.lead.findMany({
      skip,
      take: limit,
      orderBy: { id: "asc" },
    });
    res.json({
      data: leads,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});



app.post("/api/leads", authMiddleware, async (req, res) => {
  const { name, email, phone, status } = req.body;
  const lead = await prisma.lead.create({ data: { name, email, phone, status } });
  res.json(lead);
});


app.put("/api/leads/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, email, phone, status } = req.body;
  try {
    const updatedLead = await prisma.lead.update({
      where: { id: Number(id) },
      data: { name, email, phone, status },
    });
    res.json(updatedLead);
  } catch (err) {
    res.status(400).json({ error: "Lead not found" });
  }
});


app.delete("/api/leads/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.lead.delete({ where: { id: Number(id) } });
    res.json({ message: "Lead deleted" });
  } catch (err) {
    res.status(400).json({ error: "Lead not found" });
  }
});



app.get("/ping", (req, res) => {
  res.send("pong");
});


const keepAlive = async () => {
  try {
    await axios.get(`https://your-app-name.onrender.com/ping`);
    console.log("Pinged self to stay awake!");
  } catch (err) {
    console.error("Failed to ping self:", err.message);
  }
};


setInterval(keepAlive, 60 * 1000);


keepAlive();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
