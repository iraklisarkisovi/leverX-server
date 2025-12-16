import express from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import { randomUUID } from "crypto";
import { JsonDB, Config } from "node-json-db";

const app = express();
app.use(express.json());
app.use(cors());

const db = new JsonDB(new Config("./src/users.json", true, false, "/"));
let usersCache = [];  

async function loadUsers() {
  try {
    usersCache = await db.getData("/");
    return usersCache;
  } catch (error) {
    if (error.id === "/" && error.name === "DataError") {
      return [];
    }
    console.error("Error loading users from DB:", error);
    return [];
  }
}

function saveUsers(users) {
  db.push("/", users);
  usersCache = users;  
}


app.post("/api/sign-up", async (req, res) => {
  const { email, password, first_name, last_name, role } = req.body;
  const users = await loadUsers();  

  if (!email || !password || !first_name) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  if (users.find((u) => u.email === email))
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 8);
  const newUser = {
    _id: randomUUID(),
    email,
    password: hashed,
    first_name,
    last_name,
    role: role || "user",  
  };

  const newUsers = [...users, newUser];  
  saveUsers(newUsers);

  const { password: _, ...userWithoutPass } = newUser;
  res.json({ userWithoutPass });
});

app.post("/api/sign-in", async (req, res) => {
  const { email, password } = req.body;
  const users = await loadUsers();
  const user = users.find((u) => u.email === email);

  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

  res.json({ id: user._id, role: user.role });
});

app.get("/api/users", async (req, res) => {
  const users = await loadUsers();
  const safeUsers = users.map(({ password, ...u }) => u);
  res.json(safeUsers);
});

app.get("/api/users/:id", async (req, res) => {
  const users = await loadUsers();
  const user = users.find((u) => u._id === req.params.id);

  if (!user) return res.status(404).json({ error: "User not found" });

  const { password: _, ...userWithoutPass } = user;
  res.json(userWithoutPass);
});

app.put("/api/users/:id", async (req, res) => {
  const { newrole } = req.body;
  const users = await loadUsers();
  const index = users.findIndex((u) => u._id === req.params.id);

  if (index === -1) return res.status(404).json({ error: "User not found" });

  const newUsers = [...users];
  newUsers[index] = { ...newUsers[index], role: newrole };

  saveUsers(newUsers);

  res.json({ role: newrole });  
});

app.put("/api/editusers/:id", async (req, res) => {
  const updatedUser = req.body;
  const users = await loadUsers();
  const index = users.findIndex((u) => u._id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: "User not found" });
  }

  const newUsers = [...users];
  newUsers[index] = {
    ...newUsers[index],
    ...updatedUser,
  };

  saveUsers(newUsers);

  res.json({ message: "Updated successfully" });
});

export default app;  
