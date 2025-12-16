import express from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import { randomUUID } from "crypto";
import { JsonDB, Config } from "node-json-db";

const app = express();
app.use(express.json());
app.use(cors());

const db = new JsonDB(new Config("./src/users.json", true, false, "/"));

var usersGet = await db.getData("/");

function loadUsers() {
  return usersGet;
}

// var usersPush = await db.push("/", users)

function saveUsers(users) {
    db.push("/", users);
}


app.post("/api/sign-up", async (req, res) => {
  const { email, password, first_name, last_name, role } = req.body;
  const users = loadUsers();

  if (users.find((u) => u.email === email))
    return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 8);
  const newUser = {
    _id: randomUUID(),
    email,
    password: hashed,
    first_name,
    last_name,
    role,
  };

  users.push(newUser);
  saveUsers(users);

  const { password: _, ...userWithoutPass } = newUser;
  res.json({ userWithoutPass });
});

app.post("/api/sign-in", async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user = users.find((u) => u.email === email);

  if (!user) return res.status(401).json({ error: "Invalid credentials user not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials password is incorrect" });

  res.json({id: user._id, role: user.role});
});

app.get("/api/users", (req, res) => {
  const users = loadUsers().map(({ password, ...u }) => u);
  res.json(users);
});

app.get("/api/users/:id", (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => u._id === req.params.id);

  if (!user) return res.status(404).json({ error: "User not found" });

  const { password: _, ...userWithoutPass } = user;
  res.json(userWithoutPass);
});

app.put("/api/users/:id", (req, res) => {
  const {newrole} = req.body;
  const users = loadUsers();
  const user = users.find((u) => u._id === req.params.id)

  if (!user) return res.status(404).json({ error: "user not found"});
  user.role = newrole; 

  saveUsers(users)

  res.json(user.role)
})

app.put("/api/editusers/:id", (req, res) => {
  const updatedUser = req.body; 
  const users = loadUsers();
  const index = users.findIndex((u) => String(u._id) === req.params.id);

  if (index === -1) {
    return res.status(404).json({ error: "user not found" });
  }

  users[index] = {
    ...users[index],
    ...updatedUser,
  };

  saveUsers(users);

  res.json({ message: "updated successfully" });
});

export default app;