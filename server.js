const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = 3000;

// ================= DATABASE =================

const db = new sqlite3.Database("./database.db", (err) => {
    if (err) {
        console.log("Database error:", err.message);
    } else {
        console.log("Database connected");
    }
});

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`, (err) => {
    if (err) {
        console.log("Table error:", err.message);
    } else {
        console.log("Users table ready");
    }
});


// ================= MIDDLEWARE =================

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "document-assistant-secret",
    resave: false,
    saveUninitialized: false
}));


// ================= HOME =================

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "views/home.html"));
});


// ================= LOGIN PAGE =================

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "views/login.html"));
});


// ================= REGISTER PAGE =================

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "views/register.html"));
});


// ================= REGISTER =================

app.post("/register", async (req, res) => {

    const { name, email, password } = req.body;

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword],
            function(err) {

                if (err) {
                    return res.send("Email already registered.");
                }

                res.redirect("/login");
            }
        );

    } catch (error) {
        res.send("Registration error.");
    }
});


// ================= LOGIN =================

app.post("/login", (req, res) => {

    const { email, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, user) => {

            if (err || !user) {
                return res.send("Invalid email or password.");
            }

            const match = await bcrypt.compare(
                password,
                user.password
            );

            if (!match) {
                return res.send("Invalid email or password.");
            }

            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email
            };

            res.redirect("/dashboard");
        }
    );
});


// ================= DASHBOARD =================

app.get("/dashboard", (req, res) => {

    if (!req.session.user) {
        return res.redirect("/login");
    }

    res.sendFile(
        path.join(__dirname, "views/dashboard.html")
    );
});


// ================= LOGOUT =================

app.get("/logout", (req, res) => {

    req.session.destroy(() => {
        res.redirect("/");
    });

});


// ================= START =================

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

