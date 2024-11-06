const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require("dotenv").config();
const session = require('express-session'); 
const mongodbSession = require('connect-mongodb-session')(session); 

// File imports
const { userDataValidation, isEmailValidator } = require("./utils/authutils");
const userModel = require("./models/userModel");

// Constants
const app = express();
const PORT = process.env.PORT || 8000;
// Set up session store
const store = new mongodbSession({
    uri: process.env.MONGO_URL, 
    collection: "sessions"
});

// Middleware
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true })); 
app.use(express.json());
app.use(session({
    secret: process.env.SECRET_KEY, 
    store: store,
    // resave prevents saving the session to the database if nothing has changed in the session.
    resave: false,        
    // This avoids creating a new, empty session in the database for every user who visits your site without logging in                  
    saveUninitialized: false 
}));
function isAuth(req, res, next) {
    if (req.session && req.session.isAuth) {
        return next(); 
    } else {
        return res.status(401).send("Unauthorized"); 
    }
}

//db connection
mongoose
    .connect(process.env.MONGO_URL)
    .then(() => {
        console.log("mongodb connected successfully");
    })
    .catch((err) => {
        console.log("Error connecting to MongoDB:", err);
    });

//api
app.get('/', (req, res) => {
    return res.send("ramram");
});
app.get('/test', (req, res) => {
    return res.render("test");
});
app.get('/register', (req, res) => {
    return res.render("registerPage");
});

app.post('/register', async (req, res) => {
    console.log(req.body);
    const {name, email, username, password} = req.body;

    // Data validation
    try {
        await userDataValidation({name, email, username, password});
    } catch (error) {
        return res.status(400).json({error: error.message});
    }

// Hashing of password
    const hashedPassword = await bcrypt.hash(
        password,
        parseInt(process.env.SALT)
    );
    // console.log("Hashed Password:", hashedPassword);

// find the user if exist with email and username
const userEmailExit = await userModel.findOne({email});
if(userEmailExit){
    return res.send({
        status: 400,
        message: "Email already exist"
    })
}
const userUsernameExit = await userModel.findOne({username});
if(userUsernameExit){
    return res.send({
        status: 400,
        message: "Username already exist"
    })
}

// Store data in DB
    const userObj = new userModel({
        name: name,
        email: email,
        username: username,
        password: hashedPassword
    });

    try {
        const userDb = await userObj.save();
        console.log("User saved:", userDb);
        return res.render("loginPage")
        // return res.status(201).json({
        //     status: 201,
        //     message: "Register successful",
        //     data: {
        //         name: userDb.name,
        //         email: userDb.email,
        //         username: userDb.username,
        //         password: userDb.password, // hashed password
        //         _id: userDb._id
        //     }
        // });
        
    } catch (error) {
        return res.status(500).json({
            error: error.message,
            message: "Internal server error",
            status: 500
        });
    }
});

app.get('/login', (req, res) => {
    return res.render("loginPage");
});
app.post('/login-user',async(req,res)=>{
    const {loginId, password} = req.body;
    if(!loginId || !password)
        return res.status(400).json("missing login credentials")

    try {
// find the user with loginId
    let userDb;
    if(isEmailValidator({str : loginId})){
        userDb = await userModel.findOne({email : loginId})
        // console.log("email")
    }else{
        userDb = await userModel.findOne({username : loginId})
    }
    if(!userDb)
        return res.status(400).json("username not found , Please register first")
    // console.log(req.body);



// compare the password
    // console.log(password, userDb.password)
// bcrypt password compare
    const isMatched = await bcrypt.compare(password, userDb.password)
    if(!isMatched){
        return res.status(400).json("password is incorrect")
    }
// session base auth
req.session.isAuth = true
req.session.user = {
    userId: userDb._id,
    email: userDb.email,
    username: userDb.username
}  
    return res.render("dashboardPage")
    } catch (error) {
        return res.status(500).json("internal server error")
    }
})

// protected API
app.get("/dashboard", isAuth, (req,res)=>{
    return res.render("dashboardPage")
});

// logout user
app.post("/logout",(req,res)=>{
    req.session.destroy((err)=>{
        if(err) return res.status(500).json("error");
        
    // successfully logout
    return res.redirect("login")
    })
})

app.listen(PORT, () => {
    console.log(`Server is running at: http://localhost:${PORT}`);
});
