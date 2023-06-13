import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
//jwt for privacy and security of data
import jwt from "jsonwebtoken";
//for hashing password in database
//for security purpose
import bcrypt from "bcrypt";

//to connect mongodb from nodejs
//new connection
mongoose.connect("mongodb://127.0.0.1:27017",{
    dbName: "backend",
})
.then(()=>console.log('database connected')) //callback func(if database connected this will call)
.catch((e)=>console.log(e)); //if error occurs this will be called

//Set-up Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
})
//set-up model/collection
const User = mongoose.model("User", userSchema);

//creating server using express.js
const app =express();


//Using middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

//setting up view engine
app.set("view engine","ejs")

const isAuthanticated = async(req,res,next) => {
    //req.cookies help to access the cookies stored
    const { token } = req.cookies;

    if(token){

        //decoding the secret code
        const decoded = jwt.verify(token, "code");
        //console.log(decode)

        req.user = await User.findById(decoded._id);

        //next() helps jump to next handler
        next();
    }else{
        res.redirect("/login") 
    }
}

//here next() in isAuthanticated will jump to next handler (i.e res.render("logout"))
app.get("/", isAuthanticated, (req,res)=>{
    res.render("logout" ,{name:req.user.name}
    );
})

app.get("/login",(req,res)=>{
    res.render("login");
})

app.get("/register",(req,res)=>{
    res.render("register");
})

app.post("/login",async (req,res)=>{

    const { email, password}=req.body;
    let user= await User.findOne({email});

    if(!user) return res.redirect("/register");

    // const isMatch = user.password===password;
    // first hash then match(compare)
    const isMatch = await bcrypt.compare(password,user.password);

    if(!isMatch) return res.render("login",{email, message:"Incorrect Password!"})

    const token = jwt.sign({_id: user._id},"code")

    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now() + 60*1000),
        
    })
    res.redirect("/");
})

app.post("/register",async (req,res)=>{
    //destructuring req.body
    const { name, email, password }= req.body;

    //to find user is already logged in??
    let user=await User.findOne({email});
    if(user){
        return res.redirect("/login");
    }

    //hashing password before storing to database
    //hashedPassword is stored in database
    const hashedPassword = await bcrypt.hash(password,10);

    //storing data in database
        user = await User.create({
        name,
        email,
        password: hashedPassword,
    })

    //jwt
    const token = jwt.sign({_id: user._id},"code")

    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now() + 60*1000),
        
    })
    res.redirect("/");
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly:true,
        expires:new Date(Date.now()),
    })
    res.redirect("/");
})






//listening to server
app.listen(5000,()=>{
    console.log('server is working')
})

