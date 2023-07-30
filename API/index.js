const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")
const dotenv = require("dotenv")
app.use(express.json())
dotenv.config()

const users = [
    {
        id:1,
        username : "Inish",
        password : "tn72bw0600",
        isAdmin : true,
    },
    {
        id:2,
        username : "Dhanush",
        password : "tn72bv9099",
        isAdmin : false,
    }
]

const refreshtoken = []

app.post("/api/refresh",(req,res)=>{
    const refreshToken = req.body.token

    if(!refreshToken){
        return res.status(500).json("Refresh Token Not Available")
    }

    if(!refreshtoken.includes(refreshToken)){
        res.status(403).json("Refers Token Not Available")
    }
    jwt.verify(refreshToken,process.env.REF_PASS_SEC,(err,user)=>{
        err && console.log(err)

        refreshtoken = refreshtoken.filter(token=>{
            token !== refreshToken
        })

        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user)

        refreshtoken.push(newRefreshToken)

        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken : refreshToken
        })
    })
})

const generateAccessToken = (user)=>{
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.PASS_SEC, {
      expiresIn: "15m",
    });
}

const generateRefreshToken = (user)=>{
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, process.env.REF_PASS_SEC);
}

app.post("/api/login",(req,res)=>{
    const { username, password } = req.body
    const user = users.find((u)=>{
        return u.username === username && u.password === password
    })
    if(user){
        //Generate Access token
        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)

        refreshtoken.push(refreshToken);

        res.json({
            username: user.username,
            isAdmin : user.isAdmin,
            accessToken : accessToken,
            refreshToken : refreshToken
        })
    }
    else{
        res.status(400).json("User Not Found")
    }
})

const verify = (req,res,next)=>{
    const authHeader = req.headers.token
    if(authHeader){
        const token = authHeader.split(" ")[1]
        jwt.verify(token, process.env.PASS_SEC , (err, user) => {
          if (err) {
            res.status(403).json("Token not valid");
          } else {
            req.user = user;
            next();
          }
        });
    }
    else{
        res.status(400).json("Token Not Found")
    }
}

app.delete("/api/users/:userId",verify,(req,res)=>{
    if (req.user.id == req.params.userId || req.user.isAdmin) {
      res.status(200).json("Post is Deleted");
    } else {
      res.status(403).json("You are not allowed");
    }
})

app.post("/api/logout",verify,(req,res)=>{
    const refreshToken = req.body.token
    refreshtoken.filter(token => {
        token !== refreshToken
    })
    res.status(200).json("You Logged Out Successfully")
})

app.listen(5000,()=>{
    console.log("Backend is Running")
})