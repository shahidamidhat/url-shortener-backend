const express = require("express");
const app = express();
const cors = require("cors");
const {nanoid} =  require("nanoid");
const mongodb = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require ('dotenv').config();
const URL = process.env.DB;
const DB = "UrlShortening";
const port = 3001;


app.use(cors())
app.use(express.json())



app.post("/register",async function(req,res){
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db(DB);

        
        let isEmailUnique = await db.collection("users").findOne({email : req.body.email})
        if(isEmailUnique) {
            res.status(401).json({
                message: "User Already Exists"
            })
        }
        else{
            //generating salt
            let salt = await bcrypt.genSalt(10)

            //hash the password
            let hash = await bcrypt.hash(req.body.password,salt)
            //storing hash instead of raw password
            req.body.password = hash

            let users = await db.collection("users").insertOne(req.body)
            await connection.close()
            res.json(
                {
                    message: "User Registered"
                }
            )
        }
    }
    catch (error){
        console.log(error)
    }
})

app.post("/login",async function(req,res){
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db(DB);

        //find the username or useremail
        let user = await db.collection("users").findOne({email : req.body.email})
         
        //hashing the password and matching with that of user

        if(user){
            let isPassCorrect = await bcrypt.compare(req.body.password, user.password)
             
            if (isPassCorrect){

                //generating jwt token
                let token = jwt.sign({id : user._id},process.env.SECRET)
                //pass token
                res.json({
                    message:"Allow User",
                    token : token,
                    id : user._id
                })
            }
            else{
                res.status(404).json({
                    message: "Email or Password is Incorrect"
                })
            }
        }
        else{
            res.status(404).json({
                message: "Email or Password is Incorrect"
            })
        }

    }
    catch(error){
        console.log(error)
    }
})

function authenticate(req,res,next){
    //to check presence of token
    if(req.headers.authorization){        
        //check validity of token
        try {
            let jwtValid = jwt.verify(req.headers.authorization,process.env.SECRET)
            if(jwtValid){
                req.userid = jwtValid._id;
                next()
            }
        }
        catch(error){
            res.status(401).json({
                message:"Invalid token"
            })
        }
    }else {
        res.status(401).json({
            message:"No token found"
        })
    }
}

app.get('/shortUrls/:id', authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db(DB);
        let userData = await db.collection('users').findOne({_id : mongodb.ObjectID(req.params.id)});
        res.json(userData);
        await connection.close();
    } catch (error) {
        console.log(error);
    }
})

app.post('/shortUrls/:id', authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db(DB);
        await db.collection('users').updateOne({_id : mongodb.ObjectID(req.params.id)},{$push : {links : {$each : [{longURL : req.body.longURL , shortURL : nanoid(6)}]}}});
        await connection.close();
        res.json({
            message : "Short URL Created"
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/:id', async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db(DB);
        let index = req.params.id.substr(7);
        let short = req.params.id.substr(0,6);
        let response = await db.collection('users').find({"links.shortURL" : short}).toArray();
        res.redirect(response[0].links[index].longURL);
    } catch (error) {
        console.log(error);
    }
})

app.listen(process.env.PORT || port)