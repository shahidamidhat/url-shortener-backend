const cors = require('cors');
const express = require('express')
const { nanoid } = require('nanoid')
const mongodb = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();
const port = 3001;
const URL = process.env.DB;
const DB = 'urls';

app.use(cors());
app.use(express.json());

app.post('/register', async(req, res) => {
    try {
        let connection = await mongodb.connect(URL, {useUnifiedTopology : true});
        let db = connection.db(DB);
        let salt = await bcrypt.genSalt(10)
        let hash = await bcrypt.hash(req.body.password, salt);
        req.body.password = hash;
        await db.collection('users').insertOne(req.body)
        res.json({
            message : 'User Registered'
        })
    } catch (error) {
        console.log(error);
    }
})

app.post('/login', async (req, res) => {
    try {
        let connection = await mongodb.connect(URL,{useUnifiedTopology : true});
        let db = connection.db(DB);
        let user = await db.collection('users').findOne({email : req.body.email})
        if(user){
            let isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
            if(isPasswordCorrect){
                let token = jwt.sign({_id : user._id}, process.env.SECRET);
                res.json({
                    message : "Allow",
                    token : token,
                    id : user._id
                })
            }
            else{
                res.json({
                    message : "Email or Password is incorrect"
                })
            }
        }
        else{
            res.json({
                message : "Email or Password is incorrect"
            })
        }
    } catch (error) {
        console.log(error);
    }
})

function authenticate(req, res, next){
    if(req.headers.authorization){
        try {
            let jwtValid = jwt.verify(req.headers.authorization, process.env.SECRET)
            if(jwtValid){
                req.userID = jwtValid._id;
                next();
            }
        } catch (error) {
            res.status(401).json({
                message : "Invalid Token"
            })
        }
    }
    else{
        res.status(401).json({
            message : "No Token Present"
        })
    }
}

app.get('/urls/:id', authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL, {useUnifiedTopology : true});
        let db = connection.db(DB);
        let userData = await db.collection('users').findOne({_id : mongodb.ObjectID(req.params.id)});
        res.json(userData);
        await connection.close();
    } catch (error) {
        console.log(error);
    }
})

app.post('/urls/:id', authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL, {useUnifiedTopology : true});
        let db = connection.db(DB);
        await db.collection('users').updateOne({_id : mongodb.ObjectID(req.params.id)},{$push : {links : {$each : [{longURL : req.body.longURL , shortURL : nanoid(6)}]}}});
        await connection.close();
        res.json({
            message : "URL Created"
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/:id', async (req, res) => {
    try {
        let connection = await mongodb.connect(URL, {useUnifiedTopology : true});
        let db = connection.db(DB);
        let index = req.params.id.substr(7);
        let short = req.params.id.substr(0,6);
        let response = await db.collection('users').find({"links.shortURL" : short}).toArray();
        res.redirect(response[0].links[index].longURL);
    } catch (error) {
        console.log(error);
    }
})

app.listen(process.env.PORT || port);
