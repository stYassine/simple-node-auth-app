const express =require('express');
const bodyParser =require('body-parser');
const mongoose =require('mongoose');
const bcrypt =require('bcrypt');
const app =express();
const PORT =process.env.PORT || 8080;


//////////////////////////////////
/// Connect To Database
//////////////////////////////////
mongoose.Promise =global.Promise;
mongoose.connect('mongodb://127.0.0.1:27017/auth');



//////////////////////////////////
/// Middleware
//////////////////////////////////
app.use(bodyParser.json());

/// check if there is a token passed with the header
/// and find the user by token
const authMiddleware =(request, response, next) => {

    const token =request.header('x-token');

    User.findUserByToken(token, (err, user) => {
        if(err) return response.status(400).send(err);
        if(!user) return response.status(400).send({msg: 'Token Not Valid'});

        user.generateToken((err, user) => {
            if(err) return response.status(400).send(err);
            request.user =user;
            request.token =token;
            next();
        });

    });

}





//////////////////////////////////
/// Models
//////////////////////////////////
const { User } =require('./models/User');



//////////////////////////////////
/// Routes
//////////////////////////////////

const users =express.Router();


/// get users
users.get('/', authMiddleware, (request, response) => {
    
    User.find((err, users) => {
        if(err) return response.status(400).send(err);
        return response.status(200).json(users);
    });

});


/// register users
users.post('/register', (request, response) => {
    
    const user =new User({
        email: request.body.email,
        password: request.body.password
    });

    user.save((err, user) => {
        if(err) return response.status(400).send(err);

        /// generate new token
        user.generateToken((err, user) => {
            if(err) return response.status(400).send(err);
            return response.status(200).json(user);
        });

    });


});


/// login users
users.post('/login', (request, response) => {
    
    /// check if email exists
    User.findOne({ 'email': request.body.email }, (err, user) => {
        if(err) return response.status(400).send(err);
        if(!user) return response.status(400).send({'msg': 'Email Is Incorrect'});

        /// compare password
        bcrypt.compare(user.password, request.body.password, (err, isMatched) => {
            if(err) return response.status(400).send(err);

            /// generate new token every time the user login
            user.generateToken((err, user) => {
                if(err) return response.status(400).send(err);
                return response.status(200).json(user);
            });

        });

    });

});


/// logout users
users.delete('/logout', authMiddleware, (request, response) => {
    
    /// remove user token
    request.user.removeToken((err, data) => {
        if(err) return response.status(400).send(err);
        return response.status(200).json(data);
    });

});


app.use('/users', users);



//////////////////////////////////
/// Listen
//////////////////////////////////
app.listen(PORT, (err) => {
    if(err){
        console.log(err);
    }
        console.log(`Your Server Is Running On Port ${PORT}`);
});