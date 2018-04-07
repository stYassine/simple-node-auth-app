const mongoose =require('mongoose');
const bcrypt =require('bcrypt');
const jwt =require('jsonwebtoken');
const SECRET ='supersecret';


const userSchema =new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: 1,
        trim: true
    },
    password: {
        type: String,
        required: true,
        minlength: 3
    },
    token: {
        type: String
    }
});

/// hash password
userSchema.pre('save', function(next){

    let user =this;

    if(user.isModified('password')){

        bcrypt.genSalt(10, (err, salt) => {
            if(err) return next(err);
            bcrypt.hash(user.password, salt, (err, hashedPass) => {
                if(err) return next(err);
                user.password =hashedPass;
                next();
            });
        });

    }else{
        next();
    }

});


/// generate token
userSchema.methods.generateToken =function(callback){

    let user =this;
    let token =jwt.sign({ data: user._id }, SECRET);
    user.token =token;

    user.save((err, user) => {
        if(err) return callback(err);
        return callback(null, user);
    });

}

/// remove token (LOGOUT)
userSchema.methods.removeToken =function(callback){

    let user =this;
    user.update({ $unset: { token:1 } }, (err, user) => {
        if(err) return callback(err);
        return callback(null, user);
    });

}



/// find user by token
userSchema.statics.findUserByToken =function(token, callback){

    let user =this;

    jwt.verify(token, SECRET, (err, decode) => {
        if(err) return callback(err);
        user.findOne({ '_id': decode.data }, (err, user) => {
            if(err) return callback(err);
            return callback(null, user);
        });
    });


}



const User =mongoose.model('users', userSchema);

module.exports ={
    User: User
};