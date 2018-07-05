//require express
var express = require('express');
var session = require('express-session');
var fs = require('fs');

var bodyParser = require('body-parser');


var bcrypt = require('bcrypt');
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);

//khởi tạo express
var app = express();
app.set('view engine', 'pug')
app.set('trust proxy', 1) // trust first proxy
app.use(session({ secret: 'XuanNghia', cookie: { maxAge: 60000 }}))

app.use(express.static('public'));
app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies


function check(email, password) {
    var list_user = JSON.parse(fs.readFileSync('./users.json'));
    var has_user = false;
    var correct_password = false;
    for(let i = 0; i < list_user.length; i++) {
        if(email == list_user[i].email) {
            has_user = true;
            correct_password = bcrypt.compareSync(password, list_user[i].pass);
            var response = {
                has_user: has_user,
                correct_password: correct_password,
                email: email,
            };
            return response;
        }
    }
    var response = {has_user: has_user, correct_password: correct_password, email: email};
    return response;
}
function save_user(email, pass_encode)
{
    var list_user = JSON.parse(fs.readFileSync('./users.json'));
    list_user.push({email: email, pass: pass_encode});
    fs.writeFileSync('./users.json', JSON.stringify(list_user));
    return true;
}
function validateEmail(email) {
    var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}
// tạo hành động cho url /
app.get('/', function (req, res) {
    if (req.session.email) {
        res.render('index', { email: req.session.email });
    } else {
        res.redirect('/login');
    }
});
app.get('/login', function (req, res) {
    if (req.session.email) {
        res.redirect('/');
    } else {
        res.render('login', { error: 'Bạn chưa đăng nhập, hãy đăng nhập hoặc đăng ký ngay nhé!'});
    }
});
app.post('/login', function (req, res) {
    var email = req.body.email;
    var pass = req.body.password;
    if(!validateEmail(email)) {
        res.render('login', { error: 'Sai định dạng email!'});
    }
    var ok = check(email, pass);
    if(ok.has_user == false) {
        res.render('login', { error: "Email không tồn tại! Nếu chưa có tài khoản, vui lòng đăng ký!" });
    } else if(ok.correct_password == false) {
        res.render('login', {error: "Sai mật khẩu!"});
    } else {
        req.session.email = ok.email;
        res.redirect('/');
    }
});
app.get('/logout', function (req, res) {
    req.session.destroy(function(err) {
        // cannot access session here
    })
    res.redirect('/login');
});
app.get('/signup', function (req, res) {
    if (req.session.email) {
        res.redirect('/');
    } else {
        res.render('signup');
    }
});
app.post('/signup', function(req, res) {
    var email = req.body.email;
    var pass = req.body.password;
    var pass_confirm = req.body.password_confirm;
    var ok = check(email, pass);
    if(!validateEmail(email)) {
        res.render('signup', { error: 'Sai định dạng email!'});
    }
    else if(pass != pass_confirm) {
        res.render('signup', { error: 'Mật khẩu xác nhận không đúng!'});
    }
    else if(ok.has_user == true) {
        res.render('signup', { error: 'Email này đã tồn tại!'});
    } else {
        var pass_encode = bcrypt.hashSync(pass, salt);
        save_user(email, pass_encode);
        req.session.email = ok.email;
        res.redirect('/');
    }
});
//xét cổng port 8000 cho server
var server = app.listen(80, function(){
    var port = server.address().port;
    console.log("App dang chay: http://localhost:%s", port);
});