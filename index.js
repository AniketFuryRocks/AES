var lse = require('./LSEncryption');
var aes = require("aes-js");
var { base64decode, base64encode } = require("nodejs-base64")

//express js
var express = require('express');
var bodyParser = require('body-parser');
var app = express();

//req body parser
app.use(bodyParser.urlencoded({ extended: false }));

//static routing
var assets = __dirname + "/assets";

app.get('/', function (req, res) {
    res.sendFile(assets + "/index.html");
})
app.get('/decrypt', function (req, res) {
    res.sendFile(assets + "/decrypt.html");
})
app.get('/encrypt', function (req, res) {
    res.sendFile(assets + "/encrypt.html");
})
var server = app.listen(8081, function () {
    var port = server.address().port
    console.log("AES Server listening at http://localhost:%s", port)
})

//route /decrypt POST Method
app.post('/decrypt', function (req, res) {
    let key = req.body["key-from"]=="key"?req.body.key:lse.getKey(req.body.password, req.body.salt, req.body['key-length']);
    key = aes.utils.utf8.toBytes(key);
    //convert text to bytes
    req.body.text = convertToBytes(req.body.text,req.body['text-format']);//reuse req.body.text variable
    res.send(toString(lse.decrypt(key, req.body.text)));//decrypt text using key and pass it to toString() which gives a meaning full return (JSON)
})

// route /encrypt POST Method
app.post('/encrypt', function (req, res) {
    let key = req.body["key-from"]=="key"?req.body.key:lse.getKey(req.body.password, req.body.salt, req.body['key-length']);
    key = aes.utils.utf8.toBytes(key);
    //convert text to bytes
    req.body.text = convertToBytes(req.body.text,req.body['text-format'])
    res.send(toString(lse.encrypt(key, req.body.text)));//decrypt text using key and pass it to toString() which gives a meaning full return (JSON)
})

function convertToBytes(text, format) {
    if (format == 'base64')//BASE64
        return Buffer.from(text,'base64');
    else if (format == "hex")//BASE16
        return aes.utils.hex.toBytes(text);
    else//Assuming it to be utf8
        return aes.utils.utf8.toBytes(text);
}

function toString(bytes) {
    let utf_8 = aes.utils.utf8.fromBytes(bytes);
    return JSON.stringify({
        HEX : aes.utils.hex.fromBytes(bytes),
        'UTF-8' : utf_8,
        BASE64 : Buffer.from(bytes).toString('base64')
    })
}