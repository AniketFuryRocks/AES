var lse = require('./LSEncryption');
var aes = require("aes-js");
var express = require('express');
var bodyParser = require('body-parser');
var app = express();

app.use(bodyParser.urlencoded({ extended: false }));
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

//post
app.post('/decrypt', function (req, res) {
    let key = lse.getKey(req.body.password, req.body.salt, req.body['key-length']);
    //convert text to bytes
    if (req.body['text-format'] == "hex")
        req.body.text = aes.utils.hex.toBytes(req.body.text);
    else
        req.body.text = aes.utils.utf8.toBytes(req.body.text);
    let decrypt = lse.decrypt(key, req.body.text);
    res.send("HEX : " + aes.utils.hex.fromBytes(decrypt) + "<br>TEXT : " + lse.decToText(decrypt) + "<br>BYTES : " + decrypt);
})

app.post('/encrypt', function (req, res) {
    let key = lse.getKey(req.body.password, req.body.salt, req.body['key-length']);
    //convert text to bytes
    if (req.body['text-format'] == "hex")
        req.body.text = aes.utils.hex.toBytes(req.body.text);
    else
        req.body.text = aes.utils.utf8.toBytes(req.body.text);
    let encrypt = lse.encrypt(key, req.body.text);
    res.send("HEX : " + aes.utils.hex.fromBytes(encrypt) + "<br>TEXT : " + lse.decToText(encrypt) + "<br>BYTES : " + encrypt);
})