var aesjs = require('aes-js');
var pbkdf2 = require('pbkdf2');

//for CBC iv must be 16 bytes
exports.iv = [ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,35, 36 ];

//encrypt
exports.encrypt = function encrypt(key,decBytes) {
    var aesCbc = new aesjs.ModeOfOperation.cbc(key,this.iv);
    return aesCbc.encrypt(decBytes);
}

//pass encrypted bytes
//cbc needs to initialized again
exports.decrypt = (key,encBytes) => new aesjs.ModeOfOperation.cbc(key,this.iv).decrypt(encBytes);

//convert Decrypted Bytes to Text
exports.decToText = aesjs.utils.utf8.fromBytes;

//generate key using salt and password
//hash function = sha1
exports.getKey = function getKey(password,salt,size) {
    if(!(size == 128 || size == 192 || size == 256))
        throw "Invalid size(128 , 192 ,256 bits)";
    return pbkdf2.pbkdf2Sync(password, salt, 1000, size / 8, 'sha1');
}