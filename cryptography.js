const { generateKeyPairSync, publicEncrypt, privateDecrypt } = require('crypto');

//generate a key pair RSA type encryption with a .pem format
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
  }
});

// print out the generated keys
console.log(`PublicKey: ${publicKey}`);
console.log(`PrivateKey: ${privateKey}`);

//message to be encrypted
var toEncrypt = "my secret text to be encrypted";
var encryptBuffer = Buffer.from(toEncrypt);

//encrypt using public key
var encrypted = publicEncrypt(publicKey,encryptBuffer);

//print out the text and cyphertext
console.log("Text to be encrypted:");
console.log(toEncrypt);
console.log("cipherText:");
console.log(encrypted.toString());

//decrypt the cyphertext using the private key
var decryptBuffer = Buffer.from(encrypted.toString("base64"), "base64");
var decrypted = privateDecrypt(privateKey,decryptBuffer);

//print out the decrypted text
console.log("decripted Text:");
console.log(decrypted.toString());

/* const crypto = require('crypto');
const fs = require('fs');

class Cryptography {
  constructor() {
    this.privateKey = fs.readFileSync('./cert/private.pem');
    this.publicKey = fs.readFileSync('./cert/public.pem');
  }

  encrypt(plainText) {
    const plainTextBuffer = Buffer.from(plainText);
    const cipherBuffer = crypto.publicEncrypt(this.publicKey, plainTextBuffer);
    const cipher = cipherBuffer.toString();
    return cipher;
  }

  decrypt(cipher) {
    const cipherBuffer = Buffer.from(cipher.toString('base64'), 'base64');
    const plainTextBuffer = crypto.privateDecrypt(this.privateKey, cipherBuffer);
    const plainText = plainTextBuffer.toString();
    return plainText;
  }

}

const instance = new Cryptography();

const cipher = instance.encrypt('hello dog');

console.log(cipher);

const plainText = instance.decrypt(cipher);

console.log(plainText); */