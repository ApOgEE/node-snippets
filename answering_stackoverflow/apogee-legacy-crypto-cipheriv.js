// Run : node apogee-legacy-crypto-cipheriv.js
// question: https://stackoverflow.com/questions/68713891/nodejs-recover-createcipher-data-with-createcipheriv
const crypto = require('crypto');
const EVP_BytesToKey = require('evp_bytestokey')
const ALGO = 'aes192';
const password = 'Your_Password_Here';
const IV_SIZE = 16;
const KEY_SIZE = 24;

function encrypt(text) {
    let key = crypto.scryptSync(password, 'salt', KEY_SIZE);
    let iv = crypto.randomBytes(IV_SIZE);
	var cipher = crypto.createCipheriv(ALGO, key, iv);
    var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
	let textParts = text.split(':');
	let iv = Buffer.from(textParts.shift(),'hex');
    let key = crypto.scryptSync(password, 'salt', KEY_SIZE);
    let encryptedText = Buffer.from(textParts[0], 'hex');
	let decipher = crypto.createDecipheriv(ALGO, key, iv);
	let decrypted = decipher.update(encryptedText);
	decrypted = Buffer.concat([decrypted, decipher.final()]);
	return decrypted.toString();
}

function encrypt_old(text) {
	var cipher = crypto.createCipher(ALGO, password);
    var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}

function decrypt_old(text) {
    var decipher = crypto.createDecipher(ALGO, password);
    let decrypted = decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
    return decrypted.toString();
}

function decrypt_legacy_using_IV(text) {
    const result = EVP_BytesToKey(
      password,
      null,
      KEY_SIZE * 8, // byte to bit size
      IV_SIZE
    )

    let decipher = crypto.createDecipheriv(ALGO, result.key, result.iv);
	let decrypted = decipher.update(text, 'hex','utf8') + decipher.final('utf8');
	return decrypted.toString();
}

function encrypt_legacy_using_IV(text) {
    const result = EVP_BytesToKey(
      password,
      null,
      KEY_SIZE * 8, // byte to bit size
      IV_SIZE
    )

    var cipher = crypto.createCipheriv(ALGO, result.key, result.iv);
	var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
	return encrypted.toString();
}

var secret_to_keep = 'This is the secret text';

console.log('== Encrypt using createCipheriv');
let new_ivencrypted = encrypt(secret_to_keep);
console.log(new_ivencrypted);

console.log('== Decrypt using createDecipheriv');
let new_ivdecrypted = decrypt(new_ivencrypted);
console.log(new_ivdecrypted);

console.log('== Encrypt using deprecated createCipher');
let legacy_encrypted = encrypt_old(secret_to_keep);
console.log(legacy_encrypted);

console.log('== Decrypt using deprecated createDecipher');
let legacy_decrypted = decrypt_old(legacy_encrypted);
console.log(legacy_decrypted);

console.log('== encrypted using deprecated createCipher but decrypt using createDecipheriv');
let ivdecrypt_legacy = decrypt_legacy_using_IV(legacy_encrypted);
console.log(ivdecrypt_legacy);

console.log('== encrypted using new createCipheriv but decrypt using createDecipher');
let ivencrypted_for_legacy = encrypt_legacy_using_IV(secret_to_keep);
console.log(ivencrypted_for_legacy);
console.log(legacy_encrypted);
let legacy_decrypted_fromiv = decrypt_old(ivencrypted_for_legacy);
console.log(legacy_decrypted_fromiv);
