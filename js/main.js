let iv = null;
let useIV = true;
let Hmac = null;
function encrypt(clearTextData, hashedPwd, useIV){
    if (useIV){
      let randomBytes   = CryptoJS.lib.WordArray.random(128/8).toString();
      iv = CryptoJS.enc.Hex.parse(randomBytes);
      console.log(`iv : ${iv}`);
      // old method (wrong) which used first 16 bytes of key (hashed pwd)
      // CryptoJS.enc.Hex.parse(key);
    message = CryptoJS.AES.encrypt(clearTextData, CryptoJS.enc.Hex.parse(hashedPwd),{iv: iv});
    console.log(`message.iv : ${message.iv}`);
    console.log(`message: ${message}`);
    console.log(`message.ciphertext ${message.ciphertext}`);
    console.log(`message.salt ${message.salt}`);
    }
  else{
    message = CryptoJS.AES.encrypt(clearTextData, hashedPwd );
  }
  
    return message.toString();
}

function decrypt(encryptedData, hashedPwd, useIV){
  let code;  
  if (useIV){
    console.log(`hashedPwd: ${hashedPwd}`);
    // we use original created iv
    // we now use the original _random_ iv which
    // is the correct way.  IV will be passed
    // in the clear to decrypting side
    // let iv = CryptoJS.enc.Hex.parse(key);
    console.log(`iv ${iv}`);
    code = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Hex.parse(hashedPwd),{iv:iv});
    console.log(`code ${code}`);
    //alert (typeof(code));
    console.log(code);
    }
  else{
    console.log("decrypting with no IV");
    code = CryptoJS.AES.decrypt(encryptedData, hashedPwd);
    console.log(code);
    
  }
  let decryptedMessage = "";
  if (code.sigBytes < 0){
    decryptedMessage = `Couldn't decrypt! It is probable that an incorrect password was used.`;
    return decryptedMessage;
  }
  decryptedMessage = code.toString(CryptoJS.enc.Utf8);
  return decryptedMessage;
}

function encryptFromText(){
  useIV = document.querySelector("#useIVCheckBox").checked;
  let clearText = document.querySelector("#clear_text").value;
  let cleartext_pwd = document.querySelector("#password").value
  let hashedPwd = sha256(cleartext_pwd);
document.querySelector("#cleartext_output").innerHTML = "";

 document.querySelector("#cipher_output").innerHTML =  encrypt(clearText,hashedPwd,useIV);
    generateHmac();
}

function decryptFromText(){
  document.querySelector("#cleartext_output").innerHTML = "";
  useIV = document.querySelector("#useIVCheckBox").checked;
  let cleartext_pwd = document.querySelector("#password").value;

  let hashedPwd = sha256(cleartext_pwd);
  console.log(`hashedPwd: ${hashedPwd}`);
  
  // either get the cipher text from the input box or the div
  let cipherText = document.querySelector("#cipher_text").value;
  if (cipherText == ""){
    cipherText = document.querySelector("#cipher_output").innerHTML;
  }
  console.log(cleartext_pwd);
  document.querySelector("#cleartext_output").innerHTML = decrypt(cipherText,hashedPwd,useIV);
}

function generateHmac(){
  let cleartext_pwd = document.querySelector("#password").value;
  let encryptedData = document.querySelector("#cipher_output")
  let macKey = sha256(cleartext_pwd);
  console.log(`key: ${macKey}`);
  let hash = sha256.hmac(`${iv}:${encryptedData}`, macKey.toString());
  Hmac = hash;
  console.log(`mac : ${Hmac}`);
  document.querySelector("#hmac").innerHTML = Hmac;
}

function validate(){
    let output = "The MAC is valid.";
    if (!validateMac()){
      output = "The MAC is NOT valid!";
    }
    document.querySelector("#validated").innerHTML = output;
  }

function validateMac(){
    // returns boolean (true if mac matches, otherwise false)
    let cleartext_pwd = document.querySelector("#password").value;
    let encryptedData = document.querySelector("#cipher_output")
    let key = sha256(cleartext_pwd);
    let mac = sha256.hmac(`${iv}:${encryptedData}`, key.toString());
    console.log(`mac : ${mac}`);
    return (mac == Hmac);
}

// Necessary steps
// ## 1. Generate random IV
// ## 2. Encrypt Data using clearText, AES256 & random IV
// ## 3. Add IV as part of message to user (IV can be known by all readers)
// ## 4. Hmac the entire message (IV & enrypted text) so the end user can know that the IV has not been changed.
