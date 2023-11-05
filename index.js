
const crypto = require("crypto");

function generateRSAKeyPair() {

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Key length
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    });
  
    return {
        publicKey: publicKey.toString(),
        privateKey: privateKey.toString(),
    };
}

function encryptData(Data, publicKey){
    const buffer = JSON.stringify(Data);
    const cipherData = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha1',
        },
        Buffer.from(buffer)
    );
    return cipherData.toString('base64');
}

function decryptData(encryptedData, privateKey) {
    const buffer = Buffer.from(encryptedData, 'base64');
    const decryptedData = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha1',
        },
        buffer
    );
    return decryptedData.toString();
}

main = () => {

    const myKeyPair = generateRSAKeyPair();

    var cipherData, decryptedData;

    // Encrypt data should be sent by activation server
    try{
        cipherData = encryptData({
            product_id: "1"
        }, myKeyPair.publicKey);
    }catch(e){
        console.log("Encrypt Error: ", e);
    }

    // Decrypt should be done by User's device
    try{
        decryptedData = decryptData(cipherData, myKeyPair.privateKey);
    }catch(e){
        console.log("Decrypt Error: ", e);
    }

    // If decrypted data contains product id 1, then activation has been success
    console.log('Decrypted Data: ', decryptedData);
    try{
        const data = JSON.parse(decryptedData);
        if (data.product_id == 1){
            console.log("Activation: Success");
        }
    }catch(e){
        console.log("Error: ", e);
    }
    
}

main();
