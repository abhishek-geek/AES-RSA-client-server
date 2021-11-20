// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

const express = require("express");
const cors = require("cors");
const app = express();

// Import necessary functions:
const { RSAAlgo, AESDecrypt, hashAlgo, RSAKeyGenerator } = require("./functions");

// Receive value of P, Q, E from command-line for RSA Key Generation.
// If not provided, use default values: P = 907, Q = 773, E = 11.
let input = [907, 773, 11];
if(process.argv.slice(2).length === 3)
input = process.argv.slice(2);
const p = input[0];
const q = input[1];
const e = input[2];
console.log("Server's Key Parameters:", {p, q, e});

// Generate Server's Public Key and Private Key
const {publicKey: serverPublicKey, privateKey: serverPrivateKey} = RSAKeyGenerator(p, q, e);

// Main function that handle server side computation workflow
const main = ({cipherMessage, encryptedSecretKey, clientSignature, clientPublicKey}) => {

  // 1. Decrypt Secret key using RSA algorithm with server's private key
  const decryptedSecretKey = RSAAlgo(encryptedSecretKey, serverPrivateKey);

  // 2. Decrypt ciphertext using AES variant using decrypted secret key
  const {plainText: message, output} = AESDecrypt(cipherMessage, decryptedSecretKey);

  // 3. Create message digest using the plain text obtained above
  const digest = hashAlgo(String(message));

  // 4. Verify Client Signature
  let verified = false;
  const dig = RSAAlgo(clientSignature, clientPublicKey);  // decrypt client signature
  if(dig === parseInt(digest,16))  // compare decrypted client signature with generated digest
  {
    verified = true; 
  }  

  // 5. Print Output
  printOutput({decryptedSecretKey, message, digest, signature: dig.toString(16), verified, output});

}

// function to convert array of integer to representable binary string
const intToBinString = (arr) => {

  let binArr = arr.map(v=> {
    const b = v.toString(2);
    let bin = "";
    for(let i = 0; i<(4-b.length); i++) {
      bin += "0";
    }
    bin += b;
    return bin;
  });

  return binArr.toString().replace(/,/g, ' ');
}

// Function to print output to console
const printOutput = ({decryptedSecretKey, message, digest, signature, verified, output}) => {
  // console.log({decryptedSecretKey, message, digest, signature, verified});
  console.log("\n------------------------OUTPUT--------------------------");
  console.log("Decrypted Secret Key:\t\t\t", decryptedSecretKey);
  console.log("\nDecryption Intermediate process:");
  console.log("Round Key, K2:\t\t\t\t", intToBinString(output.k2));
  console.log("After Round 1 InvShift rows:\t\t", intToBinString(output.invShiftRow1));
  console.log("After Round 1 InvSubstitute nibbles:\t", intToBinString(output.invSubNib1));
  console.log("After Round 1 InvAdd round key:\t\t", intToBinString(output.addRoundKey1));
  console.log("Round 1 Key, K1:\t\t\t", intToBinString(output.k1));
  console.log("After Round 1 InvMix columns:\t\t", intToBinString(output.invMixCol));
  console.log("After Round 2 InvShift rows:\t\t", intToBinString(output.invShiftRow2));
  console.log("After Round 2 InvSubstitute nibbles:\t", intToBinString(output.invSubNib2));
  console.log("After Round 2 Add round key:\t\t", intToBinString(output.addRoundKey2));
  console.log("Pre round Key, K0:\t\t\t", intToBinString(output.k0));
  console.log("\nDecrypted Message:\t\t\t", message);
  console.log("Digest from decrypted message:\t\t", digest);
  console.log("Decrypted Signature:\t\t\t", signature);
  console.log("Verified:\t\t\t\t", verified);
  console.log();
  console.log("Submitted by: Abhishek Dubey | 2019005");
  console.log("-------------=========================", '\n');
}

// Express app to communicate with client using REST API
app.use(cors());
app.use(express.json());

// API to check if server is listening or not
app.get("/", async (req, res) => {
  console.log("health good");
  res.status(200).json({res: "healthy"});
})

// API to get Server's Public Key
app.get("/public-key", async (req, res) => {
  res.status(200).json(serverPublicKey);
})

// API to send encrypted message to server from client
app.post("/output", (req, res) => {
  console.log("-------------------------INPUT-------------------------");
  console.log("\n"+"Passed parameters for RSA:"+"\nP = "+p+", Q = "+q+", E = "+ e+"\n");
  const {cipherMessage, encryptedSecretKey, clientSignature, clientPublicKey} = req.body;
  console.log("Input received from client: \n");
  console.log("Encrypted Message:\t\t\t", cipherMessage);
  console.log("Encrypted Secret Key:\t\t\t", encryptedSecretKey);
  console.log("Client's Signature:\t\t\t", clientSignature);
  console.log("Client's Public Key Parameters: N:\t", clientPublicKey.n);
  console.log("Client's Public Key Parameters: E:\t", clientPublicKey.e);
  main({cipherMessage, encryptedSecretKey, clientSignature, clientPublicKey});
  res.status(200).json({request: {cipherMessage, encryptedSecretKey, clientSignature, clientPublicKey}});
})

// Server starts listening to API request on PORT 4000
app.listen(4000, () => {
  console.log("Listening on http://localhost:4000/");
})