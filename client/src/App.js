// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

// this file handles Client side communications and renders on browser window

import { useEffect, useState } from "react";
import "./App.css";
import Display from "./components/Display";
import { RSAAlgo, AESEncrypt, hashAlgo, RSAKeyGenerator } from "./functions";

function App() {
  const [message, setMessage] = useState(2313); // default message = 2313
  const [secret, setSecret] = useState(4321); // default secret = 4321
  const [p, setP] = useState(907); // default p = 907
  const [q, setQ] = useState(997); // default q = 997
  const [e, setE] = useState(7); // default e = 7

  // defining variables that will store values after computation
  const [serverPublicKey, setServerPublicKey] = useState({});
  const [encryptedSecretKey, setEncryptedSecretKey] = useState();
  const [cipherMessage, setCipherMessage] = useState();
  const [digest, setDigest] = useState();
  const [clientPrivateKey, setClientPrivateKey] = useState({});
  const [clientPublicKey, setClientPublicKey] = useState({});
  const [clientSignature, setClientSignature] = useState();
  const [aesLog, setAesLog] = useState({});

  // fetching server's public key on opening the client application
  useEffect(() => {
    fetch("http://localhost:4000/public-key/")
      .then((res) => res.json())
      .then((res) => setServerPublicKey(res)) // seting servers public key globally
      .catch((err) => console.log(err)); // log if there is an error while fetching
  }, []);

  // Function to send data to server using server's API
  const sendDataToServer = ({
    cipherMessage,
    encryptedSecretKey,
    clientSignature,
    clientPublicKey,
  }) => {
    // data to be sent:
    const data = {
      cipherMessage,
      encryptedSecretKey,
      clientSignature,
      clientPublicKey,
    };

    fetch("http://localhost:4000/output/", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(data),
    })
      .then((res) => res.json())
      .then((res) => {
        console.log(res);
      })
      .catch((err) => {
        console.log(err);
      });
  };

  // function that handles submiting input from form and getting outputs
  const main = (event) => {
    event.preventDefault();

    // 1. Create Client signature through RSA algorithm, taking Digest from
    //    Hash algorithm and client private key as input.

    // get Client's private key and public key
    const { privateKey, publicKey } = RSAKeyGenerator(p, q, e);

    // generate digest from input message
    const hash = hashAlgo(String(message));
    setDigest(hash);

    // generate client's signature from the digest
    const sig = RSAAlgo(parseInt(hash, 16), privateKey);
    setClientSignature(sig);

    // 2. Create Ciphertext through the AES variant, taking Message and Secret key as input.

    // encrypt message using AES varient
    const { cipherText, output } = AESEncrypt(message, secret);
    setCipherMessage(cipherText);
    setAesLog(output);

    // 3. Encrypt Secret key with RSA algorithm, taking Secret key and Server Public key as input.

    // encrypt secret key using RSA algorithm and server's public key
    const encryptedKey = RSAAlgo(secret, serverPublicKey);
    setEncryptedSecretKey(encryptedKey);

    // 4. Sending Cipher Message, Encrypted SecretKey, Client Signature, and Client Public Key to server.

    setClientPrivateKey(privateKey);
    setClientPublicKey(publicKey);

    // passing data to be sent to server
    sendDataToServer({
      cipherMessage: cipherText,
      encryptedSecretKey: encryptedKey,
      clientSignature: sig,
      clientPublicKey: publicKey,
    });
  };

  return (
    <div className="App">
      <header className="App-header">Client application</header>
      <header>Abhishek Dubey <span>|</span> 2019005</header>
      <div className="main">
        <div>
          <h1>Input Form</h1>
          <form onSubmit={main}>
            <label for="message">Message:</label>
            <br />
            <input
              type="text"
              id="message"
              name="message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
            />
            <br />
            <br />
            <label for="secret">Secret Key:</label>
            <br />
            <input
              type="text"
              id="secret"
              name="secret"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
            <p for="public-key">Public Key Parameters:</p>
            <div className="parameter">
              <div>
              <label for="public-key">P:</label>
              <input
                type="text"
                value={p}
                placeholder="p"
                onChange={(e) => setP(e.target.value)}
              />
              </div>
              <br />
              <div>
              <label for="public-key">Q:</label>
              <input
                type="text"
                value={q}
                placeholder="q"
                onChange={(e) => setQ(e.target.value)}
              />
              </div>
              <br />
              <div>
              <label for="public-key">R:</label>
              <input
                type="text"
                value={e}
                placeholder="e"
                onChange={(e) => setE(e.target.value)}
              />
              </div>
            </div>
            <br />
            <br />
            <button type="submit" style={{ width: "100%" }}>
              Submit
            </button>
          </form>
        </div>
        <div>
          <h1>Output</h1>
          <Display k="Server's Public Key, n" value={serverPublicKey.n} />
          <Display k="Server's Public Key, e" value={serverPublicKey.e} />
          <Display k="Encrypted Secret Key" value={encryptedSecretKey} />
          <h2>Cipher text intermediate computation process:</h2>
          <div style={{ paddingLeft: "30px" }}>
            <Display k="Round key K0" value={aesLog.k0} />
            <Display
              k="After Round 1 Substitute nibbles"
              value={aesLog.subNib1}
            />
            <Display k="After Round 1 Shift rows" value={aesLog.shiftRow1} />
            <Display k="After Round 1 Mix columns" value={aesLog.mixCol} />
            <Display
              k="After Round 1 Add round key"
              value={aesLog.addRoundKey1}
            />
            <Display k="Round key K1" value={aesLog.k1} />
            <Display
              k="After Round 2 Substitute nibbles"
              value={aesLog.subNib2}
            />
            <Display k="After Round 2 Shift rows" value={aesLog.shiftRow2} />
            <Display
              k="After Round 2 Add round key"
              value={aesLog.addRoundKey2}
            />
            <Display k="Round Key K2" value={aesLog.k2} />
          </div>
          <Display k="Cipher Message" value={cipherMessage} />
          <Display k="Digest" value={digest} />
          <Display k="Digital Signature" value={clientSignature} />
          <Display k="Client Private Key, d" value={clientPrivateKey.e} />
          <Display k="Client Public Key, n" value={clientPublicKey.n} />
        </div>
      </div>
    </div>
  );
}

export default App;
