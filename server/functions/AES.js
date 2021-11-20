// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

// this file implements AES encryption and decryption.
// fuction to encrypt and decrypt is exported at the bottom of the file

let key;
let preRoundKey, round1Key, round2Key;
let output = {};

// S-Box
let sBox = [
  0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf,
  0x7,
];

// Inverse S-Box
let InvSBox = [
  0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf, 0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd,
  0xe,
];

const substituteWord = (word) => {
  // Substitute nibble for each nibble in the word using Sbox
  return (sBox[word >> 4] << 4) + sBox[word & 0x0f];
};

const rotateWord = (word) => {
  // Swap two nibbles in the word
  return ((word & 0x0f) << 4) + ((word & 0xf0) >> 4);
};

const intToState = (n) => {
  // Convert a 2-byte integer into a 4-element vector (state matrix)
  return [(n >> 12) & 0xf, (n >> 4) & 0xf, (n >> 8) & 0xf, n & 0xf];
};

const keyExpansion = (key) => {
  // Create three 16-bit round keys from one single 16-bit cipher key

  // Round constants
  let Rcon1 = 0x80;
  let Rcon2 = 0x30;

  // Calculate value of each word
  let w = [];
  w.length = 6;
  w[0] = (key & 0xff00) >> 8;
  w[1] = key & 0x00ff;
  w[2] = w[0] ^ (substituteWord(rotateWord(w[1])) ^ Rcon1);
  w[3] = w[2] ^ w[1];
  w[4] = w[2] ^ (substituteWord(rotateWord(w[3])) ^ Rcon2);
  w[5] = w[4] ^ w[3];

  return {
    preRoundKey: intToState((w[0] << 8) + w[1]), // Pre-Round key
    round1Key: intToState((w[2] << 8) + w[3]), // Round 1 key
    round2Key: intToState((w[4] << 8) + w[5]), // Round 2 key
  };
};

const gfMult = (a, b) => {
  // Galois field multiplication of a and b in GF(2^4) / x^4 + x + 1

  let product = 0;

  // Mask the unwanted bits
  a = a & 0x0f;
  b = b & 0x0f;

  // While both multiplicands are non-zero
  while (a && b) {
    // If LSB of b is 1
    if (b & 1) {
      // Add current a to product
      product = product ^ a;
    }

    // Update a to a * 2
    a = a << 1;

    // If a overflows beyond 4th bit
    if (a & (1 << 4)) {
      // XOR with irreducible polynomial with high term eliminated
      a = a ^ 0b10011;
    }

    // Update b to b // 2
    b = b >> 1;
  }

  return product;
};

const stateToInt = (m) => {
  // Convert a 4-element vector (state matrix) into 2-byte integer
  return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3];
};

const addRoundKey = (s1, s2) => {
  // Add round keys in GF(2^4)

  let data = [];
  const n = s1.length;
  data.length = n;

  for (let i = 0; i < n; i++) {
    data[i] = s1[i] ^ s2[i];
  }

  return data;
};

const subNibbles = (sbox, state) => {
  let data = [];
  const n = state.length;
  data.length = n;

  for (let i = 0; i < n; i++) {
    data[i] = sbox[state[i]];
  }

  return data;
};

const shiftRows = (state) => {
  // Shift/inverse shift rows of state matrix
  return [state[0], state[1], state[3], state[2]];
};

const mixColumns = (state) => {
  return [
    state[0] ^ gfMult(4, state[2]),
    state[1] ^ gfMult(4, state[3]),
    state[2] ^ gfMult(4, state[0]),
    state[3] ^ gfMult(4, state[1]),
  ];
};

const inverseMixColumns = (state) => {
  return [
    gfMult(9, state[0]) ^ gfMult(2, state[2]),
    gfMult(9, state[1]) ^ gfMult(2, state[3]),
    gfMult(9, state[2]) ^ gfMult(2, state[0]),
    gfMult(9, state[3]) ^ gfMult(2, state[1]),
  ];
};

const encrypt = (plaintext) => {
  // Encrypt plaintext with given key

  let state = addRoundKey(preRoundKey, intToState(plaintext));

  state = mixColumns(shiftRows(subNibbles(sBox, state)));

  state = addRoundKey(round1Key, state);

  state = shiftRows(subNibbles(sBox, state));

  state = addRoundKey(round2Key, state);

  return stateToInt(state);
};

const decrypt = (ciphertext) => {
  // Decrypt ciphertext with given key

  let state = addRoundKey(round2Key, intToState(ciphertext));
  output.addRoundKey1 = state;

  let invShiftRow = shiftRows(state);
  output.invShiftRow1 = invShiftRow;

  state = subNibbles(InvSBox, invShiftRow);
  output.invSubNib1 = state;

  state = inverseMixColumns(addRoundKey(round1Key, state));
  output.invMixCol = state;

  invShiftRow = shiftRows(state);
  output.invShiftRow2 = invShiftRow;

  state = subNibbles(InvSBox, invShiftRow);
  output.invSubNib2 = state;

  state = addRoundKey(preRoundKey, state);
  output.addRoundKey2 = state;

  return stateToInt(state);
};

const AESEncrypt = (plainText, secretKey) => {
  // set key globally
  key = secretKey;

  // get pre round key, round 1 key and round 2 key and set globally
  const obj = keyExpansion(key);
  preRoundKey = obj.preRoundKey;
  round1Key = obj.round1Key;
  round2Key = obj.round2Key;

  return encrypt(plainText);
};

const AESDecrypt = (cipherText, secretKey) => {
  // set key globally
  key = secretKey;

  // get pre round key, round 1 key and round 2 key and set globally
  const obj = keyExpansion(key);
  preRoundKey = obj.preRoundKey;
  round1Key = obj.round1Key;
  round2Key = obj.round2Key;

  output.k0 = preRoundKey;
  output.k1 = round1Key;
  output.k2 = round2Key;


  return {plainText: decrypt(cipherText), output};
};

module.exports = {
  AESEncrypt,
  AESDecrypt,
};
