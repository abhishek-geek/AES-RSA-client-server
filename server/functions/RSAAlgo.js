// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

// this file contains implementation of RSA algorithm
// RSA Key Generator and RSA encryptor - decryptor is exported at the bottom of the file

const power = (x, y, m) => {
  // function to calculate ( x^y % m ) of large numbers using principles of modular arithemetics

  let res = 1;
  x = x % m;

  while (y > 0) {
    if (y & 1) res = (res * x) % m;

    // y must be even now
    y = y >> 1; // y = y/2
    x = (x * x) % m;
  }
  return res;
};

const modInverse = (a, m) => {
  // calculates modulo inverse: ( 1/a ) % m
  for (let x = 1; x < m; x++) if (((a % m) * (x % m)) % m === 1) return x;
};

const gcd = (x, y) => {
  x = Math.abs(x);
  y = Math.abs(y);
  while (y) {
    let t = y;
    y = x % y;
    x = t;
  }
  return x;
};

const lcm = (n1, n2) => {
  // gcd of n1, n2
  let g = gcd(n1, n2);

  // lcm = (n1 x n2) / gcd
  return (n1 * n2) / g;
};

const RSAKeyGenerator = (p, q, e) => {
  const n = p * q;
  const ln = lcm(p - 1, q - 1);
  const d = modInverse(e, ln);
  const data = {
    publicKey: { n, e },
    privateKey: { n, e: d },
  };
  return data;
};

const RSAAlgo = (data, key) => {
  return power(data, key.e, key.n);
};

module.exports = {
  RSAKeyGenerator,
  RSAAlgo,
};
