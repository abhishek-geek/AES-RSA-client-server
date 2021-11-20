// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

// function to compute a 16 bit hash value for a given message
module.exports.hashAlgo = (keyString) => {
  let hash = 0;

  for (let charIndex = 0; charIndex < keyString.length; ++charIndex) {
    hash += keyString.charCodeAt(charIndex);
    hash += hash << 10;
    hash ^= hash >> 6;
  }

  hash += hash << 3;
  hash ^= hash >> 11;
  
  // 65535 i.e FFFF, the maximum 16 bit unsigned integer value, used here as a mask.
  return (((hash + (hash << 15)) & 65535) >>> 0).toString(16)
};
