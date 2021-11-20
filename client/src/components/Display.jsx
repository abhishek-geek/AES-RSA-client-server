// Submitted by: Abhishek Dubey | 2019005
// -------------=========================

// this is a React component to desplay output on the browser

import React from "react";

const Display = ({ value, k }) => {
  const intToBinString = (arr) => {
    if(!Array.isArray(arr)) {
      return arr;
    }
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

  if (value && (value.length || value > 0)) {
    return (
      <p>
        {k}:{" "}
        <span>
          <b>{intToBinString(value)}</b>
        </span>
      </p>
    );
  } else {
    return (
      <p>
        {k}:{" "}
        <span>
          Loading...
        </span>
      </p>
    );
  }
};

export default Display;
