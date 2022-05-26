const api = require("neptune-js");

const correct_result =
  "17913732bd28f1e73f4cb7bae1a9949d071ee1ea41784725a47c880c40b9e6fb";

{
  const one = [...Array.from({ length: 63 }, () => 0), 1].join("");
  console.log("   one:", one);
  const two = [...Array.from({ length: 63 }, () => 0), 2].join("");
  console.log("   two:", two);
  const result = api.poseidon_t3(one, two);
  console.log("result:", result);
  if (result != correct_result) {
    throw new Error("assertion failed: hash is different");
  }
}

{
  const one = "01";
  const two = "02";
  const result = api.poseidon_t3(one, two);
  if (result != correct_result) {
    throw new Error("assertion failed: hash is different");
  }
}
