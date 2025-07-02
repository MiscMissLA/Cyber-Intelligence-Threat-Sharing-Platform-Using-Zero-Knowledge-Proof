const fs = require('fs');
const path = require('path');

// Take path to output JSON from argument
const inputPath = process.argv[2];
const data = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));

const score = data.normalized_vector?.confidence || 0;
const threshold = 10; // Set manually or extract dynamically if available

const circuitInput = {
  score,
  threshold
};

fs.writeFileSync(
  path.join(__dirname, '../proof/input.json'),
  JSON.stringify(circuitInput, null, 2)
);

console.log("✅ ZK input generated:", circuitInput);
