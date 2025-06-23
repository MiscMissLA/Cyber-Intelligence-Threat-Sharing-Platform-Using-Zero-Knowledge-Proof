#!/bin/bash
cd "$(dirname "$0")"

echo "[1] ➤ Compiling Circom circuit..."
circom circuits/threat_proof.circom --r1cs --wasm --sym -o proof -l ../node_modules


echo "[2] ➤ Running trusted setup..."
snarkjs powersoftau new bn128 12 proof/pot12_0000.ptau -v
snarkjs powersoftau contribute proof/pot12_0000.ptau proof/pot12_final.ptau --name="First contribution" -v
snarkjs groth16 setup proof/threat_proof.r1cs proof/pot12_final.ptau proof/threat_proof.zkey
snarkjs zkey export verificationkey proof/threat_proof.zkey proof/verification_key.json

echo "[3] ➤ Generating witness..."
node proof/threat_proof_js/generate_witness.js \
    proof/threat_proof_js/threat_proof.wasm input_generator/input.json proof/witness.wtns

echo "[4] ➤ Generating proof..."
snarkjs groth16 prove proof/threat_proof.zkey proof/witness.wtns \
    proof/proof.json proof/public.json

echo "[✓] Done. Proof + public inputs generated in zk/proof/"
