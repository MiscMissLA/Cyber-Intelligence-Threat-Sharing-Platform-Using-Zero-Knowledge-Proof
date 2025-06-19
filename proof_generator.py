import subprocess
import json
import os

CIRCUIT = "phishing_score"
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CIRCUIT_PATH = os.path.join(BASE_DIR, "circuits", f"{CIRCUIT}.circom")
BUILD_DIR = os.path.join(BASE_DIR, "build")
os.makedirs(BUILD_DIR, exist_ok=True)

def run(cmd):
    print(f"→ {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def generate_proof(score):
    input_data = {"score": score}
    with open(os.path.join(BUILD_DIR, "input.json"), "w") as f:
        json.dump(input_data, f)

    # Compile circuit
    run(f"circom {CIRCUIT_PATH} --r1cs --wasm --sym -o {BUILD_DIR}")

    # Generate witness
    run(f"node {BUILD_DIR}/{CIRCUIT}_js/generate_witness.js "
        f"{BUILD_DIR}/{CIRCUIT}_js/{CIRCUIT}.wasm "
        f"{BUILD_DIR}/input.json {BUILD_DIR}/witness.wtns")

    # Powers of Tau (1-time)
    if not os.path.exists(os.path.join(BASE_DIR, "pot12_final.ptau")):
        run("snarkjs powersoftau new bn128 12 pot12_0000.ptau -v")
        run("snarkjs powersoftau contribute pot12_0000.ptau pot12_final.ptau --name='initial' -v")

    # Generate .zkey
    run(f"snarkjs groth16 setup {BUILD_DIR}/{CIRCUIT}.r1cs {BASE_DIR}/pot12_final.ptau {BUILD_DIR}/circuit_0000.zkey")
    run(f"snarkjs zkey contribute {BUILD_DIR}/circuit_0000.zkey {BUILD_DIR}/circuit_final.zkey --name='vinayak'")
    run(f"snarkjs zkey export verificationkey {BUILD_DIR}/circuit_final.zkey {BUILD_DIR}/verification_key.json")

    # Generate proof
    run(f"snarkjs groth16 prove {BUILD_DIR}/circuit_final.zkey {BUILD_DIR}/witness.wtns "
        f"{BUILD_DIR}/proof.json {BUILD_DIR}/public.json")

    print("\n✅ Proof and public input generated.")

if __name__ == "__main__":
    generate_proof(score=85)

