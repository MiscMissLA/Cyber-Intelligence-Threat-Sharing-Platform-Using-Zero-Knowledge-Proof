import json

# === THREAT WEIGHTS (tune these as needed) ===
weights = {
    "ipv4": 1,
    "ipv6": 1,
    "md5": 2,
    "sha1": 2,
    "sha256": 3,
    "url": 1,
    "attack_id": 2,
    "threat_actor": 3
}

def score_threat(data):
    r = data['regex_iocs']
    score = 0
    score += len(r['ipv4']) * weights['ipv4']
    score += len(r['ipv6']) * weights['ipv6']
    score += len(r['md5']) * weights['md5']
    score += len(r['sha1']) * weights['sha1']
    score += len(r['sha256']) * weights['sha256']
    score += len(r['url']) * weights['url']
    score += len(r['attack_id']) * weights['attack_id']
    score += len(data.get("threat_actors", [])) * weights['threat_actor']
    return score

# === Read threat JSON ===
file_path = input("Enter path to *_output.json file: ")
with open(file_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# === Scoring ===
score = score_threat(data)
threshold = 10  # You can raise this as needed

zk_input = {"score": score, "threshold": threshold}

with open("input.json", "w") as f:
    json.dump(zk_input, f, indent=2)

print(f"[✓] ZK input generated: score = {score}, threshold = {threshold}")
print("Saved to input.json")
