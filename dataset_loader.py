import json
import os

root_dir = os.path.abspath("./dataset/devign")
def load_devign_file(path):
    with open(path, 'r') as f:
        data = [json.loads(line.strip()) for line in f if line.strip()]
    
    codes = [item["func"] for item in data]
    labels = [item["target"] for item in data]
    return codes, labels

def load_devign(base_path):
    train_codes, train_labels = load_devign_file(os.path.join(base_path, "train.jsonl"))
    valid_codes, valid_labels = load_devign_file(os.path.join(base_path, "valid.jsonl"))
    test_codes, test_labels = load_devign_file(os.path.join(base_path, "test.jsonl"))

    print("Devign loaded:")
    print(f"  Train: {len(train_codes)} samples")
    print(f"  Valid: {len(valid_codes)} samples")
    print(f"  Test:  {len(test_codes)} samples")

    return {
        "train": (train_codes, train_labels),
        "valid": (valid_codes, valid_labels),
        "test":  (test_codes, test_labels)
    }

load_devign(root_dir)