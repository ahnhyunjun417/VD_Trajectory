import json
import time
import os

class TrajectoryLogger:
    def __init__(self, output_dir, use_jsonl=False):
        self.output_dir = output_dir
        self.use_jsonl = use_jsonl
        os.makedirs(output_dir, exist_ok=True)

    def save(self, episode_data, episode_id):
        if self.use_jsonl:
            # Append as JSONL
            out_path = os.path.join(self.output_dir, "trajectories.jsonl")
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(episode_data) + "\n")
        else:
            # Save each episode individually, easier for debugging
            out_path = os.path.join(self.output_dir, f"episode_{episode_id}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                temp = episode_data.copy()
                temp["trajectory"] = episode_data["trajectory"][-1]
                json.dump(temp, f, indent=2)
        
        return out_path
