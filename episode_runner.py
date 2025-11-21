import time
import os
import random
from tqdm import tqdm
from trajectory_logger import TrajectoryLogger
from dataset_loader import load_devign
from devign_env import DevignEnv
from agent_policy import agent_policy
from ollama_client import OllamaClient

def run_episode(env: DevignEnv, llm_client, logger: TrajectoryLogger, episode_id: int):
    t0 = time.time()
    state = env.reset()
    trajectory = []

    for t in range(env.max_steps):
        action = agent_policy(state, llm_client)
        next_state, reward, done = env.step(action)

        # Log step
        trajectory.append({
            "t": t,
            "state": state,
            "action": action,
            "reward": reward,
            "done": done
        })

        if done:
            break
        state = next_state

    time_taken = time.time() - t0

    episode_data = {
        "time_taken": time_taken,
        "trajectory": trajectory
    }

    logger.save(episode_data, episode_id)
    return episode_data

def run_multiple_episodes(
    dataset,
    llm_client,
    num_episodes: int = 0,
    seed: int = 42,
    output_dir="./dataset/devign_runs",
    use_jsonl=False,
    only_vulnerable=False,
):  
    random.seed(seed)
    codes, labels = dataset
    indices = list(range(len(codes)))
    if only_vulnerable:
        indices = [i for i in indices if labels[i] == 1]

    print(f"Total train samples: {len(codes)} (after filter: {len(indices)})")

    logger = TrajectoryLogger(output_dir=output_dir, use_jsonl=use_jsonl)

    stats = {
        "num_episodes": 0,
        "num_success": 0,
        "total_steps": 0,
        "label_counts": {0: 0, 1: 0}
    }

    for ep_id, (code, label) in tqdm(enumerate(zip(codes, labels))):
        stats["label_counts"][label] += 1

        env = DevignEnv(code, label, max_steps=20)
        episode_data = run_episode(
            env=env,
            logger=logger,
            episode_id=ep_id,
            llm_client=llm_client
        )

        traj = episode_data["trajectory"]
        stats["num_episodes"] += 1
        stats["total_steps"] += len(traj)
        if len(traj) > 0 and traj[-1]["reward"] > 0:
            stats["num_success"] += 1

        print(f"[Episode {ep_id}] label={label}, steps={len(traj)}, "
              f"last_reward={traj[-1]['reward'] if traj else 'N/A'}")
        
        if num_episodes > 0 and stats["num_episodes"] >= num_episodes:
            break

    return stats


if __name__ == "__main__":
    ### Load Devign dataset
    root_dir = os.path.abspath("./dataset/devign")
    dataset = load_devign(root_dir)

    # train_codes, train_labels = dataset["train"]
    # valid_codes, valid_labels = dataset["valid"]
    # test_codes, test_labels = dataset["test"]

    ### LLM client setup
    model_name = "llama3.2" ### ["llama3.2:3b", "mistral:7b", "llama3.1:8b", codellam:7b, deepseek-coder:6.7b, "qwen:2.5-7b", "qwen2.5-coder:7b", "qwen3:8b"]
    ollama_url = "http://localhost:11434/api/chat"
    llm = OllamaClient(model=model_name, url=ollama_url)

    ### Run episodes on train_codes
    for dataset_name in dataset:
        print("Running episodes on training set...")
        stats = run_multiple_episodes(
            dataset=dataset[dataset_name],
            num_episodes=10,
            llm_client=llm,
            output_dir=f"./dataset/devign_runs/{dataset_name}",
            use_jsonl=False,       # use_jsonl=True: all episodes in one JSONL file
            only_vulnerable=False  # only_vulnerable=True: only run on vulnerable samples
        )

        print(f"\n=== SUMMARY of {dataset_name} ===")
        print("Episodes:", stats["num_episodes"])
        print("Success episodes:", stats["num_success"])
        print("Success rate:", stats["num_success"] / stats["num_episodes"])
        print("Average steps:", stats["total_steps"] / stats["num_episodes"])
        print("Label counts:", stats["label_counts"])
