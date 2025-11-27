from typing import Dict, Any
from ollama_client import OllamaClient

ACTION_LIST = [
    "summarize_code()",
    "list_variables()",
    "list_functions()",
    "list_dataflows()",
    "list_freed_variables()",
    "list_null_assigned_variables()",
    "check_pattern('buffer_overflow')",
    "check_pattern('null_deref')",
    "check_pattern('use_after_free')",
    "identify_vulnerable_line()",
    "positive_alarm(<int line_number>)",
    "negative_alarm()",
]

def validate_action(action: str) -> str:
    action = action.strip()
    if action in ACTION_LIST:
        return action
    
    if action.startswith("positive_alarm(") and action.endswith(")"):
        return action
    
    return action

def build_prompt(state: Dict[str, Any]) -> str:
    code = state["code"]
    history = state["history"] or ["(empty)"]
    summary = state["summary"]
    variables = state["variables"]
    functions = state["functions"]
    dataflows = state["dataflows"]
    freed_variables = state["freed_variables"]
    null_assigned_variables = state["null_assigned_variables"]
    pattern_results = state["pattern_results"]
    suspected_line = state["suspected_line"]

    # history_str = "\n- " + "\n- ".join(history)
    left_actions = []
    for action in ACTION_LIST:
        if action in history:
            continue
        left_actions.append(action)
    left_actions_str = "\n- " + "\n- ".join(left_actions) if len(left_actions) > 0 else "(none)"

    summary_str = f"{summary}" if summary is not None else "(unknown)"
    vars_str = ", ".join(variables) if variables else "(unknown)"
    funcs_str = ", ".join(functions) if functions else "(unknown)"
    flows_str = ", ".join([f"{src}->{dst}" for src, dst in dataflows]) if dataflows else "(unknown)"
    freed_str = ", ".join([f"{var}@{line}" for var, line in freed_variables]) if freed_variables else "(unknown)"
    null_assigned_str = ", ".join([f"{var}@{line}" for var, line in null_assigned_variables]) if null_assigned_variables else "(unknown)"

    pattern_str_lines = []
    for k, v in pattern_results.items():
        if v is None:
            pattern_str_lines.append(f"{k}: (unknown)")
            continue
        pattern_str_lines.append(f"{k}: {v}")
    pattern_str = "\n".join(pattern_str_lines)

    suspected_str = str(suspected_line) if suspected_line is not None else "(unknown)"

    prompt = f"""
You are a vulnerability detection agent analyzing a C/C++ function.
Representative vulnerabilities include buffer overflows, null pointer dereferences, and use-after-free errors.
You make decisions step by step using a fixed set of actions.

CURRENT CODE:
{code}

VALID ACTIONS:
{left_actions_str}

CURRENT ANALYSIS STATE:
- code summarization: {summary_str}
- variables: {vars_str}
- functions: {funcs_str}
- dataflows: {flows_str}
- freed variables: {freed_str}
- null-assigned variables: {null_assigned_str}
- suspected vulnerable line: {suspected_str}
- check_pattern:
{pattern_str}

RULES:
- You MUST output exactly ONE action per step.
- Do NOT output explanations or natural language.
- Use only actions in the updated current VALID ACTIONS list.
- Do NOT repeat actions already taken. ONLY USE ACTIONS IN THE UPDATED VALID ACTIONS LIST.

FINAL ACTION CONDITIONS:
- If at least one check_pattern result is True, "positive_alarm(<line_number>)" with the suspected vulnerable line number
- If ALL check_pattern results are False, "negative_alarm()"

Next action:
""".strip()


    return prompt


def agent_policy(state: Dict[str, Any], llm_client: OllamaClient) -> str:
    prompt = build_prompt(state)
    raw_action = llm_client.chat(prompt)
    action = validate_action(raw_action)
    return action