from typing import Dict, Any
from ollama_client import OllamaClient

VALID_ACTIONS_NO_ARG = [
    "summarize_code()",
    "list_variables()",
    "list_functions()",
    "list_dataflows()",
    "identify_vulnerable_line()",
    "stop()",
]

PATTERN_ACTIONS = [
    "check_pattern('buffer_overflow')",
    "check_pattern('null_deref')",
    "check_pattern('use_after_free')",
]

ACTION_LIST = [
    "summarize_code()",
    # "list_variables()",
    # "list_functions()",
    # "list_dataflows()",
    "check_pattern('buffer_overflow')",
    "check_pattern('null_deref')",
    "check_pattern('use_after_free')",
    # "identify_vulnerable_line()",
    "report_vulnerability(line_number)",
    "stop()",
]

def validate_action(action: str) -> str:
    action = action.strip()
    if action in VALID_ACTIONS_NO_ARG or action in PATTERN_ACTIONS:
        return action
    
    if action.startswith("report_vulnerability(") and action.endswith(")"):
        return action
    
    return action

def build_prompt(state: Dict[str, Any]) -> str:
    code = state["code"]
    history = state["history"] or ["(empty)"]
    summary = state["summary"]
    variables = state["variables"]
    functions = state["functions"]
    dataflows = state["dataflows"]
    pattern_results = state["pattern_results"]
    suspected_line = state["suspected_line"]

    history_str = "\n- " + "\n- ".join(history)
    left_actions = []
    for action in ACTION_LIST:
        if action not in history:
            left_actions.append(action)
    left_actions_str = "\n- " + "\n- ".join(left_actions) if len(left_actions) > 0 else "(none)"

    summary_str = f"{summary}" if summary is not None else "(unknown)"
    vars_str = ", ".join(variables) if variables else "(unknown)"
    funcs_str = ", ".join(functions) if functions else "(unknown)"
    flows_str = ", ".join([f"{src}->{dst}" for src, dst in dataflows]) if dataflows else "(unknown)"

    pattern_str_lines = []
    for k, v in pattern_results.items():
        pattern_str_lines.append(f"{k}: {v}")
    pattern_str = "\n".join(pattern_str_lines)

    suspected_str = str(suspected_line) if suspected_line is not None else "(unknown)"

    prompt = f"""
You are a vulnerability detection agent analyzing a C/C++ function.
Representative vulnerabilities include buffer overflows, null pointer dereferences, and use-after-free errors.
You make decisions step by step using a fixed set of actions.

VALID ACTIONS:
{left_actions_str}

CURRENT CODE:
{code}

CURRENT ANALYSIS STATE:
- code summarization: {summary_str}
- list_variables: {vars_str}
- list_functions: {funcs_str}
- list_dataflows: {flows_str}
- check_pattern:
{pattern_str}
- identify_vulnerable_line: {suspected_str}

RULES:
- You MUST output exactly ONE action per step.
- Do NOT output explanations or natural language.
- Do NOT output multiple actions.
- Use only actions in the updated VALID ACTIONS list.
- Before using report_vulnerability or stop(), You should eventually perform other actions at least once:
- There are two final actions: report_vulnerability(line_number) and stop().
- Use report_vulnerability(line_number) when you are certain about the vulnerability.
    Example: report_vulnerability(42)
- Use stop() when you conclude the function is safe.

Next action:
""".strip()

    return prompt


def agent_policy(state: Dict[str, Any], llm_client: OllamaClient) -> str:
    prompt = build_prompt(state)
    raw_action = llm_client.chat(prompt)
    action = validate_action(raw_action)
    return action