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

def validate_action(action: str) -> str:
    action = action.strip()
    if action in VALID_ACTIONS_NO_ARG or action in PATTERN_ACTIONS:
        return action
    
    if action.startswith("report_vulnerability(") and action.endswith(")"):
        return action
    
    return "Failed to parse action"

def build_prompt(state: Dict[str, Any]) -> str:
    code = state["code"]
    history = state["history"] or ["(empty)"]
    summary = state["summary"]
    variables = state["variables"]
    functions = state["functions"]
    dataflows = state["dataflows"]
    pattern_results = state["pattern_results"]
    suspected_line = state["suspected_line"]

    history_str = "\n- ".join(history)

    summary_str = f"{summary}" if summary is not None else "(not computed)"
    vars_str = ", ".join(variables) if variables else "(unknown)"
    funcs_str = ", ".join(functions) if functions else "(unknown)"
    flows_str = ", ".join([f"{src}->{dst}" for src, dst in dataflows]) if dataflows else "(unknown)"

    pattern_str_lines = []
    for k, v in pattern_results.items():
        pattern_str_lines.append(f"{k}: {v}")
    pattern_str = "\n".join(pattern_str_lines)

    suspected_str = str(suspected_line) if suspected_line is not None else "(unknown)"

    system_prompt = f"""
You are a vulnerability detection agent analyzing a C/C++ function.
Representative vulnerabilities include buffer overflows, null pointer dereferences, and use-after-free errors.
You make decisions step by step using a fixed set of actions.

VALID ACTIONS:
1. summarize_code(): Provides a high-level structural summary of the function
2. list_variables(): Returns the list of variables declared in the function.
3. list_functions(): Returns all function calls found in the code.
4. list_dataflows(): Returns simple dataflow relations of the form source -> destination
5. check_pattern("buffer_overflow"): Returns True if the code contains buffer overflow indicators:
      e.g., strcpy, strcat, sprintf, gets, memcpy, or array writes without bounds checks.
6. check_pattern("null_deref"): Returns True if pointers are used without any NULL-check.
7. check_pattern("use_after_free"): Returns True if a variable is freed and later reused.
8. identify_vulnerable_line(): Returns the most suspicious line number. Otherwise, returns -1
9. report_vulnerability(<line_number>): Final action. Report that the function is vulnerable and specify the line number
10. stop(): Use when you conclude the function is safe or no more useful actions remain.

RULES:
- You MUST output exactly ONE action per step.
- Do NOT output explanations or natural language.
- Do NOT output multiple actions.
- Use only actions in the VALID ACTIONS list.
""".strip()
    
    user_prompt = f"""
CURRENT CODE:
{code}

CURRENT ANALYSIS STATE:
- summary: {summary_str}
- variables: {vars_str}
- function calls: {funcs_str}
- dataflows: {flows_str}
- pattern results:
{pattern_str}
- suspected vulnerable line: {suspected_str}

ACTION HISTORY:
- {history_str}

Next action:
""".strip()

    return {"system": system_prompt, "user": user_prompt}


def agent_policy(state: Dict[str, Any], llm_client: OllamaClient) -> str:
    prompt = build_prompt(state)
    raw_action = llm_client.chat(prompt)
    action = validate_action(raw_action)
    return action