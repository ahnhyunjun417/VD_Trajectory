from typing import List, Tuple, Dict, Optional, Any
from analyzer import SimpleStaticAnalyzer

ACTION_LIST = [
    "summarize_code()",
    "list_variables()",
    "list_functions()",
    # "list_dataflows()",
    "list_freed_variables()",
    "list_null_assigned_variables()",
    "check_pattern('buffer_overflow')",
    "check_pattern('null_deref')",
    "check_pattern('use_after_free')",
    # "identify_vulnerable_line()",
    "positive_alarm(<int line_number>)",
    "negative_alarm()",
]

def parse_action(action: str, history: Optional[List[str]] = None):
    """
    "check_pattern('buffer_overflow')" -> ("check_pattern", "buffer_overflow")
    "positive_alarm(42)"         -> ("positive_alarm", "42")
    "summarize_code()"                 -> ("summarize_code", None)
    """
    action = action.split('\n')[0].strip()
    if "(" not in action or not action.endswith(")"):
        return action, None
    name, rest = action.split("(", 1)
    arg = rest[:-1]  # remove ")"
    arg = arg.strip()
    
    if arg.startswith(("'", '"')) and arg.endswith(("'", '"')) and len(arg) >= 2:
        arg = arg[1:-1]

    return name.strip(), arg or None

class DevignEnv:
    def __init__(self, code, label, max_steps=10):
        self.code = code
        self.label = int(label)  # 0 = safe, 1 = vulnerable
        self.max_steps = max_steps
        self.analyzer = SimpleStaticAnalyzer(code)
        self.reset()
        
    def reset(self) -> Dict[str, Any]:
        self.history = []
        self.processed_actions = []
        self.done = False
        self.step_count = 0

        self.summary = None
        self.variables = None
        self.functions = None
        self.dataflows = None
        self.freed_variables = None
        self.null_assigned_variables = None
        self.pattern_results = {
            "buffer_overflow": None,
            "null_deref": None,
            "use_after_free": None,
        }
        self.suspected_line = None

        return self._get_state()

    def step(self, action: str):
        if self.done:
            raise RuntimeError("Episode already finished. Call reset().")

        self.step_count += 1

        self.history.append(action)
        reward = 0
        done = False

        name, arg = parse_action(action, self.history)

        normal = False
        if name == "summarize_code":
            self.summary = self.analyzer.summarize_code()
            normal = True
        elif name == "list_variables":
            self.variables = self.analyzer.list_variables()
            normal = True
        elif name == "list_functions":
            self.functions = self.analyzer.list_functions()
            normal = True
        elif name == "list_dataflows":
            self.dataflows = self.analyzer.list_dataflows()
            normal = True
        elif name == "list_freed_variables":
            self.freed_variables = self.analyzer.list_freed_variables()
            normal = True
        elif name == "list_null_assigned_variables":
            self.null_assigned_variables = self.analyzer.list_null_assigned_variables()
            normal = True
        elif name == "check_pattern":
            if arg == "buffer_overflow":
                # self.pattern_results["buffer_overflow"] = self.analyzer.detect_buffer_overflow()
                self.pattern_results["buffer_overflow"] = self.analyzer.detect_buffer_overflow_v2(self.functions)
                normal = True
            elif arg == "null_deref":
                # self.pattern_results["null_deref"] = self.analyzer.detect_null_deref()
                self.pattern_results["null_deref"] = self.analyzer.detect_null_deref_v2(self.freed_variables)
                normal = True
            elif arg == "use_after_free":
                # self.pattern_results["use_after_free"] = self.analyzer.detect_use_after_free()
                self.pattern_results["use_after_free"] = self.analyzer.detect_use_after_free_v2(self.null_assigned_variables)
                normal = True

        elif name == "identify_vulnerable_line":
            self.suspected_line = self.analyzer.identify_vulnerable_line()
            normal = True

        # If agent reports vulnerability, evaluate correctness
        elif name == "positive_alarm":
            # Correct only if this function is truly vulnerable
            reward = 1 if self.label == 1 else 0
            done = True
            normal = True

        # If agent thinks no vulnerability, evaluate correctness
        elif name == "negative_alarm()":
            reward = 1 if self.label == 0 else 0
            done = True
            normal = True

        # safety cutoff
        if self.step_count >= self.max_steps:
            reward = 1 if self.label == 0 else 0
            done = True
            normal = True

        self.done = done
        
        if arg is None:
            processed_action = name + "()"
        else:
            processed_action = f"{name}({arg})"
        self.processed_actions.append((processed_action, "VALID" if normal else "INVALID"))

        return self._get_state(), reward, done
    
    def _get_state(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "vulnerable": self.label,
            "history": list(self.history),
            "processed_actions": self.processed_actions,
            "summary": self.summary,
            "variables": self.variables,
            "functions": self.functions,
            "dataflows": self.dataflows,
            "freed_variables": self.freed_variables,
            "null_assigned_variables": self.null_assigned_variables,
            "pattern_results": dict(self.pattern_results),
            "suspected_line": self.suspected_line,
        }