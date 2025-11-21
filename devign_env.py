from typing import List, Tuple, Dict, Optional, Any
from analyzer import SimpleStaticAnalyzer

def parse_action(action: str):
    """
    "check_pattern('buffer_overflow')" -> ("check_pattern", "buffer_overflow")
    "report_vulnerability(42)"         -> ("report_vulnerability", "42")
    "summarize_code()"                 -> ("summarize_code", None)
    """
    action = action.strip()
    if "(" not in action or not action.endswith(")"):
        return action, None
    name, rest = action.split("(", 1)
    arg = rest[:-1]  # remove ")"
    arg = arg.strip()
    
    if arg.startswith(("'", '"')) and arg.endswith(("'", '"')) and len(arg) >= 2:
        arg = arg[1:-1]
    return name.strip(), arg or None

class DevignEnv:
    def __init__(self, code, label, max_steps=20):
        self.code = code
        self.label = int(label)  # 0 = safe, 1 = vulnerable
        self.max_steps = max_steps
        self.analyzer = SimpleStaticAnalyzer(code)
        self.reset()
        
    def reset(self) -> Dict[str, Any]:
        self.history = []
        self.done = False
        self.step_count = 0

        self.summary = None
        self.variables = None
        self.functions = None
        self.dataflows = None
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

        self.history.append(action)
        self.step_count += 1

        reward = 0
        done = False

        name, arg = parse_action(action)

        if name == "summarize_code":
            self.summary = self.analyzer.summarize_code()

        elif name == "list_variables":
            self.variables = self.analyzer.list_variables()

        elif name == "list_functions":
            self.functions = self.analyzer.list_functions()

        elif name == "list_dataflows":
            self.dataflows = self.analyzer.list_dataflows()

        elif name == "check_pattern":
            if arg == "buffer_overflow":
                self.pattern_results["buffer_overflow"] = self.analyzer.detect_buffer_overflow()
            elif arg == "null_deref":
                self.pattern_results["null_deref"] = self.analyzer.detect_null_deref()
            elif arg == "use_after_free":
                self.pattern_results["use_after_free"] = self.analyzer.detect_use_after_free()

        elif name == "identify_vulnerable_line":
            self.suspected_line = self.analyzer.identify_vulnerable_line()

        # If agent reports vulnerability, evaluate correctness
        elif action == "report_vulnerability":
            # Correct only if this function is truly vulnerable
            reward = 1 if self.label == 1 else 0
            done = True

        # If agent calls stop()
        elif action == "stop()":
            reward = 1 if self.label == 0 else 0
            done = True

        # safety cutoff
        if self.step_count >= self.max_steps:
            done = True

        self.done = done

        return self._get_state(), reward, done
    
    def _get_state(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "history": list(self.history),
            "summary": self.summary,
            "variables": self.variables,
            "functions": self.functions,
            "dataflows": self.dataflows,
            "pattern_results": dict(self.pattern_results),
            "suspected_line": self.suspected_line,
        }