# analyzer.py
import re
from typing import List, Dict, Tuple, Optional

class SimpleStaticAnalyzer:
    """
    heuristic static analyzer.
    """

    def __init__(self, code: str):
        self.code = code
        self.lines = code.split("\n")

    def summarize_code(self) -> Dict:
        return {
            "num_lines": len(self.lines),
            "has_loops": any(("for(" in l or "while(" in l) for l in self.lines),
            "uses_pointers": any(("*" in l or "->" in l) for l in self.lines),
            "has_array": any("[" in l and "]" in l for l in self.lines),
            "calls": self.list_functions(),
        }

    def list_variables(self) -> List[str]:
        vars = []
        for line in self.lines:
            line_stripped = line.strip()
            if ";" in line_stripped and any(
                kw in line_stripped for kw in ["int ", "char ", "float ", "double ", "long "]
            ):
                # Example: "int x = 0;" -> ["int", "x", "=", "0"]
                parts = line_stripped.replace(";", "").split()
                # Type and variable name
                if len(parts) >= 2:
                    var = parts[1].strip(",")
                    if var not in vars:
                        vars.append(var)
        return vars

    def list_functions(self) -> List[str]:
        pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\("
        matches = re.findall(pattern, self.code)
        blacklist = {"if", "for", "while", "switch", "return", "sizeof"}
        calls = [m for m in matches if m not in blacklist]
        return sorted(set(calls))

    def list_dataflows(self) -> List[Tuple[str, str]]:
        flows = []
        for line in self.lines:
            if "=" in line and "==" not in line:
                left, right = line.split("=", 1)
                left = left.strip().split()[-1].strip(" ,;")
                right = right.strip().strip(" ;")
                if left and right:
                    flows.append((right, left))
        return flows

    def detect_buffer_overflow(self) -> bool:
        patterns = ["strcpy", "strcat", "gets", "sprintf", "memcpy"]
        if any(p in self.code for p in patterns):
            return True
        if any("[" in l and "]" in l for l in self.lines):
            if not any(op in self.code for op in ["<=", ">=", "sizeof"]):
                return True
        return False

    def detect_null_deref(self) -> bool:
        uses_ptr = any("*" in l or "->" in l for l in self.lines)
        has_null_check = any("!= NULL" in l or "== NULL" in l for l in self.lines)
        return uses_ptr and not has_null_check

    def detect_use_after_free(self) -> bool:
        freed_vars = []
        for i, line in enumerate(self.lines):
            if "free(" in line:
                inside = line[line.find("free(") + 5 : line.find(")", line.find("free("))]
                var = inside.strip(" )*;&")
                if var:
                    freed_vars.append((var, i))
        if not freed_vars:
            return False

        for var, free_idx in freed_vars:
            for j in range(free_idx + 1, len(self.lines)):
                if var in self.lines[j]:
                    return True
        return False

    def identify_vulnerable_line(self) -> Optional[int]:
        # buffer overflow
        for i, line in enumerate(self.lines, start=1):
            if any(f in line for f in ["strcpy", "strcat", "gets", "sprintf"]):
                return i
        # null deref
        for i, line in enumerate(self.lines, start=1):
            if ("*" in line or "->" in line) and "if(" not in line and "==" not in line and "!=" not in line:
                return i
        # detect_use_after_free
        for i, line in enumerate(self.lines, start=1):
            if "free(" in line:
                return i
        return -1
