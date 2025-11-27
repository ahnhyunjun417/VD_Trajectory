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
            "loops": any(("for(" in l or "while(" in l) for l in self.lines),
            "pointers": any(("*" in l or "->" in l) for l in self.lines),
            "arrays": any("[" in l and "]" in l for l in self.lines),
            "calls": self.list_functions(),
        }

    def is_comment_or_empty(self, line: str) -> bool:
        s = line.strip()
        return not s or s.startswith("//") or s.startswith("/*") or s.startswith("*")

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
    
    def list_null_assigned_variables(self) -> List[str]:
        null_assigned_vars = []  # (var_name, line_idx)
        null_assign_pattern = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*NULL\b")

        for i, line in enumerate(self.lines):
            if self.is_comment_or_empty(line):
                continue
            m = null_assign_pattern.search(line)
            if m:
                var = m.group(1)
                null_assigned_vars.append((var, i))
        return null_assigned_vars

    def list_freed_variables(self) -> List[Tuple[str, int]]:
        freed_vars = []  # (var_name, line_idx)
        free_pattern = re.compile(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)")

        for i, line in enumerate(self.lines):
            if self.is_comment_or_empty(line):
                continue
            m = free_pattern.search(line)
            if m:
                var = m.group(1)
                freed_vars.append((var, i))
        return freed_vars

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

    def detect_buffer_overflow_v2(self, function_list) -> bool:
        patterns = ["strcpy", "strcat", "gets", "sprintf", "memcpy"]
        if function_list is None:
            return None
        if any(p in function_list for p in patterns):
            return True
        if any("[" in l and "]" in l for l in self.lines):
            if not any(op in self.code for op in ["<=", ">=", "sizeof"]):
                return True
        return False

    def detect_null_deref(self) -> bool:
        uses_ptr = any("*" in l or "->" in l for l in self.lines)
        has_null_check = any("!= NULL" in l or "== NULL" in l for l in self.lines)
        return uses_ptr and not has_null_check
    
    def has_deref_of_var(self, line: str, var: str, deref_cache) -> bool:
        key = (line, var)
        if key in deref_cache:
            return deref_cache[key]
        
        v = re.escape(var)
        patterns = [
            r"\*" + r"\s*" + v + r"\b",     # *var
            r"\b" + v + r"\s*->",           # var->
            r"\b" + v + r"\s*\[",           # var[ ... ]
        ]
        res = any(re.search(p, line) for p in patterns)
        deref_cache[key] = res
        return res

    def is_reassignement_of_var(self, line: str, var: str) -> bool:
        v = re.escape(var)
        return re.search(r"\b" + v + r"\s*=", line) is not None
    
    def has_null_check_for_var(self, lines: List[str], var: str) -> bool:
            v = re.escape(var)
            pat = re.compile(r"\b" + v + r"\s*(!=|==)\s*NULL\b")
            return any(pat.search(l) for l in lines)

    def detect_null_deref_v2(self, null_assigned_var_list) -> bool:
        if null_assigned_var_list is None:
            return None

        deref_patterns_cache = {}
        for var, idx in null_assigned_var_list:
            for j in range(idx + 1, len(self.lines)):
                line = self.lines[j]
                if self.is_comment_or_empty(line):
                    continue
                if self.is_reassignement_of_var(line, var):
                    break
                if self.has_deref_of_var(line, var, deref_patterns_cache):
                    return True
        return False

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
    
    def detect_use_after_free_v2(self, freed_var_list) -> bool:
        if freed_var_list is None:
            return None
        
        assign_pattern = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\b")
        for var, free_idx in freed_var_list:
            alias_set = {var}
            for j in range(free_idx + 1, len(self.lines)):
                line = self.lines[j]
                if self.is_comment_or_empty(line):
                    continue
                # Check for aliases
                for alias in list(alias_set):
                    m = assign_pattern.search(line)
                    if m:
                        left, right = m.group(1), m.group(2)
                        if right in alias_set:
                            alias_set.add(left)
                        
                # Check for deref of any alias
                for alias in list(alias_set):
                    if self.has_deref_of_var(line, alias, {}):
                        return True
        return False
