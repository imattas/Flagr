"""
Python pickle deserialization analyzer.

This unit detects serialized Python pickle data and safely analyzes it
for potential deserialization vulnerabilities. It decodes the pickle
without executing dangerous operations.

Common in Python web CTF challenges involving insecure deserialization.
"""

import io
import pickle
import pickletools
from typing import Any

from flagr.unit import FileUnit, NotApplicable


class SafeUnpickler(pickle.Unpickler):
    """Restricted unpickler that blocks dangerous operations."""

    SAFE_MODULES = {
        "builtins": {"str", "int", "float", "bool", "bytes", "list", "dict",
                     "set", "tuple", "frozenset", "True", "False", "None"},
        "collections": {"OrderedDict", "defaultdict"},
    }

    def find_class(self, module, name):
        if module in self.SAFE_MODULES and name in self.SAFE_MODULES[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Blocked: {module}.{name}"
        )


class Unit(FileUnit):

    GROUPS = ["misc", "forensics", "pickle", "deserialization"]
    PRIORITY = 30
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs, keywords=["Python"])

    def evaluate(self, case: Any):
        """Analyze pickle data safely."""
        try:
            data = self.target.raw
            if isinstance(data, str):
                data = data.encode()

            # Disassemble the pickle to see operations
            output = io.StringIO()
            try:
                pickletools.dis(io.BytesIO(data), output)
                disasm = output.getvalue()
            except Exception:
                disasm = "(could not disassemble)"

            # Check for dangerous operations in the pickle stream
            dangerous_ops = []
            for line in disasm.split("\n"):
                for dangerous in ["GLOBAL", "INST", "REDUCE", "__reduce__",
                                  "os.", "subprocess.", "exec", "eval",
                                  "system", "__import__"]:
                    if dangerous in line:
                        dangerous_ops.append(line.strip())

            lines = ["=== Pickle Data Analysis ==="]

            if dangerous_ops:
                lines.append("  [!] DANGEROUS OPERATIONS DETECTED:")
                for op in dangerous_ops[:10]:
                    lines.append(f"    {op}")
                lines.append("  This pickle contains code execution!")

            # Try safe unpickling
            try:
                obj = SafeUnpickler(io.BytesIO(data)).load()
                lines.append(f"  Safe data: {str(obj)[:500]}")
            except pickle.UnpicklingError as e:
                lines.append(f"  Unsafe pickle: {e}")
            except Exception:
                lines.append("  Could not safely unpickle")

            # Include disassembly summary
            lines.append(f"\n  Pickle opcodes:\n{disasm[:1000]}")

            result = "\n".join(lines)
            self.manager.register_data(self, result)

        except Exception:
            pass
