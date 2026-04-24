"""
Function String Associate Extra for IDA 9+
Rewritten using IDA Domain API (https://github.com/HexRaysSA/ida-domain)

Extracts strings from functions, generates #STR comments,
and renames auto-generated function names based on SEH handler strings.
"""

import re
import string
import time
import unicodedata

import idaapi
import ida_auto
import ida_kernwin

from PySide6 import QtWidgets

from ida_domain import Database
from ida_domain.operands import OperandType

MAX_LINE_STRING_COUNT = 10
MAX_LABEL_STRING = 60
MAX_COMMENT_SIZE = 764
MIN_STRING_SIZE = 4

PLUGIN_NAME = "Function String Associate Extra"
PLUGIN_HOTKEY = ""

g_replace_comments = False


def filter_whitespace(input_string: str) -> str:
    """Replaces all non-printable ASCII characters with a space and trims result."""
    return "".join(ch if " " <= ch <= "~" else " " for ch in input_string).strip()


def safe_func_name(name):
    clean = []
    for ch in name:
        if (
            ch.isalnum()
            or ch in ['_', ':', '~']
            or unicodedata.category(ch)[0] in {'L', 'N'}
        ):
            clean.append(ch)
        else:
            clean.append('_')
    return ''.join(clean)[:250]


def safe_comment_text(s):
    return s.replace('\x00', ' ').replace('\r', ' ')[:750]


def is_pretty_printable(s: str) -> bool:
    letters = sum(1 for ch in s if ch in string.ascii_letters + string.digits)
    printable = sum(1 for ch in s if ch in string.printable and ch not in '\t\r\n\x0b\x0c')
    length = len(s)
    if length == 0 or printable == 0:
        return False
    return letters >= 3 and (printable / length) > 0.7


def extract_function_strings(db, func) -> list:
    """Extract string references from function instructions using IDA Domain API."""
    if not func or func.size < 8:
        return []

    found_strings = []
    found_strings_set = set()
    seh_name_candidate = None
    seh_name_is_priority = False

    instructions = list(db.functions.get_instructions(func))
    string_xrefs = []

    for idx, insn in enumerate(instructions):
        mnem = db.instructions.get_mnemonic(insn)
        if mnem != "push":
            continue

        operand = db.instructions.get_operand(insn, 0)
        if operand is None or operand.type != OperandType.IMMEDIATE:
            continue

        val = operand.get_value()
        string_item = db.strings.get_at(val)
        if string_item is None:
            continue
        if string_item.length < MIN_STRING_SIZE:
            continue

        try:
            s_full = string_item.contents.decode("utf-8", errors="replace").split('\x00')[0]
        except Exception:
            continue

        filtered = filter_whitespace(s_full)
        if (len(filtered) < MIN_STRING_SIZE
                or filtered in found_strings_set
                or not is_pretty_printable(filtered)):
            continue

        string_xrefs.append((idx, filtered, val))
        found_strings.append([filtered, 1])
        found_strings_set.add(filtered)

    for instr_idx, string_val, val in string_xrefs:
        for look_ahead in range(1, 5):
            ahead_idx = instr_idx + look_ahead
            if ahead_idx >= len(instructions):
                break
            ahead_insn = instructions[ahead_idx]
            if db.instructions.is_call_instruction(ahead_insn):
                disasm = db.instructions.get_disassembly(ahead_insn) or ""
                if any(w in disasm.lower() for w in ["appunwindf", "throw", "seh", "uncaught"]):
                    if "::" in string_val and len(string_val) > 5:
                        seh_name_candidate = string_val
                        seh_name_is_priority = True
                        break
        if seh_name_is_priority:
            break

    if seh_name_is_priority:
        found_strings = [[seh_name_candidate, 1]] + [
            s for s in found_strings if s[0] != seh_name_candidate
        ]

    return found_strings


def generate_str_comment(function_strings: list) -> str:
    """Generate #STR comment text from a list of function strings."""
    if not function_strings:
        return ""
    seen = set()
    unique_strings = []
    for string_value, ref_count in function_strings:
        if string_value not in seen:
            seen.add(string_value)
            unique_strings.append(string_value)

    comment_text = "#STR: "
    first = True
    for string_value in unique_strings:
        required_size = len(string_value) + 2
        available_size = MAX_COMMENT_SIZE - len(comment_text) - 1
        if not first:
            required_size += 2
        if available_size < required_size:
            break
        if not first:
            comment_text += ", "
        comment_text += f"\"{string_value}\""
        first = False
    return comment_text


def update_function_comment(db, func, comment_text: str) -> None:
    """Set or append function comment using IDA Domain Functions API."""
    if not comment_text:
        return
    comment_text = safe_comment_text(comment_text)
    if not g_replace_comments:
        current_comment = (
            db.functions.get_comment(func, repeatable=True)
            or db.functions.get_comment(func, repeatable=False)
            or ""
        )
        if current_comment:
            combined_comment = current_comment + "\n" + comment_text
        else:
            combined_comment = comment_text
        db.functions.set_comment(func, combined_comment, repeatable=True)
    else:
        db.functions.set_comment(func, comment_text, repeatable=True)


def process_function_add_comments(db, func) -> bool:
    """Extract strings and add #STR comment to the function."""
    function_strings = extract_function_strings(db, func)
    if function_strings:
        comment_text = generate_str_comment(function_strings)
        update_function_comment(db, func, comment_text)
        return True
    return False


def is_valid_ida_func_name(function_name: str) -> bool:
    if len(function_name) > 128:
        return False
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$', function_name))


def extract_candidate_function_names(comment_text: str) -> list:
    """Extract potential function names (Class::Method patterns) from #STR comment."""
    if not comment_text:
        return []
    candidate_names = []
    str_comment_match = re.search(r'#STR:(.+)', comment_text)
    if str_comment_match:
        str_content = str_comment_match.group(1)
        quoted_strings = re.findall(r'"(.*?)"', str_content)
        for quoted_string in quoted_strings:
            if "::" in quoted_string and is_valid_ida_func_name(quoted_string.replace("~", "___")):
                candidate = quoted_string.replace("~", "___")
                candidate_names.append(candidate)
    return candidate_names


def is_autogen_func_name(function_name: str) -> bool:
    return re.fullmatch(r'(sub_|nullsub_)[0-9A-Fa-f]{6,}', function_name or "") is not None


def process_function_rename(db, func, rename_map=None, rename_counter=None) -> str:
    """
    Rename auto-generated function names based on #STR comment content.
    Uses IDA Domain Functions API for comments, naming, and collision detection.
    """
    comment_text = db.functions.get_comment(func, repeatable=True)
    if not comment_text:
        return 'none'
    candidate_names = extract_candidate_function_names(comment_text)
    if not candidate_names:
        return 'none'
    orig_name = candidate_names[0]
    if not orig_name:
        return 'none'
    orig_name = orig_name[:240]
    current_name = db.functions.get_name(func)
    if not is_autogen_func_name(current_name):
        return 'skip'

    if rename_map is not None and rename_counter is not None:
        count = rename_counter.get(orig_name, 0)
        postfix = "" if count == 0 else f"_{count}"
        new_name_try = safe_func_name(f"{orig_name}{postfix}")
        while db.functions.get_by_name(new_name_try) is not None or new_name_try in rename_map:
            count += 1
            new_name_try = safe_func_name(f"{orig_name}_{count}")
        rename_counter[orig_name] = count + 1
        rename_map[new_name_try] = func.start_ea
        if current_name == new_name_try:
            return 'none'
        if db.functions.set_name(func, new_name_try):
            return 'ok'
        else:
            return 'err'

    if len(candidate_names) > 1:
        return 'warn'
    new_name = orig_name
    if not new_name or new_name == current_name:
        return 'none'
    if db.functions.get_by_name(new_name) is not None:
        return 'warn'
    if db.functions.set_name(func, new_name):
        return 'ok'
    else:
        return 'err'


class ReplaceOrAppendDialog(QtWidgets.QDialog):
    def __init__(self, function_count, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Function String Associate")
        self.setModal(True)
        layout = QtWidgets.QVBoxLayout()
        label = QtWidgets.QLabel(
            f"This will process all {function_count} functions.\n\n"
            "If you choose REPLACE, existing function comments will be overwritten.\n"
            "If unchecked, the plugin will APPEND to existing comments.\n"
        )
        layout.addWidget(label)
        self.checkbox = QtWidgets.QCheckBox("Replace existing comments?")
        layout.addWidget(self.checkbox)
        button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        self.setLayout(layout)

    def should_replace(self):
        return self.checkbox.isChecked()


def show_qt_dialog(function_count):
    dialog = ReplaceOrAppendDialog(function_count)
    result = dialog.exec_()
    if result == QtWidgets.QDialog.Accepted:
        return dialog.should_replace()
    else:
        return None


class FunctionStringAssociatePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Extracts strings from functions as comments then renames via #STR"
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[{PLUGIN_NAME}] Plugin loaded.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if not ida_auto.auto_is_ok():
            ida_kernwin.warning("Please wait until auto-analysis completes!")
            return

        with Database.open() as db:
            all_functions = list(db.functions)
            user_choice = show_qt_dialog(len(all_functions))
            if user_choice is None:
                return

            global g_replace_comments
            g_replace_comments = user_choice
            comment_mode = "REPLACE" if g_replace_comments else "APPEND"
            print(f"[{PLUGIN_NAME}] Starting in {comment_mode} mode.")
            start_time = time.time()

            ida_kernwin.show_wait_box("Function String Associate: adding comments...")
            comment_count = 0
            for idx, func in enumerate(all_functions):
                if process_function_add_comments(db, func):
                    comment_count += 1
                if idx % 100 == 0:
                    ida_kernwin.replace_wait_box(
                        f"Processing comments: {idx + 1}/{len(all_functions)}"
                    )
                    if ida_kernwin.user_cancelled():
                        print("[INFO] Cancelled by user.")
                        ida_kernwin.hide_wait_box()
                        return

            rename_stats = dict(ok=0, warn=0, skip=0, err=0)
            ida_kernwin.replace_wait_box("Renaming functions...")
            rename_map = {}
            rename_counter = {}
            for idx, func in enumerate(all_functions):
                status = process_function_rename(
                    db, func, rename_map=rename_map, rename_counter=rename_counter
                )
                if status in rename_stats:
                    rename_stats[status] += 1
                if idx % 100 == 0:
                    ida_kernwin.replace_wait_box(
                        f"Renaming: {idx + 1}/{len(all_functions)}"
                    )
                    if ida_kernwin.user_cancelled():
                        print("[INFO] Cancelled by user.")
                        break

            ida_kernwin.hide_wait_box()
            elapsed = time.time() - start_time
            print(f"\n[{PLUGIN_NAME}]")
            print("--- Summary ---")
            print(f"Functions with new comments: {comment_count}")
            print(f"Renamed:                    {rename_stats['ok']}")
            print(f"Skipped (custom name):      {rename_stats['skip']}")
            print(f"Warnings:                   {rename_stats['warn']}")
            print(f"Errors:                     {rename_stats['err']}")
            print(f"Total time:                 {elapsed:.2f} sec")
            print("------------------------\n")

        idaapi.refresh_idaview_anyway()

    def term(self):
        print(f"[{PLUGIN_NAME}] Plugin exited.")


def PLUGIN_ENTRY():
    return FunctionStringAssociatePlugin()
