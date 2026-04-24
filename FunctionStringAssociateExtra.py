import idc
import idaapi
import ida_ua
import idautils
import ida_bytes
import ida_funcs
import ida_auto
import ida_kernwin

import re
import string
import time
import unicodedata

from PySide6 import QtWidgets


try:
    import ida_nalt
except ImportError:
    class ida_nalt:
        STRTYPE_C = 0        # 1 bite ASCII/UTF-8
        STRTYPE_C_16 = 1     # 2 bites UTF-16LE
        STRTYPE_C_32 = 2     # 4 bites UTF-32LE

MAX_LINE_STRING_COUNT = 10
MAX_LABEL_STRING = 60
MAX_COMMENT_SIZE = 764
MIN_STRING_SIZE = 4

PLUGIN_NAME = "Function String Associate Extra"
PLUGIN_HOTKEY = ""

g_replace_comments = False

def filter_whitespace(input_string: str) -> str:
    """
    Replaces all non-printable ASCII characters with a space and trims result.
    """
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
    l = len(s)
    if l == 0 or printable == 0:
        return False
    return letters >= 3 and (printable / l) > 0.7

def is_pretty_printable(s: str) -> bool:
    letters = sum(1 for ch in s if ch in string.ascii_letters + string.digits)
    printable = sum(1 for ch in s if ch in string.printable and ch not in '\t\r\n\x0b\x0c')
    l = len(s)
    if l == 0 or printable == 0:
        return False
    return letters >= 3 and (printable / l) > 0.7

def extract_function_strings(function_start_ea: int) -> list:
    function = ida_funcs.get_func(function_start_ea)
    if not function or function.size() < 8:
        return []

    found_strings = []
    found_strings_set = set()
    seh_name_candidate = None
    seh_name_is_priority = False

    instr_addrs = list(idautils.FuncItems(function_start_ea))
    string_xrefs = []
    for idx, item_ea in enumerate(instr_addrs):
        mnem = idc.print_insn_mnem(item_ea)
        if mnem == "push":
            op_val = idc.get_operand_type(item_ea, 0)
            if op_val == idc.o_imm:
                val = idc.get_operand_value(item_ea, 0)
                if hasattr(ida_bytes, "get_str_type"):
                    str_type = ida_bytes.get_str_type(val)
                else:
                    str_type = idc.get_str_type(val)
                if str_type is None:
                    continue
                max_len = ida_bytes.get_max_strlit_length(val, str_type)
                if not max_len or max_len < MIN_STRING_SIZE:
                    continue
                raw_string_bytes = ida_bytes.get_strlit_contents(val, max_len, str_type)
                if not raw_string_bytes:
                    continue
                try:
                    if str_type == getattr(ida_nalt, "STRTYPE_C_16", 1):
                        s_full = raw_string_bytes.decode("utf-16le", errors="replace").split('\x00')[0]
                    elif str_type == getattr(ida_nalt, "STRTYPE_C_32", 2):
                        s_full = raw_string_bytes.decode("utf-32le", errors="replace").split('\x00')[0]
                    else:
                        s_full = raw_string_bytes.decode("ascii", errors="replace").split('\x00')[0]
                except Exception:
                    continue
                filtered = filter_whitespace(s_full)
                if (len(filtered) < MIN_STRING_SIZE or
                    filtered in found_strings_set or
                    not is_pretty_printable(filtered)):
                    continue
                string_xrefs.append((item_ea, filtered, val))
                found_strings.append([filtered, 1])
                found_strings_set.add(filtered)

    for idx, (item_ea, string_val, val) in enumerate(string_xrefs):
        for look_ahead in range(1, 5):
            ahead_idx = idx + look_ahead
            if ahead_idx >= len(instr_addrs):
                break
            ea2 = instr_addrs[ahead_idx]
            mnem2 = idc.print_insn_mnem(ea2)
            op2 = idc.print_operand(ea2, 0)
            full_line = idc.GetDisasm(ea2)
            if mnem2 == "call":
                op_call = op2.lower()
                if any(w in op_call for w in ["appunwindf", "throw", "seh", "uncaught"]):
                    if "::" in string_val and len(string_val) > 5:
                        seh_name_candidate = string_val
                        seh_name_is_priority = True
                        break
        if seh_name_is_priority:
            break

    if seh_name_is_priority:
        found_strings = [[seh_name_candidate, 1]] + [s for s in found_strings if s[0] != seh_name_candidate]

    return found_strings


def generate_str_comment(function_strings: list) -> str:
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

def update_function_comment(function_ea: int, comment_text: str) -> None:
    if not comment_text:
        return
    comment_text = safe_comment_text(comment_text)
    if not g_replace_comments:
        current_comment = idc.get_func_cmt(function_ea, repeatable=True) \
            or idc.get_func_cmt(function_ea, repeatable=False) or ""
        if current_comment:
            combined_comment = current_comment + "\n" + comment_text
        else:
            combined_comment = comment_text
        idc.set_func_cmt(function_ea, combined_comment, repeatable=True)
    else:
        idc.set_func_cmt(function_ea, comment_text, repeatable=True)

def process_function_add_comments(function_ea: int) -> bool:
    function_strings = extract_function_strings(function_ea)
    if function_strings:
        comment_text = generate_str_comment(function_strings)
        update_function_comment(function_ea, comment_text)
        return True
    return False

def is_valid_ida_func_name(function_name: str) -> bool:
    if len(function_name) > 128:
        return False
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$', function_name))

def extract_candidate_function_names(comment_text: str) -> list:
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

def process_function_rename(function_ea: int, rename_map=None, rename_counter=None) -> str:
    comment_text = idc.get_func_cmt(function_ea, 1)
    if not comment_text:
        return 'none'
    candidate_names = extract_candidate_function_names(comment_text)
    if not candidate_names:
        return 'none'
    orig_name = candidate_names[0]
    if not orig_name:
        return 'none'
    orig_name = orig_name[:240]
    current_name = idc.get_func_name(function_ea)
    if not is_autogen_func_name(current_name):
        return 'skip'

    if rename_map is not None and rename_counter is not None:
        count = rename_counter.get(orig_name, 0)
        postfix = "" if count == 0 else f"_{count}"
        new_name_try = f"{orig_name}{postfix}"
        new_name_try = safe_func_name(new_name_try)
        while idc.get_name_ea_simple(new_name_try) != idc.BADADDR or new_name_try in rename_map:
            count += 1
            new_name_try = f"{orig_name}_{count}"
            new_name_try = safe_func_name(new_name_try)
        rename_counter[orig_name] = count + 1
        rename_map[new_name_try] = function_ea
        if current_name == new_name_try:
            return 'none'
        if idc.set_name(function_ea, new_name_try, idc.SN_NOWARN):
            return 'ok'
        else:
            return 'err'

    if len(candidate_names) > 1:
        return 'warn'
    new_name = orig_name
    if not new_name or new_name == current_name:
        return 'none'
    if idc.get_name_ea_simple(new_name) != idc.BADADDR:
        return 'warn'
    if idc.set_name(function_ea, new_name, idc.SN_NOWARN):
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
        all_functions = list(idautils.Functions())
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
        for idx, func_ea in enumerate(all_functions):
            if process_function_add_comments(func_ea):
                comment_count += 1
            if idx % 100 == 0:
                ida_kernwin.replace_wait_box(f"Processing comments: {idx+1}/{len(all_functions)}")
                if ida_kernwin.user_cancelled():
                    print("[INFO] Cancelled by user.")
                    ida_kernwin.hide_wait_box()
                    return

        rename_stats = dict(ok=0, warn=0, skip=0, err=0)
        ida_kernwin.replace_wait_box("Renaming functions...")
        rename_map = {}     # function_name -> function_ea
        rename_counter = {} # function_name -> count
        for idx, func_ea in enumerate(all_functions):
            status = process_function_rename(func_ea, rename_map=rename_map, rename_counter=rename_counter)
            if status in rename_stats:
                rename_stats[status] += 1
            if idx % 100 == 0:
                ida_kernwin.replace_wait_box(f"Renaming: {idx+1}/{len(all_functions)}")
                if ida_kernwin.user_cancelled():
                    print("[INFO] Cancelled by user.")
                    break
        ida_kernwin.hide_wait_box()
        elapsed = time.time() - start_time
        print(f"\n[{PLUGIN_NAME}]")
        print(f"--- Summary ---")
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
