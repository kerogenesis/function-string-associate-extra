# -*- coding: utf-8 -*-

import re
import string as _string
import time
import unicodedata

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_kernwin
import ida_auto


# Configuration
PLUGIN_NAME = "Function String Associate Extra"
PLUGIN_HOTKEY = ""

MIN_STRING_SIZE = 4
MAX_STRING_SIZE = 512
MAX_COMMENT_SIZE = 764
MAX_LINE_STRING_COUNT = 10   # max strings placed into a single function comment
MAX_STRINGS_SCANNED = 64     # cap on distinct strings inspected per function
MIN_FUNC_SIZE = 8            # same as the original plugin: skip tiny thunks
MAX_FUNC_COMMENT = 2000

# Codecs tried for single-byte strings, in priority order.
ANSI_CODECS = ("utf-8", "cp1251", "cp1252", "cp949")

# Helpers whose call sites carry the function name. Matched as a substring
# against the demangled symbol name of the call target.
UNWIND_HELPERS = ("AppUnwindF", "AppUnwind", "AppMsg", "UnwindF")

# Collision handling: "index" -> Name, Name_1, Name_2 ...
#                    "addr"  -> Name, Name_401000, Name_402000 ...
SUFFIX_MODE = "index"

# MSVC FuncInfo signatures.
FUNCINFO_MAGIC = (0x19930520, 0x19930521, 0x19930522)

MAX_TRY_BLOCKS = 512
MAX_CATCHES = 256
MAX_HANDLER_INSNS = 256

# Confidence scores for competing name sources.
CONF_SEH = 100      # name taken from a catch handler (structural walk)
CONF_CALLSITE = 60  # string pushed right before a call to an unwind helper
CONF_STRING = 20    # plain name-shaped string somewhere inside the function

# Compatibility layer (avoids deprecated APIs)
_GET_CMT_EA = getattr(ida_funcs, "get_func_cmt_ea", None)
_SET_CMT_EA = getattr(ida_funcs, "set_func_cmt_ea", None)
_GET_FUNC_START = getattr(ida_funcs, "get_func_start", None)


def func_start(ea):
    """Start of the function containing ea, or BADADDR."""
    if _GET_FUNC_START is not None:
        try:
            return _GET_FUNC_START(ea)
        except Exception:
            pass
    return idc.get_func_attr(ea, idc.FUNCATTR_START)


def func_size(func_ea):
    start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
    end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    if start == idc.BADADDR or end == idc.BADADDR or end <= start:
        return 0
    return end - start


def is_inside_function(ea):
    return func_start(ea) != idc.BADADDR


def get_func_comment(func_ea, repeatable=True):
    try:
        if _GET_CMT_EA is not None:
            return _GET_CMT_EA(func_ea, repeatable) or ""
        return idc.get_func_cmt(func_ea, repeatable) or ""
    except Exception:
        return ""


def set_func_comment(func_ea, text, repeatable=True):
    try:
        if _SET_CMT_EA is not None:
            return bool(_SET_CMT_EA(func_ea, text, repeatable))
        return bool(idc.set_func_cmt(func_ea, text, repeatable))
    except Exception:
        return False


def get_function_name(func_ea):
    """Raw (still mangled) name as stored in the database."""
    return idc.get_func_name(func_ea) or ""



# String reading

_STR_CACHE = {}


def _is_loaded(ea):
    return ea not in (None, 0, idc.BADADDR) and ida_bytes.is_loaded(ea)


def is_string_target(ea):
    """Reject addresses that cannot hold a string literal.

    This is the main defense against garbage: immediates that are really code
    addresses, sizes or flags never reach the decoder.
    """
    if not _is_loaded(ea):
        return False
    if ida_bytes.is_code(ida_bytes.get_flags(ea)):
        return False
    if is_inside_function(ea):
        return False
    return True


def _decode_literal(raw):
    """Decode literal bytes returned by IDA.

    For 16-bit literals IDA may hand back raw UTF-16LE bytes; without this
    check "MOVE" would end up as "M O V E" after whitespace filtering.
    """
    if not isinstance(raw, bytes):
        return str(raw)
    if b"\x00" in raw:
        try:
            txt = raw.decode("utf-16le", errors="ignore").rstrip("\x00")
            if txt:
                return txt
        except Exception:
            pass
    return raw.decode("utf-8", errors="ignore")


def read_utf16_string(ea, max_chars=MAX_STRING_SIZE):
    if not _is_loaded(ea):
        return None
    out = bytearray()
    cur = ea
    for _ in range(max_chars):
        chunk = ida_bytes.get_bytes(cur, 2)
        if not chunk or len(chunk) != 2:
            return None
        if chunk == b"\x00\x00":
            try:
                return out.decode("utf-16le")
            except UnicodeDecodeError:
                return None
        out += chunk
        cur += 2
    return None


def read_ansi_string(ea, max_chars=MAX_STRING_SIZE):
    """Read a NUL-terminated single-byte string, trying each codec in turn."""
    if not _is_loaded(ea):
        return None
    out = bytearray()
    cur = ea
    terminated = False
    for _ in range(max_chars):
        b = ida_bytes.get_bytes(cur, 1)
        if not b:
            break
        if b == b"\x00":
            terminated = True
            break
        out += b
        cur += 1
    # An unterminated run is almost always binary noise, not a string.
    if not terminated or not out:
        return None
    for codec in ANSI_CODECS:
        try:
            return out.decode(codec)
        except UnicodeDecodeError:
            continue
    return None


def read_any_string(ea):
    """Return (text, from_literal).

    from_literal is True when IDA itself has the address marked as a string
    literal. Such strings are trusted like in the original plugin; raw reads are
    validated by is_comment_worthy() instead.
    """
    cached = _STR_CACHE.get(ea)
    if cached is not None:
        return cached

    result = (None, False)
    if _is_loaded(ea):
        flags = ida_bytes.get_flags(ea)
        # Only ask IDA about literals it already defined, otherwise the kernel
        # may attempt an item conversion and fail with "MakeData".
        if ida_bytes.is_strlit(flags):
            try:
                st = idc.get_str_type(ea)
                if st is not None and st != -1:
                    raw = ida_bytes.get_strlit_contents(ea, -1, st)
                    if raw:
                        txt = _decode_literal(raw)
                        if txt and len(txt) >= MIN_STRING_SIZE:
                            result = (txt, True)
            except Exception:
                pass

        if result[0] is None:
            w = read_utf16_string(ea)
            a = read_ansi_string(ea)

            def score(s):
                if not s or len(s) < MIN_STRING_SIZE:
                    return -1
                printable = sum(1 for ch in s if ch.isprintable())
                return printable * 2 - (len(s) - printable) * 4

            sw, sa = score(w), score(a)
            if sw > 0 or sa > 0:
                result = ((w, False) if sw >= sa else (a, False))

    if len(_STR_CACHE) < 200000:
        _STR_CACHE[ea] = result
    return result


# Quality filters and name normalization
def filter_whitespace(s):
    return "".join(ch if " " <= ch <= "~" else " " for ch in s).strip()


def is_pretty_printable(s):
    letters = sum(1 for ch in s if ch in _string.ascii_letters + _string.digits)
    printable = sum(1 for ch in s if ch in _string.printable and ch not in "\t\r\n\x0b\x0c")
    if not s or printable == 0:
        return False
    return letters >= 3 and (printable / len(s)) > 0.7


_REPEAT_RE = re.compile(r"(.)\1{6,}")
_HEX_JUNK_RE = re.compile(r"[0-9A-Fa-f ]{8,}")
_ALLOWED_PUNCT = set(" _.:/\\-%()[]{}'\"!?,;=+*<>#@&|$^~`")


def is_comment_worthy(text, from_literal):
    """Decide whether a string may enter a function comment.

    IDA literals follow the original plugin's rules. Raw reads are checked much
    harder, since arbitrary bytes can decode into plausible-looking text.
    """
    if not text or len(text) < MIN_STRING_SIZE or len(text) > MAX_STRING_SIZE:
        return False
    if not is_pretty_printable(text):
        return False
    if from_literal:
        return True

    good = sum(1 for ch in text if ch.isalnum() or ch in _ALLOWED_PUNCT)
    if good / len(text) < 0.95:
        return False
    letters = sum(1 for ch in text if ch.isalpha())
    if letters < max(3, len(text) // 4):
        return False
    if _REPEAT_RE.search(text):          # runs like "aaaaaaaa"
        return False
    if _HEX_JUNK_RE.fullmatch(text):     # pure hex dumps
        return False
    return True


# Matches Foo, Foo::Bar, Foo::Bar::Baz, Foo::~Bar
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::~?[A-Za-z_][A-Za-z0-9_]*)*$")


def looks_like_func_name(s):
    if not s or len(s) > 200:
        return False
    s = s.strip()
    if " " in s or "%" in s:
        return False
    return bool(_NAME_RE.match(s))


def sanitize_name(name):
    """Turn a raw name into something IDA accepts, keeping :: and mapping ~."""
    name = name.strip().replace("~", "dtor_")
    clean = []
    for ch in name:
        if ch.isalnum() or ch in ("_", ":") or unicodedata.category(ch)[0] in ("L", "N"):
            clean.append(ch)
        else:
            clean.append("_")
    out = "".join(clean)[:200]
    out = re.sub(r"_{3,}", "__", out)
    try:
        validated = ida_name.validate_name(out, ida_name.VNT_IDENT, ida_name.SN_NOCHECK)
    except Exception:
        validated = out
    return validated or out


# Only these names are considered free to overwrite. Real symbols, including
# mangled ones and manual renames, are always preserved.
AUTOGEN_RE = re.compile(r"^(j_)?(sub|nullsub|unknown_libname|loc)_[0-9A-Fa-f]{3,}$")


def is_autogen_func_name(name):
    return bool(AUTOGEN_RE.match(name or ""))



# Instruction helpers

def mnem(ea):
    return (idc.print_insn_mnem(ea) or "").lower()


def is_push_imm(ea):
    return mnem(ea) == "push" and idc.get_operand_type(ea, 0) == idc.o_imm


def is_call(ea):
    return mnem(ea) == "call"


def call_target_name(ea):
    """Names of a call target, including the import-table indirection."""
    if not is_call(ea):
        return ""
    otype = idc.get_operand_type(ea, 0)
    target = idc.get_operand_value(ea, 0)
    names = []
    if otype in (idc.o_near, idc.o_far, idc.o_mem, idc.o_imm):
        indirect = ida_bytes.get_dword(target) if (otype == idc.o_mem and _is_loaded(target)) else None
        for cand in (target, indirect):
            if cand in (None, 0, idc.BADADDR):
                continue
            raw = ida_name.get_name(cand) or ""
            if raw:
                names.append(raw)
                try:
                    dem = idc.demangle_name(raw, idc.get_inf_attr(idc.INF_SHORT_DN)) or ""
                except Exception:
                    dem = ""
                if dem:
                    names.append(dem)
    if not names:
        names.append(idc.GetDisasm(ea) or "")
    return " | ".join(names)


def is_unwind_helper_call(ea):
    if not is_call(ea):
        return False
    text = call_target_name(ea).lower()
    return any(h.lower() in text for h in UNWIND_HELPERS)


def func_heads(func_ea):
    """All instructions of a function, including tail chunks."""
    try:
        return list(idautils.FuncItems(func_ea))
    except Exception:
        return list(idautils.Heads(func_ea, idc.find_func_end(func_ea)))



# Source 1: structural MSVC C++ EH walk

def find_funcinfo_ea(heads):
    """Locate the FuncInfo structure of a function.

    Matches the classic SEH prologue:
        push 0FFFFFFFFh
        push <seh_handler>
        mov  eax, large fs:0
        push eax
        mov  large fs:0, esp
    then reads FuncInfo out of 'mov eax, <FuncInfo>' in the handler trampoline.
    """
    for head in heads:
        if not (mnem(head) == "push"
                and idc.get_operand_type(head, 0) == idc.o_imm
                and idc.get_operand_value(head, 0) in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, -1)):
            continue
        h1 = idc.next_head(head)
        if mnem(h1) != "push":
            continue
        seh_ea = idc.get_operand_value(h1, 0)
        h2 = idc.next_head(h1)
        if not (mnem(h2) == "mov"
                and idc.get_operand_type(h2, 0) == idc.o_reg
                and idc.get_operand_value(h2, 0) == 0
                and idc.get_operand_type(h2, 1) == idc.o_mem
                and idc.get_operand_value(h2, 1) == 0):
            continue
        h3 = idc.next_head(h2)
        if not (mnem(h3) == "push"
                and idc.get_operand_type(h3, 0) == idc.o_reg
                and idc.get_operand_value(h3, 0) == 0):
            continue
        h4 = idc.next_head(h3)
        if not (mnem(h4) == "mov"
                and idc.get_operand_type(h4, 0) == idc.o_mem
                and idc.get_operand_value(h4, 0) == 0
                and idc.get_operand_type(h4, 1) == idc.o_reg
                and idc.get_operand_value(h4, 1) == 4):
            continue
        if not _is_loaded(seh_ea):
            continue
        if (mnem(seh_ea) == "mov"
                and idc.get_operand_type(seh_ea, 0) == idc.o_reg
                and idc.get_operand_value(seh_ea, 0) == 0
                and idc.get_operand_type(seh_ea, 1) == idc.o_imm):
            return idc.get_operand_value(seh_ea, 1)
    return None


def iter_catch_handlers(funcinfo_ea):
    """Yield catch handler addresses.

    Layout walked here:
        FuncInfo:           magic(+0x0) nTryBlocks(+0xC) pTryBlockMap(+0x10)
        TryBlockMapEntry:   size 0x14, nCatches(+0xC) pHandlerArray(+0x10)
        HandlerType:        size 0x10, addressOfHandler(+0xC)
    """
    if not _is_loaded(funcinfo_ea):
        return
    if ida_bytes.get_dword(funcinfo_ea) not in FUNCINFO_MAGIC:
        return
    try_count = ida_bytes.get_dword(funcinfo_ea + 0x0C)
    if not (0 < try_count <= MAX_TRY_BLOCKS):
        return
    try_map_ea = ida_bytes.get_dword(funcinfo_ea + 0x10)
    if not _is_loaded(try_map_ea):
        return
    for i in range(try_count):
        tb = try_map_ea + i * 0x14
        if not _is_loaded(tb):
            continue
        catches = ida_bytes.get_dword(tb + 0x0C)
        if not (0 < catches <= MAX_CATCHES):
            continue
        harr = ida_bytes.get_dword(tb + 0x10)
        if not _is_loaded(harr):
            continue
        for j in range(catches):
            hd = harr + j * 0x10
            if not _is_loaded(hd):
                continue
            handler_ea = ida_bytes.get_dword(hd + 0x0C)
            if _is_loaded(handler_ea):
                yield handler_ea


def name_from_handler(handler_ea):
    """Scan a catch handler for 'push A; push B; call <AppUnwindF>' and return
    whichever argument reads back as a function name."""
    end = idc.find_func_end(handler_ea)
    if end in (None, idc.BADADDR) or end <= handler_ea:
        end = handler_ea + 0x800

    ea = handler_ea
    prev_pushes = []
    for _ in range(MAX_HANDLER_INSNS):
        if ea in (None, idc.BADADDR) or ea >= end:
            break
        if is_push_imm(ea):
            prev_pushes.append(idc.get_operand_value(ea, 0))
            if len(prev_pushes) > 4:
                prev_pushes.pop(0)
        elif is_call(ea):
            helper = is_unwind_helper_call(ea)
            # Arguments are pushed right-to-left, so scan the newest first.
            for val in reversed(prev_pushes):
                text, _from_literal = read_any_string(val)
                if not text:
                    continue
                text = filter_whitespace(text)
                if looks_like_func_name(text) and len(text) >= MIN_STRING_SIZE:
                    return text, (CONF_SEH if helper else CONF_SEH - 20)
            prev_pushes = []
        elif mnem(ea) in ("retn", "ret", "jmp"):
            prev_pushes = []
        ea = idc.next_head(ea, end)
    return None, 0


def seh_name_for_function(heads):
    funcinfo_ea = find_funcinfo_ea(heads)
    if not funcinfo_ea:
        return None, 0
    best, best_conf = None, 0
    for handler_ea in iter_catch_handlers(funcinfo_ea):
        name, conf = name_from_handler(handler_ea)
        if name and conf > best_conf:
            best, best_conf = name, conf
            if conf >= CONF_SEH:
                break
    return best, best_conf


# Source 2: strings referenced by the function

def collect_function_strings(heads):
    """Collect strings referenced from a function.

    Reference sources:
      * XREF_DATA from any instruction (mov / lea / push / cmp / ...), as in the
        original plugin;
      * push imm, to catch constants IDA does not treat as offsets - a large
        share of the UTF-16 strings in game clients arrive this way.

    Returns ([[text, ref_count], ...], name_candidate, confidence). The list is
    sorted by reference count descending and truncated to MAX_LINE_STRING_COUNT,
    so the comment holds the most characteristic strings rather than whichever
    ten happened to come first.
    """
    counts = {}
    order = []
    cand_name, cand_conf = None, 0

    for i, ea in enumerate(heads):
        targets = []
        try:
            for xref in idautils.XrefsFrom(ea, idaapi.XREF_DATA):
                targets.append(xref.to)
        except Exception:
            pass
        if is_push_imm(ea):
            targets.append(idc.get_operand_value(ea, 0))

        for val in targets:
            if not is_string_target(val):
                continue
            text, from_literal = read_any_string(val)
            if not text:
                continue
            text = filter_whitespace(text)
            if not is_comment_worthy(text, from_literal):
                continue

            if text in counts:
                counts[text] += 1
            elif len(order) < MAX_STRINGS_SCANNED:
                counts[text] = 1
                order.append(text)

            # The name candidate is searched across the whole function; the
            # comment limit must not hide a name that appears late.
            if looks_like_func_name(text):
                near_helper = any(
                    is_unwind_helper_call(heads[j])
                    for j in range(i + 1, min(i + 6, len(heads)))
                )
                conf = CONF_CALLSITE if near_helper else CONF_STRING
                if "::" in text:
                    conf += 5
                if conf > cand_conf:
                    cand_name, cand_conf = text, conf

    # sorted() is stable, so equally referenced strings keep code order.
    strings = sorted(([s, counts[s]] for s in order), key=lambda x: x[1], reverse=True)
    return strings[:MAX_LINE_STRING_COUNT], cand_name, cand_conf


def build_comment(strings):
    """Format [[text, refs], ...] into a '#STR: "a", "b"' comment."""
    if not strings:
        return ""
    out = "#STR: "
    first = True
    for text, _refs in strings:
        need = len(text) + 2 + (0 if first else 2)
        if MAX_COMMENT_SIZE - len(out) - 1 < need:
            break
        out += ("" if first else ", ") + '"%s"' % text
        first = False
    return "" if first else out


# Rename planner

def collect_reserved_names(rename_eas):
    """Every name already in the database except the ones we are replacing."""
    reserved = set()
    for ea, name in idautils.Names():
        if ea in rename_eas:
            continue
        reserved.add(name)
    return reserved


def plan_renames(candidates):
    """Map {func_ea: (raw_name, confidence)} to {func_ea: final_name}.

    A base name is used bare when a single function claims it, otherwise the
    suffix scheme from SUFFIX_MODE applies. Ordering is by address, so repeated
    runs produce identical names instead of shuffling suffixes around.
    """
    by_base = {}
    for ea in sorted(candidates):
        raw, conf = candidates[ea]
        base = sanitize_name(raw)
        if not base:
            continue
        by_base.setdefault(base, []).append((ea, conf))

    reserved = collect_reserved_names(set(candidates))
    plan = {}
    used = set()
    for base, items in by_base.items():
        items.sort(key=lambda t: t[0])
        single = len(items) == 1
        for idx, (ea, _conf) in enumerate(items):
            if single and base not in reserved and base not in used:
                final = base
            elif SUFFIX_MODE == "addr":
                final = "%s_%X" % (base, ea)
            else:
                if idx == 0 and base not in reserved and base not in used:
                    final = base
                else:
                    n = max(idx, 1)
                    final = "%s_%d" % (base, n)
                    while final in reserved or final in used:
                        n += 1
                        final = "%s_%d" % (base, n)
            while final in reserved or final in used:
                final += "_"
            used.add(final)
            plan[ea] = final
    return plan


# Reporting
def print_report(rows, title=PLUGIN_NAME):
    width = 62
    print("")
    print("=" * width)
    print(" %s ~ summary ~" % title)
    print("-" * width)
    label_w = max(len(label) for label, _ in rows)
    for label, value in rows:
        print("  %-*s  %12s" % (label_w, label, value))
    print("=" * width)
    print("")


# Main pass
def run(add_comments=True, replace_comments=False, rename=True, min_confidence=CONF_STRING,
        verbose=True):
    t0 = time.time()
    _STR_CACHE.clear()

    funcs = list(idautils.Functions())
    total = len(funcs)

    candidates = {}
    commented = 0
    seh_hits = 0
    skipped_small = 0
    named_already = 0
    renamed = 0
    failed = 0
    cancelled = False

    ida_kernwin.show_wait_box("%s: analyzing..." % PLUGIN_NAME)
    try:
        for i, func_ea in enumerate(funcs):
            if i % 100 == 0:
                ida_kernwin.replace_wait_box("Analyzing %d/%d" % (i + 1, total))
                if ida_kernwin.user_cancelled():
                    cancelled = True
                    break

            if func_size(func_ea) < MIN_FUNC_SIZE:
                skipped_small += 1
                continue

            cur_name = get_function_name(func_ea)
            # Renaming touches auto-generated names only, but commenting applies
            # to every function - mangled symbols included.
            want_rename = rename and is_autogen_func_name(cur_name)
            if not want_rename and not cur_name.startswith("sub_"):
                named_already += 1

            heads = func_heads(func_ea)
            if not heads:
                continue

            strings, str_name, str_conf = collect_function_strings(heads)

            if add_comments and strings:
                cmt = build_comment(strings)
                if cmt:
                    old = get_func_comment(func_ea, True)
                    if replace_comments or not old:
                        new_cmt = cmt
                    elif cmt in old:
                        new_cmt = old          # idempotent on repeated runs
                    else:
                        new_cmt = old + "\n" + cmt
                    if new_cmt != old and set_func_comment(func_ea, new_cmt[:MAX_FUNC_COMMENT], True):
                        commented += 1

            if not want_rename:
                continue

            # The EH walk is comparatively expensive, so run it only for
            # functions that can actually be renamed.
            seh_name, seh_conf = seh_name_for_function(heads)
            if seh_name:
                seh_hits += 1

            best_name, best_conf = None, 0
            for nm, cf in ((seh_name, seh_conf), (str_name, str_conf)):
                if nm and cf > best_conf:
                    best_name, best_conf = nm, cf

            if best_name and best_conf >= min_confidence:
                candidates[func_ea] = (best_name, best_conf)

        if rename and not cancelled:
            ida_kernwin.replace_wait_box("Planning names...")
            plan = plan_renames(candidates)

            for i, (ea, name) in enumerate(sorted(plan.items())):
                if i % 200 == 0:
                    ida_kernwin.replace_wait_box("Renaming %d/%d" % (i + 1, len(plan)))
                    if ida_kernwin.user_cancelled():
                        cancelled = True
                        break
                old = get_function_name(ea)
                if old == name:
                    continue
                try:
                    done = ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                except Exception:
                    done = False
                if done:
                    renamed += 1
                    if verbose:
                        print("  %s -> %s" % (old, name))
                else:
                    failed += 1
                    print("  [!] rename failed: %s -> %s" % (old, name))
    finally:
        ida_kernwin.hide_wait_box()

    if cancelled:
        print("[%s] Cancelled by user." % PLUGIN_NAME)

    print_report([
        ("Functions total", total),
        ("Skipped (< %d bytes)" % MIN_FUNC_SIZE, skipped_small),
        ("Already named (rename skipped)", named_already),
        ("#STR comments written", commented),
        ("Names from catch/SEH", seh_hits),
        ("Rename candidates", len(candidates)),
        ("Renamed", renamed),
        ("Failed", failed),
        ("Elapsed", "%.2f s" % (time.time() - t0)),
    ])
    idaapi.refresh_idaview_anyway()


# Plugin wrapper

class FunctionStringAssociateExtraPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Extracts strings into #STR comments and renames functions via SEH/catch data"
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print("[%s] Plugin loaded." % PLUGIN_NAME)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if not ida_auto.auto_is_ok():
            ida_kernwin.warning("Please wait until auto-analysis completes!")
            return
        answer = ida_kernwin.ask_yn(
            0,
            "Replace existing function comments?\n\n"
            "Yes - overwrite existing comments\n"
            "No  - append to existing comments",
        )
        if answer == -1:
            return
        print("[%s] Starting in %s mode." % (PLUGIN_NAME, "REPLACE" if answer else "APPEND"))
        run(add_comments=True, replace_comments=bool(answer), rename=True)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return FunctionStringAssociateExtraPlugin()


if __name__ == "__main__":
    # Allows running as a plain script: File > Script file...
    run(add_comments=True, replace_comments=False, rename=True)
