# corewait show OUT [--top N] [--causes] [--fn SYMBOL] [--k K] [--bytes B --bw GBPS]   diff OUT_A OUT_B [--top N]   budget OUT FILE
# Joins OUT/samples.tsv to OUT/objdump.txt by address: one row per instruction, with a cause on each row.
#   skid rule: a sample lands up to K instructions after its cause, so the cycles and memory (or branch-miss) events of a
#   row go to the nearest preceding load (branch) in the same function; --k 0 turns the rule off.
#   causes, first match wins: mem (memory event charged), branch, dep (the row, or the one before it, reads a register one of
#   the 3 rows before it wrote), fe (front-end event), busy (the rest).
from std.collections import Dict
from std.os import getenv, stat
from std.os.path import exists
from std.sys import argv, exit

comptime NC = 5
comptime MIN_SAMPLES = 10  # fewer samples of an event on a row are noise: no cause, no skid
comptime ROW_CAP = 4096  # an instruction line is kept to its first bytes: a branch row names its target's whole mangled symbol (1.4 MB each)
comptime ALIGN_CELLS = 40000000  # diff: a function pair above this many cells is aligned in linear memory (CW_ALIGN_CELLS overrides)


def fail(step: String, reason: String):
    print("FAIL " + step + ": " + reason)
    exit(1)


def lpad(s: String, w: Int) -> String:
    return " " * max(0, w - s.byte_length()) + s


def rpad(s: String, w: Int) -> String:
    return s + " " * max(0, w - s.byte_length())


def pct(a: Int, b: Int) -> String:
    var t = (a * 1000 + b // 2) // b if b > 0 else 0
    return String(t // 10) + "." + String(t % 10) + "%"


def hexs(a: Int) -> String:
    var s = String("")
    var v = a
    while True:
        s = String("0123456789abcdef"[byte = v & 15]) + s
        v >>= 4
        if v == 0:
            return s


def hex_digit(c: UInt8) -> Int:
    """0-15, either case; -1 for any other byte."""
    if c >= 48 and c < 58:
        return Int(c - 48)
    var l = c | 32
    return Int(l - 87) if l >= 97 and l < 103 else -1


def hex_val(s: String) -> Int:
    var v = 0
    for c in s.as_bytes():
        v = v * 16 + hex_digit(c)
    return v


@fieldwise_init
struct Insn(Copyable, Movable):
    var addr: Int
    var func: Int
    var text: String
    var load: Bool
    var branch: Bool
    var dep: Bool  # the row reads a register written by one of the 3 rows before it, or by itself
    var cyc: Int
    var mem: Int
    var fe: Int
    var br: Int


def rank(v: Int, r: Int) -> UInt128:
    """Sort key: v above, (row from the end) below: ascending sort, read backwards = largest v first, then lowest row."""
    return (UInt128(v) << 32) | UInt128(4294967295 - r)


def unrank(k: UInt128) -> Int:
    return 4294967295 - Int(k & 4294967295)


def is_branch(mn: String) -> Bool:
    if mn.startswith("j") or mn.startswith("ret") or mn == "call" or mn.startswith("b."):
        return True
    return mn == "b" or mn == "bl" or mn == "br" or mn == "blr" or mn == "cbz" or mn == "cbnz" or mn == "tbz" or mn == "tbnz"


def writes_nothing(mn: String) -> Bool:
    return mn.startswith("cmp") or mn.startswith("cmn") or mn.startswith("ccm") or mn.startswith("fccm") or mn.startswith("test") or mn.startswith("tst") or mn.startswith("fcmp") or mn.startswith("ucomis") or mn.startswith("vucomis") or mn.startswith("st") or mn.startswith("nop") or mn.startswith("push") or mn.startswith("prf")


def rmw(mn: String, dest: String, ops: String) -> Bool:
    """x86 two-operand forms read their destination (add rax, rcx; inc rax; vfmadd231): AArch64 and VEX three-operand forms do not."""
    var x86 = dest.startswith("r") or dest.startswith("e") or dest.startswith("xmm") or dest.startswith("ymm") or dest.startswith("zmm")
    for g in ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "ax", "bx", "cx", "dx", "si", "di", "bp", "sil", "dil", "bpl"]:
        x86 = x86 or dest == g
    if not x86:
        return False
    if mn.startswith("v"):
        return mn.startswith("vfm") or mn.startswith("vfnm") or mn.startswith("vperm") and (mn.find("2") >= 0)
    var writes = mn.startswith("mov") or mn.startswith("lea") or mn.startswith("set") or mn.startswith("cvt") or mn.startswith("pop") or mn.startswith("lzcnt") or mn.startswith("tzcnt") or mn.startswith("popcnt") or mn.startswith("bs") or mn.startswith("pshuf") or mn.startswith("sqrt") or mn.startswith("rdtsc") or mn.startswith("cpuid")
    var n = 1
    for c in ops.as_bytes():
        n += 1 if c == 44 else 0
    return not writes and not (mn == "imul" and n == 3)


def operand0(rest: String) -> String:
    """The first operand: up to the first comma outside brackets."""
    var depth = 0
    var i = 0
    for c in rest.as_bytes():
        if c == 91:
            depth += 1
        elif c == 93:
            depth -= 1
        elif c == 44 and depth == 0:
            return String(rest[byte=0:i])
        i += 1
    return rest


def tokens(s: String) -> List[String]:
    var out = List[String]()
    var cur = String("")
    for c in s.as_bytes():
        if (c >= 48 and c <= 57) or (c >= 97 and c <= 122) or (c >= 65 and c <= 90) or c == 95:
            cur += String(chr(Int(c)))
        else:
            if cur.byte_length() > 0:
                out.append(cur)
            cur = String("")
    if cur.byte_length() > 0:
        out.append(cur)
    return out^


struct Analysis(Movable):
    var ins: List[Insn]
    var fns: List[String]
    var raw: List[Int]  # per function: cycles of mapped samples before the skid rule
    var unmapped: Int
    var stat_keys: List[String]
    var stat_vals: List[Int]
    var note: String
    var tot: List[Int]  # cycles, mem, fe, br totals
    var per: List[Int]  # their sampling periods
    var k: Int  # skid distance

    def __init__(out self):
        self.ins = List[Insn]()
        self.fns = List[String]()
        self.raw = List[Int]()
        self.unmapped = 0
        self.stat_keys = List[String]()
        self.stat_vals = List[Int]()
        self.note = String("")
        self.tot = List[Int]()
        self.per = List[Int]()
        self.k = 4

    def stat(self, key: String) -> Int:
        for i in range(len(self.stat_keys)):
            if self.stat_keys[i] == key:
                return self.stat_vals[i]
        return -1


struct Lines:
    """The lines of a file read in 8 MB chunks, so a 1 GB objdump never sits in memory. An instruction line (it starts
    with a space) is cut to ROW_CAP bytes; a function header line comes whole."""

    var f: FileHandle
    var buf: List[UInt8]
    var pos: Int
    var scan: Int
    var eof: Bool

    def __init__(out self, path: String) raises:
        self.f = open(path, "r")
        self.buf = List[UInt8]()
        self.pos = 0
        self.scan = 0
        self.eof = False

    def next(mut self, mut line: String) raises -> Bool:
        while True:
            while self.scan < len(self.buf) and self.buf[self.scan] != 10:
                self.scan += 1
            if self.scan < len(self.buf) or self.eof:
                break
            self.buf = List[UInt8](Span(self.buf)[self.pos : len(self.buf)])  # drop what was consumed, then append a chunk
            self.scan -= self.pos
            self.pos = 0
            var chunk = self.f.read_bytes(8 << 20)
            if len(chunk) == 0:
                self.eof = True
            else:
                self.buf.extend(chunk^)
        if self.pos >= len(self.buf):
            return False
        var end = self.scan
        if self.buf[self.pos] == 32 and end - self.pos > ROW_CAP:
            end = self.pos + ROW_CAP
        line = String(unsafe_from_utf8=Span(self.buf)[self.pos : end])
        self.pos = self.scan + 1
        self.scan = self.pos
        return True


def load_insns(mut an: Analysis, path: String) raises:
    var writer = List[String]()  # destination register of each row, "" if none
    var rd = Lines(path)
    var line = String("")
    while rd.next(line):
        if line.byte_length() == 0:
            continue
        if not line.startswith(" "):  # "0000000000001360 <name>:"
            var lt = line.find("<")
            var name = String(line[byte = lt + 1 : line.byte_length() - 2]) if lt >= 0 else String(line)
            var cut = name.find("(")
            an.fns.append(String(name[byte=0:cut]) if cut > 0 else name)
            an.raw.append(0)
            continue
        var colon = line.find(":")
        if colon < 0 or len(an.fns) == 0:
            continue
        var text = String(String(line[byte = colon + 1 :]).replace("\t", " ").strip())
        var sp = text.find(" ")
        var mn = String(text[byte=0:sp]) if sp > 0 else text
        var rest = String(text[byte = sp + 1 :]) if sp > 0 else String("")
        var cm = rest.find("#")  # llvm adds "# xmm0 = (xmm1 * xmm0) + xmm2": it names the implicit source
        var ops = String(rest[byte=0:cm]) if cm >= 0 else rest
        var first = operand0(ops).strip()
        var br = is_branch(mn)
        var store = first.find("ptr [") >= 0 and (mn.startswith("mov") or mn.startswith("vmov") or mn.startswith("vpmov") or mn.find("extr") >= 0 or mn.startswith("set") or mn.find("cvtps2ph") >= 0 or mn.find("maskmov") >= 0 or mn.find("compress") >= 0 or mn.find("scatter") >= 0)
        var ld = (mn.startswith("ld") or (ops.find("ptr [") >= 0 and not store)) and not br
        var dest = String("")
        if not writes_nothing(mn) and not br and first.byte_length() > 0 and first.find("[") < 0:
            var c0 = first.as_bytes()[0]
            var ft = tokens(String(first))  # "v0.4s" and "{v0.4s": the register is the first token
            if c0 != 35 and not (c0 >= 48 and c0 <= 57) and len(ft) > 0:
                dest = ft[0]
        var src = List[String]()  # a branch row reads no dependence: its operand text (a mangled symbol) is not tokenised
        if not br:
            src = tokens(String(rest[byte = max(0, first.byte_length() + 1) :]) if rest.byte_length() > first.byte_length() else String(""))
        var zero = dest.byte_length() > 0 and len(src) > 0 and (mn == "xor" or mn == "sub" or mn.endswith("pxor") or mn.endswith("xorps") or mn.endswith("xorpd"))
        for t in src:  # "xor eax, eax": a zero idiom, renamed away, reads nothing
            zero = zero and t == dest
        var d = rmw(mn, dest, ops) and not ld and not zero
        if dest.byte_length() > 0 and not ld and not zero:
            for t in src:
                d = d or t == dest
        var n = len(an.ins)
        if not ld and not br and not zero:
            for j in range(max(0, n - 3), n):
                if an.ins[j].func == len(an.fns) - 1 and writer[j].byte_length() > 0:
                    for t in src:
                        d = d or t == writer[j]
        an.ins.append(Insn(hex_val(String(String(line[byte=0:colon]).strip())), len(an.fns) - 1, text, ld, br, d, 0, 0, 0, 0))
        writer.append(dest)
    # a row one after a dependent row is the skid victim of its stall
    var prev = False
    for i in range(len(an.ins)):
        var self_dep = an.ins[i].dep
        if prev and not an.ins[i].load and an.ins[i - 1].func == an.ins[i].func:
            an.ins[i].dep = True
        prev = self_dep


def find_row(ins: List[Insn], addr: Int) -> Int:
    var lo = 0
    var hi = len(ins) - 1
    while lo <= hi:
        var mid = (lo + hi) // 2
        if ins[mid].addr == addr:
            return mid
        if ins[mid].addr < addr:
            lo = mid + 1
        else:
            hi = mid - 1
    return -1


def load_samples(mut an: Analysis, path: String) raises:
    """Streaming parse of event TAB dso TAB vaddr TAB count lines from a sized read."""
    var b = open(path, "r").read_bytes(stat(path).st_size)
    var n = len(b)
    var i = 0
    var last = -1
    var lineno = 0
    while i < n:
        lineno += 1
        if b[i] == 10 or b[i] == 13:  # a blank line; the CR of a CRLF one is not a line
            lineno -= 1 if b[i] == 13 else 0
            i += 1
            continue
        var ev = b[i]
        for _ in range(2):  # event, dso
            while i < n and b[i] != 9 and b[i] != 10:
                i += 1
            if i >= n or b[i] == 10:
                fail("samples", "too few fields at " + path + " line " + String(lineno))
            i += 1
        var addr = 0
        if i + 1 < n and b[i] == 48 and b[i + 1] | 32 == 120:  # 0x
            i += 2
        while i < n and b[i] != 9:
            if b[i] == 10:
                fail("samples", "too few fields at " + path + " line " + String(lineno))
            var d = hex_digit(b[i])
            if d < 0:
                fail("samples", "bad address at " + path + " line " + String(lineno))
            addr = addr * 16 + d
            i += 1
        i += 1
        var count = 0
        while i < n and b[i] != 10:
            if b[i] != 13:
                if b[i] < 48 or b[i] > 57:
                    fail("samples", "bad count at " + path + " line " + String(lineno))
                count = count * 10 + Int(b[i] - 48)
            i += 1
        i += 1
        var r = last if last >= 0 and an.ins[last].addr == addr else find_row(an.ins, addr)
        if r < 0:
            an.unmapped += count if ev == 99 else 0
            continue
        last = r
        if ev == 99:
            an.ins[r].cyc += count
            an.raw[an.ins[r].func] += count
        elif ev == 109:
            an.ins[r].mem += count
        elif ev == 102:
            an.ins[r].fe += count
        elif ev == 98:
            an.ins[r].br += count


def ev_of(r: Insn, e: Int) -> Int:
    return r.mem if e == 1 else (r.fe if e == 2 else r.br)


def totals(mut an: Analysis):
    """Per event: total count over all mapped rows, and the sampling period (p_EVENT in stat.tsv, else the smallest nonzero count)."""
    an.tot = List[Int](length=4, fill=0)
    an.per = List[Int](length=4, fill=0)
    for r in an.ins:
        an.tot[0] += r.cyc
        for e in range(1, 4):
            var v = ev_of(r, e)
            an.tot[e] += v
            if v > 0 and (an.per[e] == 0 or v < an.per[e]):
                an.per[e] = v
    for e in range(1, 4):
        var p = an.stat("p_" + String("mem" if e == 1 else ("fe" if e == 2 else "br")))
        if p > 0:
            an.per[e] = p


def qual(an: Analysis, r: Insn, e: Int) -> Bool:
    """The row carries at least MIN_SAMPLES samples of event e, and at least half as large a share of the event as of the cycles."""
    var v = ev_of(r, e)
    return v > 0 and v >= MIN_SAMPLES * an.per[e] and 2.0 * Float64(v) * Float64(an.tot[0]) >= Float64(r.cyc) * Float64(an.tot[e])


def skid(mut an: Analysis, k: Int):
    """Move cycles and memory events to the nearest preceding load, cycles and branch-miss events to the preceding branch."""
    for pass_ in range(2):
        for r in range(len(an.ins)):
            if (pass_ == 0 and an.ins[r].load) or (pass_ == 1 and an.ins[r].branch) or not qual(an, an.ins[r], 1 if pass_ == 0 else 3):
                continue
            for t in range(r - 1, max(-1, r - k - 1), -1):
                if an.ins[t].func != an.ins[r].func:
                    break
                if an.ins[t].load if pass_ == 0 else an.ins[t].branch:
                    an.ins[t].cyc += an.ins[r].cyc
                    an.ins[r].cyc = 0
                    if pass_ == 0:
                        an.ins[t].mem += an.ins[r].mem
                        an.ins[r].mem = 0
                    else:
                        an.ins[t].br += an.ins[r].br
                        an.ins[r].br = 0
                    break


def cname(c: Int) -> String:
    return "mem" if c == 0 else ("fe" if c == 1 else ("dep" if c == 2 else ("branch" if c == 3 else "busy")))


def near_branch_miss(an: Analysis, i: Int) -> Bool:
    for j in range(max(0, i - an.k), min(len(an.ins), i + an.k + 1)):
        if an.ins[j].func == an.ins[i].func and qual(an, an.ins[j], 3):
            return True
    return False


def cause_of(an: Analysis, i: Int) -> Int:
    """A front-end stall next to a mispredicted branch is its refetch: the branch pays for it. A row with a recent register
    dependence is dep before fe: Oryon counts a dependent FMA chain as 80% front-end stall."""
    ref r = an.ins[i]
    if qual(an, r, 1):
        return 0
    if qual(an, r, 3) or (qual(an, r, 2) and near_branch_miss(an, i)):
        return 3
    if r.dep and not r.load:
        return 2
    return 1 if qual(an, r, 2) else 4


def load_stat(mut an: Analysis, path: String) raises:
    for line in open(path, "r").read().split("\n"):
        var f = line.split("\t")
        if len(f) < 2:
            continue
        if f[0] == "note":
            an.note = String(f[1])
        else:
            try:
                an.stat_vals.append(Int(f[1]))
                an.stat_keys.append(String(f[0]))
            except:
                pass  # "<not counted>" in an older recording: the role is missing, as if not recorded


def analyze(od: String, k: Int) raises -> Analysis:
    for f in ["objdump.txt", "samples.tsv", "stat.tsv"]:
        if not exists(od + "/" + f):
            fail("input", "no " + f + " in " + od + ": not a corewait recording (corewait record DEV OUT -- BINARY)")
    var an = Analysis()
    an.k = k
    load_insns(an, od + "/objdump.txt")
    load_samples(an, od + "/samples.tsv")
    load_stat(an, od + "/stat.tsv")
    totals(an)
    skid(an, k)
    return an^


def summary(an: Analysis) -> String:
    var cyc = an.stat("cycles")
    if cyc <= 0:
        return String("run: no stat.tsv counts")
    var den = an.stat("slots") if an.stat("slots") > 0 else cyc
    var s = "run: cycles " + String(cyc)
    if an.stat("instructions") >= 0:
        var ipc = an.stat("instructions") * 100 // cyc
        s += " ipc " + String(ipc // 100) + "." + lpad(String(ipc % 100), 2).replace(" ", "0")
    s += " |"
    for p in [("fe", "frontend"), ("bad", "bad-spec"), ("be", "backend"), ("be_mem", "backend-mem"), ("ret", "retiring")]:
        if an.stat(p[0]) >= 0:
            s += " " + p[1] + " " + pct(an.stat(p[0]), den)
    return s + (" (" + an.note + ")" if an.note.byte_length() > 0 else String(""))


def select(an: Analysis, func: String) -> List[Bool]:
    var sel = List[Bool]()
    for f in an.fns:
        sel.append(func.byte_length() == 0 or f.find(func) >= 0)
    return sel^


def cause_cycles(an: Analysis, sel: List[Bool]) -> List[Int]:
    """Cycles per cause of the selected functions, the total last."""
    var by_cause = List[Int](length=NC + 1, fill=0)
    for i in range(len(an.ins)):
        if sel[an.ins[i].func]:
            by_cause[cause_of(an, i)] += an.ins[i].cyc
            by_cause[NC] += an.ins[i].cyc
    return by_cause^


def f1(x: Float64) -> String:
    var t = Int(x * 10.0 + 0.5)
    return String(t // 10) + "." + String(t % 10)


def sol_line(an: Analysis, sel: List[Bool], bytes_: Int, bw: Float64) -> String:
    """Speed of light: bytes the selected functions move over their share of the run's CPU time, against the measured bw."""
    var all = 0
    var mine = 0
    for i in range(len(an.fns)):
        all += an.raw[i]
        mine += an.raw[i] if sel[i] else 0
    if an.stat("time_us") <= 0 or all == 0:
        fail("show", "--bytes needs time_us in stat.tsv: record again with this corewait")
    var secs = Float64(an.stat("time_us")) / 1e6 * Float64(mine) / Float64(all)
    var gbs = Float64(bytes_) / secs / 1e9
    return "sol: " + String(bytes_) + " bytes in " + String(Int(secs * 1000.0 + 0.5)) + " ms = " + f1(gbs) + " GB/s, " + f1(100.0 * gbs / bw) + "% of the device's " + f1(bw) + " GB/s"


def show(an: Analysis, func: String, top: Int, causes: Bool, bytes_: Int, bw: Float64) raises:
    var sel = select(an, func)
    var by_cause = cause_cycles(an, sel)
    var total = by_cause[NC]
    var raw = 0
    for i in range(len(an.fns)):
        raw += an.raw[i] if sel[i] else 0
    if total == 0:
        fail("show", "no samples in the selected functions" + (" (--fn " + func + ")" if func.byte_length() > 0 else String("")))
    print(summary(an))
    if bytes_ > 0 and bw > 0.0:
        print(sol_line(an, sel, bytes_, bw))
    if causes:
        print(rpad("cause", 8) + lpad("cycles", 14) + lpad("share", 8))
        for c in range(NC):
            print(rpad(cname(c), 8) + lpad(String(by_cause[c]), 14) + lpad(pct(by_cause[c], total), 8))
        print(rpad("total", 8) + lpad(String(total), 14) + "  raw " + String(raw) + (" unmapped " + String(an.unmapped) if an.unmapped > 0 else String("")))
        return
    for i in range(len(an.fns)):
        if sel[i] and an.raw[i] > 0:
            print("fn " + lpad(pct(an.raw[i], raw), 6) + "  " + an.fns[i])
    var keys = List[UInt128]()  # 128 bits: a row past 2^39 cycles overflowed a 64-bit key and sorted last
    for r in range(len(an.ins)):
        if sel[an.ins[r].func] and an.ins[r].cyc > 0:
            keys.append(rank(an.ins[r].cyc, r))
    sort(keys)
    print(lpad("addr", 8) + lpad("cyc%", 7) + lpad("cycles", 13) + lpad("mem", 12) + lpad("fe", 10) + lpad("br", 10) + "  " + rpad("cause", 7) + "instruction")
    for i in range(min(top, len(keys))):
        var ri = unrank(keys[len(keys) - 1 - i])
        ref r = an.ins[ri]
        var text = String(r.text[byte = 0 : min(60, r.text.byte_length())])
        print(lpad(hexs(r.addr), 8) + lpad(pct(r.cyc, total), 7) + lpad(String(r.cyc), 13) + lpad(String(r.mem), 12) + lpad(String(r.fe), 10) + lpad(String(r.br), 10) + "  " + rpad(cname(cause_of(an, ri)), 7) + text)
    if an.unmapped > 0:
        print("WARN", an.unmapped, "cycles of samples matched no instruction in objdump.txt")


def key(text: String) -> String:
    """An instruction without its addresses, so two builds of one kernel align."""
    var sp = text.find(" ")
    var mn = String(text[byte=0:sp]) if sp > 0 else text
    if is_branch(mn):
        return mn
    var cut = text.find(" #")
    var t = String(text[byte=0:cut]) if cut >= 0 else text
    cut = t.find(" <")
    return String(t[byte=0:cut]) if cut >= 0 else t


def is_reg(t: String) -> Bool:
    """x86 and ARM register names: rax..r15 with d/w/b, e/l/h forms, xmm/ymm/zmm/k, x/w/v/q/d/s/h/b with a number, sp, xzr."""
    var b = t.as_bytes()
    var n = len(b)
    if n < 2 or n > 6:
        return False
    for w in ["sp", "xzr", "wzr", "rsp", "rbp", "rsi", "rdi", "esp", "ebp", "esi", "edi", "sil", "dil", "spl", "bpl", "rip"]:
        if t == w:
            return True
    if n == 3 and (b[0] == 114 or b[0] == 101) and b[2] == 120:  # rax ebx ...
        return b[1] >= 97 and b[1] <= 100
    if n == 2 and b[1] == 120 and b[0] >= 97 and b[0] <= 100:  # ax bx cx dx
        return True
    if n == 2 and (b[1] == 108 or b[1] == 104) and b[0] >= 97 and b[0] <= 100:  # al ah ...
        return True
    var i = 0
    if t.startswith("xmm") or t.startswith("ymm") or t.startswith("zmm"):
        i = 3
    elif b[0] == 114 or b[0] == 120 or b[0] == 119 or b[0] == 118 or b[0] == 113 or b[0] == 100 or b[0] == 115 or b[0] == 104 or b[0] == 107 or b[0] == 98:
        i = 1  # r8.. x0 w0 v0 q0 d0 s0 h0 k0 b0
    else:
        return False
    var d = i
    while d < n and b[d] >= 48 and b[d] <= 57:
        d += 1
    if d == i:
        return False
    return d == n or (b[0] == 114 and i == 1 and d == n - 1 and (b[d] == 100 or b[d] == 119 or b[d] == 98))


def shape(k: String) -> String:
    """A key with its register names cut to %: one instruction with other registers, as two builds allocate them."""
    var out = String("")
    var cur = String("")
    for c in k.as_bytes():
        if (c >= 48 and c <= 57) or (c >= 97 and c <= 122) or c == 95:
            cur += String(chr(Int(c)))
            continue
        out += "%" if is_reg(cur) else cur
        cur = String("")
        out += String(chr(Int(c)))
    return out + ("%" if is_reg(cur) else cur)


def spct(a: Int, b: Int) -> String:
    if a == 0:
        return "new" if b > 0 else "+0.0%"
    return ("+" if b >= a else "-") + pct(abs(b - a), a)


def fn_rows(an: Analysis, name: String) -> List[Int]:
    var rows = List[Int]()
    for i in range(len(an.ins)):
        if an.fns[an.ins[i].func] == name:
            rows.append(i)
    return rows^


def lcs_row(a: List[Int], alo: Int, ahi: Int, b: List[Int], blo: Int, bhi: Int, rev: Bool) -> List[Int32]:
    """LCS lengths of a[alo:ahi] against every prefix of b[blo:bhi] (every suffix of it when `rev`): m + 1 values."""
    var m = bhi - blo
    var row = List[Int32](length=m + 1, fill=0)
    for ii in range(ahi - alo):
        var x = a[alo + ii] if not rev else a[ahi - 1 - ii]
        var diag = Int32(0)
        for j in range(1, m + 1):
            var up = row[j]
            var y = b[blo + j - 1] if not rev else b[bhi - j]
            if x == y:
                row[j] = diag + 1
            elif row[j - 1] > up:
                row[j] = row[j - 1]
            diag = up
    return row^


def hirschberg(a: List[Int], alo: Int, ahi: Int, b: List[Int], blo: Int, bhi: Int, mut out: List[Int]):
    """Append the aligned pairs of a[alo:ahi] and b[blo:bhi] (the layout of align()): memory linear in the rows."""
    if ahi == alo:
        for j in range(blo, bhi):
            out += [-1, j]
        return
    if bhi == blo:
        for i in range(alo, ahi):
            out += [i, -1]
        return
    if ahi - alo == 1:
        var hit = -1
        for j in range(blo, bhi):
            if b[j] == a[alo]:
                hit = j
                break
        if hit < 0:
            out += [alo, -1]
        for j in range(blo, bhi):
            if j == hit:
                out += [alo, j]
            else:
                out += [-1, j]
        return
    var mid = (alo + ahi) // 2
    var f = lcs_row(a, alo, mid, b, blo, bhi, False)
    var g = lcs_row(a, mid, ahi, b, blo, bhi, True)
    var m = bhi - blo
    var best = -1
    var cut = 0
    for k in range(m + 1):
        var v = Int(f[k]) + Int(g[m - k])
        if v > best:
            best = v
            cut = k
    hirschberg(a, alo, mid, b, blo, blo + cut, out)
    hirschberg(a, mid, ahi, b, blo + cut, bhi, out)


def align(ka: List[String], kb: List[String]) raises -> List[Int]:
    """Align two key sequences by LCS. Two entries per pair: the index in A and in B (-1: no partner, the row is removed
    or inserted). Up to ALIGN_CELLS cells the O(nm) table whose tie-breaking the golden diffs froze; above it Hirschberg's
    recursion, the same LCS length in memory linear in the rows."""
    var ids = Dict[String, Int]()
    var a = List[Int]()
    var b = List[Int]()
    for t in ka:
        if t not in ids:
            ids[t] = len(ids)
        a.append(ids[t])
    for t in kb:
        if t not in ids:
            ids[t] = len(ids)
        b.append(ids[t])
    var n = len(a)
    var m = len(b)
    var out = List[Int]()
    if n * m > atol(getenv("CW_ALIGN_CELLS", String(ALIGN_CELLS)), 10) or n > 65000 or m > 65000:
        hirschberg(a, 0, n, b, 0, m, out)
        return out^
    var L = List[UInt16](length=(n + 1) * (m + 1), fill=0)
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            if a[i] == b[j]:
                L[i * (m + 1) + j] = L[(i + 1) * (m + 1) + j + 1] + 1
            else:
                L[i * (m + 1) + j] = max(L[(i + 1) * (m + 1) + j], L[i * (m + 1) + j + 1])
    var i = 0
    var j = 0
    while i < n or j < m:
        if i < n and j < m and a[i] == b[j]:
            out += [i, j]
            i += 1
            j += 1
        elif j >= m or (i < n and L[(i + 1) * (m + 1) + j] >= L[i * (m + 1) + j + 1]):
            out += [i, -1]
            i += 1
        else:
            out += [-1, j]
            j += 1
    return out^


def diff(a: Analysis, b: Analysis, top: Int) raises:
    """Per-row cycle delta between two runs: rows of same-named functions are aligned by LCS on the instruction text."""
    var d_row = List[Int]()  # row of A (or -1), row of B (or -1), cycle delta, three values per entry
    var ta = 0
    var tb = 0
    for r in a.ins:
        ta += r.cyc
    for r in b.ins:
        tb += r.cyc
    for fa in range(len(a.fns)):
        var again = False  # one name, many instantiations (Mojo's are cut at "("): fn_rows already took them all
        for q in range(fa):
            again = again or a.fns[q] == a.fns[fa]
        if again:
            continue
        var ra = fn_rows(a, a.fns[fa])
        var rb = List[Int]()
        for fb in range(len(b.fns)):
            if b.fns[fb] == a.fns[fa]:
                rb = fn_rows(b, b.fns[fb])
        var ka = List[String]()
        var kb = List[String]()
        for r in ra:
            ka.append(shape(key(a.ins[r].text)))
        for r in rb:
            kb.append(shape(key(b.ins[r].text)))
        var al = align(ka, kb)
        for e in range(0, len(al), 2):
            var x = al[e]
            var y = al[e + 1]
            if x >= 0 and y >= 0:
                d_row += [ra[x], rb[y], b.ins[rb[y]].cyc - a.ins[ra[x]].cyc]
            elif x >= 0:
                d_row += [ra[x], -1, -a.ins[ra[x]].cyc]
            else:
                d_row += [-1, rb[y], b.ins[rb[y]].cyc]
    for fb in range(len(b.fns)):  # functions only B has
        var found = False
        for fa in range(len(a.fns)):
            found = found or a.fns[fa] == b.fns[fb]
        if not found:
            for r in fn_rows(b, b.fns[fb]):
                d_row += [-1, r, b.ins[r].cyc]
    var keys = List[UInt128]()
    for e in range(len(d_row) // 3):
        if d_row[3 * e + 2] != 0:
            keys.append(rank(abs(d_row[3 * e + 2]), e))
    sort(keys)
    print("diff: cycles " + String(ta) + " -> " + String(tb) + " (" + spct(ta, tb) + "), rows changed " + String(len(keys)))
    print(lpad("addr A", 8) + lpad("addr B", 8) + lpad("cycles A", 13) + lpad("cycles B", 13) + lpad("delta", 14) + "  " + rpad("cause B", 8) + "instruction")
    for q in range(min(top, len(keys))):
        var e = unrank(keys[len(keys) - 1 - q])
        var ia = d_row[3 * e]
        var ib = d_row[3 * e + 1]
        var text = a.ins[ia].text if ia >= 0 else b.ins[ib].text
        print(lpad(hexs(a.ins[ia].addr) if ia >= 0 else "-", 8) + lpad(hexs(b.ins[ib].addr) if ib >= 0 else "-", 8)
              + lpad(String(a.ins[ia].cyc) if ia >= 0 else "0", 13) + lpad(String(b.ins[ib].cyc) if ib >= 0 else "0", 13)
              + lpad(String(d_row[3 * e + 2]), 14) + "  " + rpad(cname(cause_of(b, ib)) if ib >= 0 else "-", 8) + String(text[byte=0:min(60, text.byte_length())]))


def tenths(s: String) raises -> Int:
    """\"12\" -> 120, \"12.5\" -> 125; -1 for anything else."""
    var parts = s.split(".")
    if len(parts) > 2 or not is_digits(String(parts[0])) or (len(parts) == 2 and not is_digits(String(parts[1]))):
        return -1
    return Int(String(parts[0])) * 10 + (Int(String(String(parts[1])[byte=0:1])) if len(parts) > 1 else 0)


def is_digits(s: String) -> Bool:
    if s.byte_length() == 0:
        return False
    for c in s.as_bytes():
        if c < 48 or c > 57:
            return False
    return True


def budget(an: Analysis, path: String) raises:
    """FILE lines `fn cause max-percent`: the cause may take at most that share of the function's cycles. Exit 1 on a breach."""
    var breaches = 0
    var rules = 0
    var lineno = 0
    for line in open(path, "r").read().split("\n"):
        lineno += 1
        var f = line.split()
        if len(f) == 0 or f[0].startswith("#"):
            continue
        if len(f) < 3:
            fail("budget", "want 'fn cause max-percent' at " + path + ":" + String(lineno))
        rules += 1
        var c = -1
        for q in range(NC):
            if cname(q) == f[1]:
                c = q
        if c < 0:
            fail("budget", "unknown cause '" + String(f[1]) + "' in " + path)
        var cc = cause_cycles(an, select(an, String(f[0])))
        if cc[NC] == 0:
            fail("budget", "no samples in functions matching '" + String(f[0]) + "'")
        var cap = tenths(String(f[2]))
        if cap < 0:
            fail("budget", "bad percent '" + String(f[2]) + "' at " + path + ":" + String(lineno))
        var got = (cc[c] * 1000 + cc[NC] // 2) // cc[NC]
        var line_out = String(f[0]) + " " + String(f[1]) + " " + pct(cc[c], cc[NC]) + " (max " + String(f[2]) + "%)"
        if got > cap:
            breaches += 1
            print("FAIL budget: " + line_out)
        else:
            print("ok " + line_out)
    if rules == 0:
        fail("budget", "no rules in " + path)
    if breaches > 0:
        exit(1)


def main() raises:
    var args = argv()
    var top = 20
    var k = 4
    var causes = False
    var bytes_ = 0
    var bw = 0.0
    var func = String("")
    var pos = List[String]()
    var i = 2
    while i < len(args):
        if args[i] == "--top":
            if i + 1 >= len(args):
                fail("usage", "--top needs a value")
            top = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--k":
            if i + 1 >= len(args):
                fail("usage", "--k needs a value")
            k = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--fn":
            if i + 1 >= len(args):
                fail("usage", "--fn needs a value")
            func = String(args[i + 1])
            i += 1
        elif args[i] == "--bytes":
            if i + 1 >= len(args):
                fail("usage", "--bytes needs a value")
            bytes_ = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--bw":
            if i + 1 >= len(args):
                fail("usage", "--bw needs a value")
            bw = Float64(String(args[i + 1]))
            i += 1
        elif args[i] == "--causes":
            causes = True
        else:
            pos.append(String(args[i]))
        i += 1
    var cmd = String(args[1]) if len(args) > 1 else String("")
    if cmd == "show" and len(pos) >= 1:
        show(analyze(pos[0], k), func, top, causes, bytes_, bw)
    elif cmd == "diff" and len(pos) >= 2:
        diff(analyze(pos[0], k), analyze(pos[1], k), top)
    elif cmd == "budget" and len(pos) == 2:
        budget(analyze(pos[0], k), pos[1])
    else:
        fail("usage", "corewait show OUT [--top N] [--causes] [--fn SYMBOL] [--k K] | diff OUT_A OUT_B [--top N] | budget OUT FILE")
