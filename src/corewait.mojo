# corewait show OUT [--top N] [--causes] [--fn SYMBOL] [--k K] [--bytes B --bw GBPS]   diff OUT_A OUT_B [--top N]   budget OUT FILE
# Joins OUT/samples.tsv to OUT/objdump.txt by address: one row per instruction, with a cause on each row.
#   skid rule: a sample lands up to K instructions after its cause, so the cycles and memory (or branch-miss) events of a
#   row go to the nearest preceding load (branch) in the same function; --k 0 turns the rule off.
#   causes, first match wins: mem (memory event charged), branch, dep (the row, or the one before it, reads a register one of
#   the 3 rows before it wrote), fe (front-end event), busy (the rest).
from std.os import stat
from std.sys import argv, exit

comptime NC = 5
comptime MIN_SAMPLES = 10  # fewer samples of an event on a row are noise: no cause, no skid


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


def hex_val(s: String) -> Int:
    var v = 0
    for c in s.as_bytes():
        v = v * 16 + Int(c - 48 if c < 58 else c - 87)
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


def is_branch(mn: String) -> Bool:
    if mn.startswith("j") or mn.startswith("ret") or mn == "call" or mn.startswith("b."):
        return True
    return mn == "b" or mn == "bl" or mn == "br" or mn == "blr" or mn == "cbz" or mn == "cbnz" or mn == "tbz" or mn == "tbnz"


def writes_nothing(mn: String) -> Bool:
    return mn.startswith("cmp") or mn.startswith("test") or mn.startswith("tst") or mn.startswith("fcmp") or mn.startswith("ucomis") or mn.startswith("vucomis") or mn.startswith("st") or mn.startswith("nop") or mn.startswith("push") or mn.startswith("prf")


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


def load_insns(mut an: Analysis, path: String) raises:
    var writer = List[String]()  # destination register of each row, "" if none
    var srcs = List[List[String]]()
    for line in open(path, "r").read().split("\n"):
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
        var store = first.find("ptr [") >= 0 and (mn.startswith("mov") or mn.startswith("vmov") or mn.startswith("vpmov"))
        var ld = (mn.startswith("ld") or (ops.find("ptr [") >= 0 and not store)) and not br
        var dest = String("")
        if not writes_nothing(mn) and not br and first.byte_length() > 0 and first.find("[") < 0:
            var c0 = first.as_bytes()[0]
            if c0 != 35 and not (c0 >= 48 and c0 <= 57):
                dest = String(first)
        var src = tokens(String(rest[byte = max(0, first.byte_length() + 1) :]) if rest.byte_length() > first.byte_length() else String(""))
        var d = False
        if dest.byte_length() > 0 and not ld:
            for t in src:
                d = d or t == dest
        var n = len(an.ins)
        if not ld and not br:
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
    while i < n:
        var ev = b[i]
        while i < n and b[i] != 9:
            i += 1
        i += 1
        while i < n and b[i] != 9:  # dso
            i += 1
        i += 1
        var addr = 0
        while i < n and b[i] != 9:
            addr = addr * 16 + Int(b[i] - 48 if b[i] < 58 else b[i] - 87)
            i += 1
        i += 1
        var count = 0
        while i < n and b[i] != 10:
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
            an.stat_keys.append(String(f[0]))
            an.stat_vals.append(Int(f[1]))


def analyze(od: String, k: Int) raises -> Analysis:
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
    var keys = List[Int]()  # cycles above, (row from the end) below: ascending sort, read backwards = most cycles first
    for r in range(len(an.ins)):
        if sel[an.ins[r].func] and an.ins[r].cyc > 0:
            keys.append(an.ins[r].cyc * 16777216 + (16777215 - r))
    sort(keys)
    print(lpad("addr", 8) + lpad("cyc%", 7) + lpad("cycles", 13) + lpad("mem", 12) + lpad("fe", 10) + lpad("br", 10) + "  " + rpad("cause", 7) + "instruction")
    for i in range(min(top, len(keys))):
        var ri = 16777215 - keys[len(keys) - 1 - i] % 16777216
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


def spct(a: Int, b: Int) -> String:
    return ("+" if b >= a else "-") + pct(abs(b - a), a)


def fn_rows(an: Analysis, name: String) -> List[Int]:
    var rows = List[Int]()
    for i in range(len(an.ins)):
        if an.fns[an.ins[i].func] == name:
            rows.append(i)
    return rows^


def diff(a: Analysis, b: Analysis, top: Int):
    """Per-row cycle delta between two runs: rows of same-named functions are aligned by LCS on the instruction text."""
    var d_row = List[Int]()  # row of A (or -1), row of B (or -1), cycle delta, three values per entry
    var ta = 0
    var tb = 0
    for r in a.ins:
        ta += r.cyc
    for r in b.ins:
        tb += r.cyc
    for fa in range(len(a.fns)):
        var ra = fn_rows(a, a.fns[fa])
        var rb = List[Int]()
        for fb in range(len(b.fns)):
            if b.fns[fb] == a.fns[fa]:
                rb = fn_rows(b, b.fns[fb])
        var n = len(ra)
        var m = len(rb)
        if n * m > 40000000 or n > 65000 or m > 65000:
            fail("diff", a.fns[fa] + " has " + String(n) + " and " + String(m) + " rows: too large to align")
        var L = List[UInt16](length=(n + 1) * (m + 1), fill=0)
        for i in range(n - 1, -1, -1):
            for j in range(m - 1, -1, -1):
                if key(a.ins[ra[i]].text) == key(b.ins[rb[j]].text):
                    L[i * (m + 1) + j] = L[(i + 1) * (m + 1) + j + 1] + 1
                else:
                    L[i * (m + 1) + j] = max(L[(i + 1) * (m + 1) + j], L[i * (m + 1) + j + 1])
        var i = 0
        var j = 0
        while i < n or j < m:
            if i < n and j < m and key(a.ins[ra[i]].text) == key(b.ins[rb[j]].text):
                d_row += [ra[i], rb[j], b.ins[rb[j]].cyc - a.ins[ra[i]].cyc]
                i += 1
                j += 1
            elif j >= m or (i < n and L[(i + 1) * (m + 1) + j] >= L[i * (m + 1) + j + 1]):
                d_row += [ra[i], -1, -a.ins[ra[i]].cyc]
                i += 1
            else:
                d_row += [-1, rb[j], b.ins[rb[j]].cyc]
                j += 1
    for fb in range(len(b.fns)):  # functions only B has
        var found = False
        for fa in range(len(a.fns)):
            found = found or a.fns[fa] == b.fns[fb]
        if not found:
            for r in fn_rows(b, b.fns[fb]):
                d_row += [-1, r, b.ins[r].cyc]
    var keys = List[Int]()
    for e in range(len(d_row) // 3):
        if d_row[3 * e + 2] != 0:
            keys.append(abs(d_row[3 * e + 2]) * 16777216 + (16777215 - e))
    sort(keys)
    print("diff: cycles " + String(ta) + " -> " + String(tb) + " (" + spct(ta, tb) + "), rows changed " + String(len(keys)))
    print(lpad("addr A", 8) + lpad("addr B", 8) + lpad("cycles A", 13) + lpad("cycles B", 13) + lpad("delta", 14) + "  " + rpad("cause B", 8) + "instruction")
    for q in range(min(top, len(keys))):
        var e = 16777215 - keys[len(keys) - 1 - q] % 16777216
        var ia = d_row[3 * e]
        var ib = d_row[3 * e + 1]
        var text = a.ins[ia].text if ia >= 0 else b.ins[ib].text
        print(lpad(hexs(a.ins[ia].addr) if ia >= 0 else "-", 8) + lpad(hexs(b.ins[ib].addr) if ib >= 0 else "-", 8)
              + lpad(String(a.ins[ia].cyc) if ia >= 0 else "0", 13) + lpad(String(b.ins[ib].cyc) if ib >= 0 else "0", 13)
              + lpad(String(d_row[3 * e + 2]), 14) + "  " + rpad(cname(cause_of(b, ib)) if ib >= 0 else "-", 8) + String(text[byte=0:min(60, text.byte_length())]))


def tenths(s: String) raises -> Int:
    """\"12\" -> 120, \"12.5\" -> 125."""
    var parts = s.split(".")
    return Int(String(parts[0])) * 10 + (Int(String(String(parts[1])[byte=0:1])) if len(parts) > 1 else 0)


def budget(an: Analysis, path: String) raises:
    """FILE lines `fn cause max-percent`: the cause may take at most that share of the function's cycles. Exit 1 on a breach."""
    var breaches = 0
    for line in open(path, "r").read().split("\n"):
        var f = line.split()
        if len(f) < 3 or f[0].startswith("#"):
            continue
        var c = -1
        for q in range(NC):
            if cname(q) == f[1]:
                c = q
        if c < 0:
            fail("budget", "unknown cause '" + String(f[1]) + "' in " + path)
        var cc = cause_cycles(an, select(an, String(f[0])))
        if cc[NC] == 0:
            fail("budget", "no samples in functions matching '" + String(f[0]) + "'")
        var got = (cc[c] * 1000 + cc[NC] // 2) // cc[NC]
        var line_out = String(f[0]) + " " + String(f[1]) + " " + pct(cc[c], cc[NC]) + " (max " + String(f[2]) + "%)"
        if got > tenths(String(f[2])):
            breaches += 1
            print("FAIL budget: " + line_out)
        else:
            print("ok " + line_out)
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
            top = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--k":
            k = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--fn":
            func = String(args[i + 1])
            i += 1
        elif args[i] == "--bytes":
            bytes_ = Int(String(args[i + 1]))
            i += 1
        elif args[i] == "--bw":
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
