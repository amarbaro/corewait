# cwprobe chase|stream|fmachain|branchy [--n MB]: four kernels, each runs about 0.5 s and is bound by one cause.
#   chase    dependent pointer walk over MB of memory   -> mem (latency)
#   stream   sequential read of MB of memory            -> mem (bandwidth), prints GB/s
#   fmachain one long dependent multiply-add chain      -> dep
#   branchy  random branches over a MB-sized table      -> branch
# The kernels are @no_inline so `corewait show --fn chase_k` selects one; --n defaults to 256 (1 for branchy and fmachain).
from std.ffi import external_call
from std.time import perf_counter_ns

comptime RUN_NS = 500_000_000
comptime Ptr = MutPointer[UInt64, MutUntrackedOrigin]


@no_inline
def chase_k(a: Ptr, start: UInt64, steps: Int) -> UInt64:
    var p = start
    for _ in range(steps):
        p = a[unsafe_offset=Int(p)]
    return p


@no_inline
def stream_k(a: Ptr, words: Int) -> UInt64:
    var s0 = SIMD[DType.uint64, 8](0)
    var s1 = s0
    var s2 = s0
    var s3 = s0
    for i in range(0, words, 32):
        s0 += a.unsafe_load[width=8](i)
        s1 += a.unsafe_load[width=8](i + 8)
        s2 += a.unsafe_load[width=8](i + 16)
        s3 += a.unsafe_load[width=8](i + 24)
    return (s0 + s1 + s2 + s3).reduce_add()


@no_inline
def fmachain_k(x0: Float64, steps: Int) -> Float64:
    var x = x0
    for _ in range(steps):
        x = x * 1.0000001 + 1e-9
    return x


@no_inline
def up(s: UInt64) -> UInt64:
    return s * 3 + 1


@no_inline
def down(s: UInt64) -> UInt64:
    return s ^ (s >> 3)


@no_inline
def branchy_k(a: Ptr, words: Int, s0: UInt64) -> UInt64:
    var s = s0
    for i in range(words):
        if a[unsafe_offset=i] & 1 == 1:
            s = up(s)
        else:
            s = down(s)
    return s


@no_inline
def fill_k(p: Ptr, words: Int, chase: Bool):
    var x: UInt64 = 88172645463325252
    for i in range(words):
        if chase:
            p[unsafe_offset=i] = UInt64((i * 6364136223846793005 + 1442695040888963407) & (words - 1))
        else:
            x ^= x << 13  # xorshift64: random words for branchy, anything for stream
            x ^= x >> 7
            x ^= x << 17
            p[unsafe_offset=i] = x


@no_inline
def report(mode: String, mb: Int, steps: Int, dt: Int, acc: UInt64):
    var s = Float64(dt) / 1e9
    print(mode, "mb", mb, "steps", steps, "s", s, "check", acc & 1, "GBps" if mode == "stream" else "Msteps/s",
          Float64(steps) / s / (1e9 if mode == "stream" else 1e6))


def arg(i: Int) -> String:  # probes/kgen_shim.c: std.sys.argv() is empty without the Mojo runtime
    var buf = List[UInt8](length=Int(external_call["cw_arg_len", Int64](Int64(i))), fill=0)
    external_call["cw_arg", NoneType](Int64(i), buf.unsafe_ptr())
    return String(StringSlice(unsafe_from_utf8=Span(buf)))


def main() raises:
    var argc = Int(external_call["cw_argc", Int64]())
    var mode = arg(1) if argc > 1 else String("")
    var mb = 1 if mode == "branchy" or mode == "fmachain" else 256
    var go = 0
    for i in range(2, argc - 1):
        if arg(i) == "--n":
            mb = Int(arg(i + 1))
        elif arg(i) == "--go":  # wait until this file exists, so concurrent copies overlap (corewait bw)
            go = i + 1
    var words = mb * (1 << 17)
    var a = List[UInt64](length=words, fill=0)
    var p = a.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin]()
    fill_k(p, words, mode == "chase")
    var steps = 0
    var acc: UInt64 = 0
    while go > 0 and external_call["cw_exists_arg", Int64](Int64(go)) == 0:
        pass
    var t0 = perf_counter_ns()
    var dt = 0
    while dt < RUN_NS:
        if mode == "chase":
            acc = chase_k(p, acc, 1 << 20)
            steps += 1 << 20
        elif mode == "stream":
            acc += stream_k(p, words)
            steps += words * 8
        elif mode == "fmachain":
            acc += UInt64(fmachain_k(Float64(acc & 7), 1 << 24))
            steps += 1 << 24
        elif mode == "branchy":
            acc = branchy_k(p, words, acc)
            steps += words
        else:
            print("usage: cwprobe chase|stream|fmachain|branchy [--n MB] [--go FILE]")
            return
        dt = perf_counter_ns() - t0
    report(mode, mb, steps, dt, acc)
    _ = len(a)
