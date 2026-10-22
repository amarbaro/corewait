// Minimal KGEN_CompilerRT for Mojo objects on Android (bionic). Signatures read from
// the LLVM IR Mojo 1.0 emits for aarch64-unknown-linux-gnu. Probe code, not the runtime.
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *KGEN_CompilerRT_AlignedAlloc(int64_t align, int64_t size) {
    void *p = NULL;
    if (align < (int64_t) sizeof(void *)) align = sizeof(void *);
    return posix_memalign(&p, (size_t) align, (size_t) size) == 0 ? p : NULL;
}
void KGEN_CompilerRT_AlignedFree(void *p) { free(p); }

// Globals: (name ptr, name len, init, destroy) -> value returned by init, created once.
typedef int64_t (*kgen_init)(void);
typedef void (*kgen_destroy)(int64_t);
struct kgen_global { char name[128]; int64_t value; kgen_destroy destroy; };
static struct kgen_global g_globals[256];
static int g_count;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

int64_t KGEN_CompilerRT_GetOrCreateGlobal(int64_t name, int64_t len, kgen_init init, kgen_destroy destroy) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_count; i++)
        if ((int64_t) strlen(g_globals[i].name) == len && memcmp(g_globals[i].name, (const char *) name, len) == 0) {
            pthread_mutex_unlock(&g_lock);
            return g_globals[i].value;
        }
    if (g_count == 256 || len >= 128) abort();
    struct kgen_global *g = &g_globals[g_count++];
    memcpy(g->name, (const char *) name, len); g->name[len] = 0;
    g->destroy = destroy;
    pthread_mutex_unlock(&g_lock);
    g->value = init();
    return g->value;
}
void KGEN_CompilerRT_DestroyGlobals(void) {
    for (int i = g_count - 1; i >= 0; i--) if (g_globals[i].destroy) g_globals[i].destroy(g_globals[i].value);
    g_count = 0;
}

// AsyncRT CPU device: a non-zero token; parallelize is not supported by this probe.
static int64_t g_device;
int64_t KGEN_CompilerRT_AsyncRT_GetOrCreateCPUDevice(void) { g_device = 1; return g_device; }
int64_t KGEN_CompilerRT_AsyncRT_GetCurrentCPUDevice(void) { return g_device; }
void KGEN_CompilerRT_AsyncRT_ReleaseCPUDevice(int64_t d) { (void) d; }

static int32_t g_kgen_argc;
static char **g_kgen_argv;
void KGEN_CompilerRT_SetArgV(int32_t argc, char **argv) { g_kgen_argc = argc; g_kgen_argv = argv; }
int32_t KGEN_CompilerRT_GetArgV(char ***argv_out) { *argv_out = g_kgen_argv; return g_kgen_argc; }
void KGEN_CompilerRT_PrintStackTraceOnFault(void) {}
void KGEN_CompilerRT_GetStackTrace(void *buf, int64_t len, int64_t skip) { (void)buf; (void)len; (void)skip; }
int32_t KGEN_CompilerRT_fprintf(int64_t f, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    int r = vfprintf((FILE *) f, fmt, ap);
    va_end(ap);
    return r;
}

// corewait: the shim's GetArgV does not fill the list std.sys.argv() passes, so cwprobe reads its arguments through these;
// glibc and bionic hand (argc, argv, envp) to ELF constructors. std.os.path.exists needs __xstat, which bionic lacks.
#include <unistd.h>
__attribute__((constructor)) static void cw_capture_args(int argc, char **argv, char **envp) {
    (void) envp; g_kgen_argc = argc; g_kgen_argv = argv;
}
int64_t cw_argc(void) { return g_kgen_argc; }
int64_t cw_arg_len(int64_t i) { return i < g_kgen_argc ? (int64_t) strlen(g_kgen_argv[i]) : 0; }
void cw_arg(int64_t i, char *buf) { memcpy(buf, g_kgen_argv[i], strlen(g_kgen_argv[i])); }
int64_t cw_exists_arg(int64_t i) { return access(g_kgen_argv[i], F_OK) == 0; }
