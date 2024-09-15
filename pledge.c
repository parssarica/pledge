#include <fcntl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "systemcalls.h"

/*
struct _perm
{
    int stdio;
    int rpath;
    int wpath;
    int cpath;
    int dpath;
    int tmppath;
    int inet;
    int mcast;
    int fattr;
    int chown;
    int flock;
    int unix_perm;
    int dns;
    int getpw;
    int sendfd;
    int recvfd;
    int tape;
    int tty;
    int proc;
    int exec;
    int prot_exec;
    int settime;
    int ps;
    int vminfo;
    int id;
    int pf;
    int route;
    int wroute;
    int audio;
    int video;
    int bpf;
    int unveil;
    int error;
} perm;

int disable_all(void)
{
    perm.stdio = 0;
    perm.rpath = 0;
    perm.wpath = 0;
    perm.cpath = 0;
    perm.dpath = 0;
    perm.tmppath = 0;
    perm.inet = 0;
    perm.mcast = 0;
    perm.fattr = 0;
    perm.chown = 0;
    perm.flock = 0;
    perm.unix_perm = 0;
    perm.dns = 0;
    perm.getpw = 0;
    perm.sendfd = 0;
    perm.recvfd = 0;
    perm.tape = 0;
    perm.tty = 0;
    perm.proc = 0;
    perm.exec = 0;
    perm.prot_exec = 0;
    perm.settime = 0;
    perm.ps = 0;
    perm.vminfo = 0;
    perm.id = 0;
    perm.pf = 0;
    perm.route = 0;
    perm.wroute = 0;
    perm.audio = 0;
    perm.video = 0;
    perm.bpf = 0;
    perm.unveil = 0;
    perm.error = 0;
    
    return 0;
}

int update_perm(char *permission, int val)
{
    if(strcmp(permission, "stdio") == 0) perm.stdio = val;
    if(strcmp(permission, "rpath") == 0) perm.rpath = val;
    if(strcmp(permission, "wpath") == 0) perm.wpath = val;
    if(strcmp(permission, "cpath") == 0) perm.cpath = val;
    if(strcmp(permission, "dpath") == 0) perm.dpath = val;
    if(strcmp(permission, "tmppath") == 0) perm.tmppath = val;
    if(strcmp(permission, "inet") == 0) perm.inet = val;
    if(strcmp(permission, "mcast") == 0) perm.mcast = val;
    if(strcmp(permission, "fattr") == 0) perm.fattr = val;
    if(strcmp(permission, "chown") == 0) perm.chown = val;
    if(strcmp(permission, "flock") == 0) perm.flock = val;
    if(strcmp(permission, "unix_perm") == 0) perm.unix_perm = val;
    if(strcmp(permission, "dns") == 0) perm.dns = val;
    if(strcmp(permission, "getpw") == 0) perm.getpw = val;
    if(strcmp(permission, "sendfd") == 0) perm.sendfd = val;
    if(strcmp(permission, "recvfd") == 0) perm.recvfd = val;
    if(strcmp(permission, "tape") == 0) perm.tape = val;
    if(strcmp(permission, "tty") == 0) perm.tty = val;
    if(strcmp(permission, "proc") == 0) perm.proc = val;
    if(strcmp(permission, "exec") == 0) perm.exec = val;
    if(strcmp(permission, "prot_exec") == 0) perm.prot_exec = val;
    if(strcmp(permission, "settime") == 0) perm.settime = val;
    if(strcmp(permission, "ps") == 0) perm.ps = val;
    if(strcmp(permission, "vminfo") == 0) perm.vminfo = val;
    if(strcmp(permission, "id") == 0) perm.id = val;
    if(strcmp(permission, "pf") == 0) perm.pf = val;
    if(strcmp(permission, "route") == 0) perm.route = val;
    if(strcmp(permission, "wroute") == 0) perm.wroute = val;
    if(strcmp(permission, "audio") == 0) perm.audio = val;
    if(strcmp(permission, "video") == 0) perm.video = val;
    if(strcmp(permission, "bpf") == 0) perm.bpf = val;
    if(strcmp(permission, "unveil") == 0) perm.unveil = val;
    if(strcmp(permission, "error") == 0) perm.error = val;

    return 0;
}
*/

scmp_filter_ctx ctx = NULL;

int update_ctx(char *promises)
{
    char *token;
    char *promises_internal;
    int syscall;
    int inet_used = 0;
    ctx = seccomp_init(SCMP_ACT_KILL);
    if(ctx == NULL)
        perror("seccomp_init");

    promises_internal = strdup(promises);
    token = strtok(promises_internal, " ");
    while(token != NULL)
    {
        if(strcmp(token, "stdio") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(stdio) / sizeof(stdio[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, stdio[syscall], 0) < 0)
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "rpath") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(rpath) / sizeof(rpath[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, rpath[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "wpath") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(wpath) / sizeof(wpath[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, wpath[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "cpath") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(cpath) / sizeof(cpath[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, cpath[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "dpath") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(dpath) / sizeof(dpath[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, dpath[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "tmppath") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(tmppath) / sizeof(tmppath[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, tmppath[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "inet") == 0)
        {
            inet_used = 1;
            for(syscall = 0; syscall < (int)(sizeof(inet_group) / sizeof(inet_group[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, inet_group[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "mcast") == 0 && inet_used == 1)
        {
            for(syscall = 0; syscall < (int)(sizeof(mcast) / sizeof(mcast[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, mcast[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "fattr") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(fattr) / sizeof(fattr[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, fattr[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "chown") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(chown) / sizeof(chown[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, chown[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "flock") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(flock) / sizeof(flock[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, flock[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "unix") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(unix_group) / sizeof(unix_group[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, unix_group[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "dns") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(dns) / sizeof(dns[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, dns[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "sendfd") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(sendfd) / sizeof(sendfd[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sendfd[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "recvfd") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(recvfd) / sizeof(recvfd[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, recvfd[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "tty") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(tty) / sizeof(tty[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, tty[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "exec") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(exec) / sizeof(exec[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, exec[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
        else if(strcmp(token, "settime") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(settime) / sizeof(settime[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, settime[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }
/*        else if(strcmp(token, "ps") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(ps) / sizeof(ps[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, ps[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }*/
        else if(strcmp(token, "id") == 0)
        {
            for(syscall = 0; syscall < (int)(sizeof(id) / sizeof(id[0])); syscall++)
            {
                if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, id[syscall], 0))
                {
                    perror("seccomp_rule_add");
                    seccomp_release(ctx);
                    free(promises_internal);
                    return EXIT_FAILURE;
                }
            }
        }

        token = strtok(NULL, " ");
    }
    
    for(syscall = 0; syscall < (int)(sizeof(essentials) / sizeof(essentials[0])); syscall++)
    {
        if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, essentials[syscall], 0))
        {
            perror("seccomp_rule_add");
            seccomp_release(ctx);
            free(promises_internal);
            return EXIT_FAILURE;
        }
    }

    if(seccomp_load(ctx) < 0)
    {
        perror("seccomp_load");
        seccomp_release(ctx);
        free(promises_internal);
        return EXIT_FAILURE;
    }
    
    seccomp_release(ctx);
    free(promises_internal);
    return 0;
}

int pledge(char *promises, char *execpromises)
{
/*    static int firstrun = 0;
    static int used = 0;
    int pledge_used = 0;
    char* token;
    char* promises_internal;
    promises_internal = strdup(promises);

    if(firstrun == 0)
    {
        token = strtok(promises_internal, " ");
        while(token != NULL)
        {
            used++;
            update_perm(token, 1);
            token = strtok(NULL, " ");
        }
        firstrun = 1;
        free(promises_internal);*/
        return update_ctx(promises);
/*    }
    token = strtok(promises_internal, " ");
    while(token != NULL)
    {
        pledge_used++;
        token = strtok(NULL, " ");
    }
    if(pledge_used > used) return -1;
    
    ctx = NULL;
    token = strtok(promises, " ");
    disable_all();
    used = 0;
    while(token != NULL)
    {
        used++;
        update_perm(token, 1);
        token = strtok(NULL, " ");
    }
    
    free(promises_internal);

    return update_ctx(promises);*/
}
