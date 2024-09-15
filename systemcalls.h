#pragma once
#include <seccomp.h>

int essentials[] = {__SNR_exit, __SNR_exit_group};
int stdio[] = {__SNR_clock_getres, __SNR_clock_gettime, __SNR_close, /*__SNR_closefrom,*/ __SNR_dup, __SNR_dup2, __SNR_dup3, __SNR_fchdir, __SNR_fcntl, __SNR_stat, __SNR_fstat, __SNR_fsync, __SNR_ftruncate, __SNR_getdents, /*__SNR_getdtablecount,*/ __SNR_getegid, /*__SNR_getentropy,*/ __SNR_geteuid, __SNR_getgid, __SNR_getgroups, __SNR_getitimer, /*__SNR_getlogin,*/ __SNR_getpgid, __SNR_getpgrp, __SNR_getpid, __SNR_getppid, __SNR_getresgid, __SNR_getresuid, __SNR_getrlimit, /*__SNR_getrtable,*/ __SNR_getsid, /*__SNR_getthrid,*/ __SNR_gettimeofday, __SNR_getuid, /*__SNR_issetugid,*/ /*__SNR_kevent, __SNR_kqueue, __SNR_kqueue1,*/ __SNR_lseek, __SNR_madvise, /*__SNR_minherit,*/ __SNR_mmap, __SNR_mprotect, /*__SNR_mquery,*/ __SNR_munmap, __SNR_nanosleep, __SNR_pipe, __SNR_pipe2, __SNR_poll, /*__SNR_pread,*/ __SNR_preadv, __SNR_profil, /*__SNR_pwrite,*/ __SNR_pwritev, __SNR_read, __SNR_readv, __SNR_recvfrom, __SNR_recvmsg, __SNR_select, __SNR_sendmsg, /*__SNR_sendsyslog,*/ __SNR_sendto, __SNR_setitimer, __SNR_shutdown, __SNR_sigaction, __SNR_sigprocmask, __SNR_sigreturn, __SNR_socketpair, __SNR_umask, __SNR_wait4, __SNR_waitid, __SNR_write, __SNR_writev};
int rpath[] = {__SNR_chdir, __SNR_getcwd, __SNR_openat, /*__SNR_fstatat,*/ __SNR_faccessat, __SNR_readlinkat, __SNR_lstat, __SNR_chmod, __SNR_fchmod, __SNR_fchmodat, /*__SNR_chflags, __SNR_chflagsat,*/ __SNR_chown, __SNR_fchown, __SNR_fchownat, __SNR_fstat, /*__SNR_getfsstat*/};
int wpath[] = {__SNR_getcwd, __SNR_openat, /*__SNR_fstatat,*/ __SNR_faccessat, __SNR_readlinkat, __SNR_lstat, __SNR_chmod, __SNR_fchmod, __SNR_fchmodat, /*__SNR_chflags, __SNR_chflagsat,*/ __SNR_chown, __SNR_fchown, __SNR_fchownat, __SNR_fstat};
int cpath[] = {__SNR_rename, __SNR_renameat, __SNR_link, __SNR_linkat, __SNR_symlink, __SNR_symlinkat, __SNR_unlink, __SNR_unlinkat, __SNR_mkdir, __SNR_mkdirat, __SNR_rmdir};
int dpath[] = {/*__SNR_mkfifo,*/ __SNR_mknod};
int tmppath[] = {__SNR_lstat, __SNR_chmod, /*__SNR_chflags,*/ __SNR_chown, __SNR_unlink, __SNR_fstat};
int inet_group[] = {__SNR_socket, __SNR_listen, __SNR_bind, __SNR_connect, __SNR_accept4, __SNR_accept, __SNR_getpeername, __SNR_getsockname, __SNR_setsockopt, __SNR_getsockopt};
int mcast[] = {__SNR_setsockopt};
int fattr[] = {__SNR_utimes, /*__SNR_futimes,*/ __SNR_utimensat, /*__SNR_futimens,*/ __SNR_chmod, __SNR_fchmod, __SNR_fchmodat,/* __SNR_chflags, __SNR_chflagsat,*/ __SNR_chown, __SNR_fchownat, __SNR_lchown, __SNR_fchown, __SNR_utimes};
int chown[] = {__SNR_chown, __SNR_fchown, __SNR_fchownat, __SNR_lchown};
int flock[] = {__SNR_fcntl, __SNR_flock, /*__SNR_lockf,*/ __SNR_open};
int unix_group[] = {__SNR_socket, __SNR_listen, __SNR_bind, __SNR_connect, __SNR_accept4, __SNR_accept, __SNR_getpeername, __SNR_getsockname, __SNR_setsockopt, __SNR_getsockopt};
int dns[] = {__SNR_sendto, __SNR_recvfrom, __SNR_socket, __SNR_connect};
//int getpw[] = {__SNR_getpwnam, __SNR_getgrnam, __SNR_getgrouplist};
int sendfd[] = {__SNR_sendmsg};
int recvfd[] = {__SNR_recvmsg};
//int tape[] = {};
int tty[] = {__SNR_fork, __SNR_vfork, __SNR_kill, __SNR_getpriority, __SNR_setpriority, __SNR_setrlimit, __SNR_setpgid, __SNR_setsid};
int exec[] = {__SNR_execve};
//int prot_
int settime[] = {__SNR_settimeofday/*, __SNR_adjtime, __SNR_adjfreq*/};
//int ps[] = {__SNR_sysctl};
//int vminfo[] = {__SNR_};
int id[] = {__SNR_setuid, /*__SNR_seteuid,*/ __SNR_setreuid, /*__SNR_sentresuid,*/ __SNR_setgid,/* __SNR_setegid,*/ __SNR_setregid, __SNR_setresgid, __SNR_setgroups, /*__SNR_setlogin,*/ __SNR_setrlimit, __SNR_getpriority, __SNR_setpriority/*, __SNR_setrtable*/};
//int pf[] = {};
//int route[] = {};
//int wroute[] = {};
//int audio[] = {};
//int video[] = {};
//int bpf[] = {};
////////////////////////////////////// UNVEIL - UNVEIL - UNVEIL - UNVEIL \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

