#ifndef _PURELIBC_H
#define _PURELIBC_H

typedef long int (*sfun)(long int __sysno, ...);

#define PUREFLAG_STDIN (1<<STDIN_FILENO)
#define PUREFLAG_STDOUT (1<<STDOUT_FILENO)
#define PUREFLAG_STDERR (1<<STDERR_FILENO)
#define PUREFLAG_STDALL (PUREFLAG_STDIN|PUREFLAG_STDOUT|PUREFLAG_STDERR)

sfun _pure_start(sfun pure_syscall, int flags);

long _pure_debug_printf(const char *format, ...);

#endif
