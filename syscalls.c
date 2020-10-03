/*   This is part of pure_libc (a project related to ViewOS and Virtual Square)
 *
 *   syscalls.c: syscall mgmt
 *
 *   Copyright 2006-2020 Renzo Davoli University of Bologna - Italy
 *   Copyright 2005 Andrea Gasparini University of Bologna - Italy
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>
#include <stdarg.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/sendfile.h>
#include <sys/xattr.h>
#include <sys/timeb.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <bits/wordsize.h>
#include <utime.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include "purelibc.h"

/* in case of pre-init call, use syscall */
sfun _pure_syscall = syscall;
sfun _pure_native_syscall;

#if defined(__NR_mmap2)
static int _pageshift()
{
	static int ps=0;
	if (ps == 0) {
		long pagesize=pagesize = sysconf(_SC_PAGESIZE);
		for (ps = -1;pagesize > 0; ps++, pagesize >>= 1)
			;
	}
	return ps;
}
#endif

long _pure_debug_printf(const char *format, ...)
{
	char *s;
	int rv;
	va_list ap;
	va_start(ap, format);

	rv=vasprintf(&s, format, ap);
	if (rv>0)
		_pure_native_syscall(__NR_write,2,s,strlen(s));
	free(s);
	va_end(ap);
	return rv;
}

// open must consider two mode of calling: with two or three arguments
int __open_2(const char* pathname,int flags){
#if defined(__NR_openat) && ! defined(__NR_open)
	return _pure_syscall(__NR_openat,AT_FDCWD,pathname,flags);
#else
	return _pure_syscall(__NR_open,pathname,flags);
#endif
}

static int __open_3(const char* pathname,int flags, mode_t mode) {
#if defined(__NR_openat) && ! defined(__NR_open)
	return _pure_syscall(__NR_openat,AT_FDCWD,pathname,flags,mode);
#else
	return _pure_syscall(__NR_open,pathname,flags,mode);
#endif
}

int open(const char* pathname,int flags,...){
	va_list arg_list;
	if( flags &  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return __open_3(pathname,flags,mode);
	}
	else
		return __open_2(pathname,flags);
}

int open64(const char* pathname,int flags,...){
	va_list arg_list;
	if( flags &  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return __open_3(pathname,flags|O_LARGEFILE,mode);
	}
	else
		return __open_2(pathname,flags|O_LARGEFILE);
}

int __open64_2 (const char* pathname,int flags){
	return __open_2(pathname,flags|O_LARGEFILE);
}

int creat(const char *pathname, mode_t mode)
{
	return __open_3(pathname,O_CREAT|O_WRONLY|O_TRUNC,mode);
}

int creat64(const char *pathname, mode_t mode)
{
	return __open_3(pathname,O_CREAT|O_WRONLY|O_TRUNC|O_LARGEFILE,mode);
}

int close(int fd){
	return _pure_syscall(__NR_close,fd);
}

ssize_t read(int fd,void* buf,size_t count){
	return _pure_syscall(__NR_read,fd,buf,count);
}

ssize_t write(int fd,const void* buf,size_t count){
	return _pure_syscall(__NR_write,fd,buf,count);
}

ssize_t readv(int filedes, const struct iovec *vector,
		int count)
{
	return _pure_syscall(__NR_readv, filedes, vector, count);
}

ssize_t writev(int filedes, const struct iovec *vector,
		int count)
{
	return _pure_syscall(__NR_writev, filedes, vector, count);
}

int dup(int oldfd){
	return _pure_syscall(__NR_dup, oldfd);
}

int dup2(int oldfd, int newfd){
#if defined(__NR_dup3) && ! defined(__NR_dup2)
	return _pure_syscall(__NR_dup3, oldfd, newfd, 0);
#else
	return _pure_syscall(__NR_dup2, oldfd, newfd);
#endif
}

#ifdef __NR_dup3
int dup3(int oldfd, int newfd, int flags){
	  return _pure_syscall(__NR_dup3, oldfd, newfd, flags);
}
#endif

/* When <sys/stat.h> is included, inline #defines for {,l,f}stat{,64} are
 * inserted and they make calls to __{,l,f}xstat{,64}. So we don't need
 * to define them.
 */

/* Since libc developers seem to be quite sadic in writing unreadable code,
 * making me go crazy trying to understand it, I decided to have some fun
 * myself. The following not-so-readable stuff takes care of calling the
 * correct 64-bit function on both 32 bit and 64 bit architectures.*/

#ifdef __NR_fstatat64
#define __NR_FSTATAT64 __NR_fstatat64
#endif
#ifdef __NR_newfstatat
#define __NR_FSTATAT64 __NR_newfstatat
#endif

#if __WORDSIZE == 64 || defined(__ILP32__)
# if defined(__NR_FSTATAT64) && ! defined(__NR_stat)
#  define __USE_FSTATAT64
# endif
#	define arch_stat64 stat
#	define IFNOT64(x)
#else
# if defined(__NR_FSTATAT64) && ! defined(__NR_stat64)
#  define __USE_FSTATAT64
# endif
#	define arch_stat64 stat64
#	define IFNOT64(x) x
#endif

#define INTERNAL_MAKE_NAME(a, b) a ## b
#define MAKE_NAME(a, b) INTERNAL_MAKE_NAME(a, b)

static void arch_stat64_2_stat(struct arch_stat64 *from, struct stat *to)
{
	if ((void*)from == (void*)to)
		return;

	to->st_dev = from->st_dev;
	to->st_ino = from->st_ino;
	to->st_mode = from->st_mode;
	to->st_nlink = from->st_nlink;
	to->st_uid = from->st_uid;
	to->st_gid = from->st_gid;
	to->st_rdev = from->st_rdev;
	to->st_size = from->st_size;
	to->st_blksize = from->st_blksize;
	to->st_blocks = from->st_blocks;
	to->st_atim = from->st_atim;
	to->st_mtim = from->st_mtim;
	to->st_ctim = from->st_ctim;

	return;
}

int __xstat(int ver, const char* pathname, struct stat* buf_stat)
{
	IFNOT64(struct stat64 *buf_stat64 = alloca(sizeof(struct stat64));)
	int rv;
	
	switch(ver)
	{
		case _STAT_VER_LINUX:
#ifdef __USE_FSTATAT64
			rv = _pure_syscall(__NR_FSTATAT64, AT_FDCWD, pathname, MAKE_NAME(buf_, arch_stat64), 0);
#else
			rv = _pure_syscall(MAKE_NAME(__NR_, arch_stat64), pathname, MAKE_NAME(buf_, arch_stat64));
#endif
			break;

		default:
			_pure_debug_printf("*** BUG! *** __xstat can't manage version %d!\n", ver);
			abort();
	}

	if (rv >= 0)
		arch_stat64_2_stat(MAKE_NAME(buf_, arch_stat64), buf_stat);

	return rv;
}

int __lxstat(int ver, const char* pathname, struct stat* buf_stat)
{
	IFNOT64(struct stat64 *buf_stat64 = alloca(sizeof(struct stat64));)
	int rv;
	
	switch(ver)
	{
		case _STAT_VER_LINUX:
#ifdef __USE_FSTATAT64
			rv = _pure_syscall(__NR_FSTATAT64, AT_FDCWD, pathname, MAKE_NAME(buf_, arch_stat64), AT_SYMLINK_NOFOLLOW);
#else
			rv = _pure_syscall(MAKE_NAME(__NR_l, arch_stat64), pathname, MAKE_NAME(buf_, arch_stat64));
#endif
			break;

		default:
			_pure_debug_printf("*** BUG! *** __lxstat can't manage version %d!\n", ver);
			abort();
	}

	if (rv >= 0)
		arch_stat64_2_stat(MAKE_NAME(buf_, arch_stat64), buf_stat);

	return rv;
}

int __fxstat(int ver, int fildes, struct stat* buf_stat)
{
	IFNOT64(struct stat64 *buf_stat64 = alloca(sizeof(struct stat64));)
	int rv;
	switch(ver)
	{
		case _STAT_VER_LINUX:
			rv = _pure_syscall(MAKE_NAME(__NR_f, arch_stat64), fildes, MAKE_NAME(buf_, arch_stat64));
			break;

		default:
			_pure_debug_printf("*** BUG! *** __fxstat can't manage version %d!\n", ver);
			abort();
	}
	if (rv >= 0)
		arch_stat64_2_stat(MAKE_NAME(buf_, arch_stat64), buf_stat);

	return rv;
}

int __xstat64(int ver,const char* pathname,struct stat64* buf){
#ifdef __USE_FSTATAT64
	return _pure_syscall(__NR_FSTATAT64, AT_FDCWD, pathname, buf, 0);
#else
	return _pure_syscall(MAKE_NAME(__NR_, arch_stat64), pathname, buf);
#endif
}

int __lxstat64(int ver,const char* pathname,struct stat64* buf){
#ifdef __USE_FSTATAT64
	return _pure_syscall(__NR_FSTATAT64, AT_FDCWD, pathname, buf,	AT_SYMLINK_NOFOLLOW);
#else
	return _pure_syscall(MAKE_NAME(__NR_l, arch_stat64), pathname, buf);
#endif
}

int __fxstat64 (int ver, int fildes, struct stat64 *buf){
	return _pure_syscall(MAKE_NAME(__NR_f, arch_stat64), fildes, buf);
}
/* end of unreadable code */
#ifdef __NR_statx
int statx(int dirfd, const char *pathname, int flags,
		unsigned int mask, struct statx *statxbuf) {
	return _pure_syscall(__NR_statx, dirfd, pathname, flags, mask, statxbuf);
}
#endif

int mknod(const char *pathname, mode_t mode, dev_t dev) {
#if defined(__NR_mknodat) && ! defined(__NR_mknod)
	return _pure_syscall(__NR_mknodat,AT_FDCWD,pathname,mode,dev);
#else
	return _pure_syscall(__NR_mknod,pathname,mode,dev);
#endif
}

int __xmknod (int ver, const char *path, mode_t mode, dev_t *dev) {
#if defined(__NR_mknodat) && ! defined(__NR_mknod)
	return _pure_syscall(__NR_mknodat,AT_FDCWD,path,mode,dev);
#else
	return _pure_syscall(__NR_mknod,path,mode,dev);
#endif
}

int access(const char* pathname,int mode){
#if defined(__NR_faccessat) && ! defined(__NR_access)
	return _pure_syscall(__NR_faccessat,AT_FDCWD,pathname,mode,0);
#else
	return _pure_syscall(__NR_access,pathname,mode);
#endif
}

int __access(const char* pathname,int mode){
	return access(pathname,mode);
}

ssize_t readlink(const char* pathname,char* buf, size_t bufsize){
#if defined(__NR_readlinkat) && ! defined(__NR_readlink)
	return _pure_syscall(__NR_readlinkat,AT_FDCWD,pathname,buf,bufsize);
#else
	return _pure_syscall(__NR_readlink,pathname,buf,bufsize);
#endif
}

int mkdir(const char* pathname,mode_t mode){
#if defined(__NR_mkdirat) && ! defined(__NR_mkdir)
	return _pure_syscall(__NR_mkdirat,AT_FDCWD,pathname,mode);
#else
	return _pure_syscall(__NR_mkdir,pathname,mode);
#endif
}

int rmdir(const char* pathname){
#if defined(__NR_unlinkat) && ! defined(__NR_rmdir)
	return _pure_syscall(__NR_unlinkat,AT_FDCWD,pathname,AT_REMOVEDIR);
#else
	return _pure_syscall(__NR_rmdir,pathname);
#endif
}

int chmod(const char* pathname,mode_t mode){
#if defined(__NR_fchownat) && ! defined(__NR_chmod)
	return _pure_syscall(__NR_fchownat,AT_FDCWD,pathname,mode,0);
#else
	return _pure_syscall(__NR_chmod,pathname,mode);
#endif
}

int fchmod(int fd,mode_t mode){
	return _pure_syscall(__NR_fchmod,fd,mode);
}

int chown(const char* pathname,uid_t owner,gid_t group){
#if defined(__NR_fchownat) && ! defined(__NR_chown)
	return _pure_syscall(__NR_fchownat,AT_FDCWD,pathname,owner,group,0);
#else
	return _pure_syscall(__NR_chown,pathname,owner,group);
#endif
}

int lchown(const char* pathname,uid_t owner,gid_t group){
#if defined(__NR_fchownat) && ! defined(__NR_lchown)
	return _pure_syscall(__NR_fchownat,AT_FDCWD,pathname,owner,group,AT_SYMLINK_NOFOLLOW);
#else
	return _pure_syscall(__NR_lchown,pathname,owner,group);
#endif
}

int fchown(int fd,uid_t owner,gid_t group){
	return _pure_syscall(__NR_fchown,fd,owner,group);
}

int link(const char* pathname,const char*newpath){
#if defined(__NR_linkat) && ! defined(__NR_link)
	return _pure_syscall(__NR_linkat,AT_FDCWD,pathname,AT_FDCWD,newpath,0);
#else
	return _pure_syscall(__NR_link,pathname,newpath);
#endif
}

int unlink(const char* pathname){
#if defined(__NR_unlinkat) && ! defined(__NR_unlink)
	return _pure_syscall(__NR_unlinkat,AT_FDCWD,pathname,0);
#else
	return _pure_syscall(__NR_unlink,pathname);
#endif
}

int symlink(const char* pathname,const char* newpath){
#if defined(__NR_symlinkat) && ! defined(__NR_symlink)
	return _pure_syscall(__NR_symlinkat,pathname,AT_FDCWD,newpath,0);
#else
	return _pure_syscall(__NR_symlink,pathname,newpath);
#endif
}

int rename(const char *oldpath, const char *newpath){
#if defined(__NR_renameat2) && ! defined(__NR_rename)
	return _pure_syscall(__NR_renameat2,AT_FDCWD,oldpath,AT_FDCWD,newpath,0);
#else
	return _pure_syscall(__NR_rename,oldpath,newpath);
#endif
}

int chdir(const char *path) {
	return _pure_syscall(__NR_chdir,path);
}

int fchdir(int fd) {
	return _pure_syscall(__NR_fchdir,fd);
}

int utimes(const char* pathname,const struct timeval tv[2]){
#if defined(__NR_utimensat) && ! defined(__NR_utimes)
	struct timespec ts[2] = {
		{tv[0].tv_sec, tv[0].tv_usec * 1000},
		{tv[1].tv_sec, tv[1].tv_usec * 1000}};
	return _pure_syscall(__NR_utimensat, AT_FDCWD, pathname, ts, 0);
#else
	return _pure_syscall(__NR_utimes,pathname,tv);
#endif
}

int utime(const char* pathname,const struct utimbuf *buf){
#ifdef __NR_utime
	return _pure_syscall(__NR_utime,pathname,buf);
#else
	struct timeval tv[2];
	tv[0].tv_sec = buf->actime;
	tv[1].tv_sec = buf->modtime;
	tv[0].tv_usec = tv[1].tv_usec = 0;
	return utimes(pathname, tv);
#endif
}

#ifdef __NR_pread
ssize_t pread(int fs,void* buf, size_t count, __off_t offset){
	return _pure_syscall(__NR_pread,fs,buf,count,offset);
}
#endif

#ifdef __NR_pwrite
ssize_t pwrite(int fs,const void* buf, size_t count, __off_t offset){
	return _pure_syscall(__NR_pwrite,fs,buf,count,offset);
}
#endif

#ifdef __NR_pread64
ssize_t pread64(int fs,void* buf, size_t count, __off64_t offset){
	return _pure_syscall(__NR_pread64,fs,buf,count,
#if defined(__powerpc__) || defined(__arm__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(offset>>32),(__off_t)(offset&0xffffffff)));
}
ssize_t pread(int fs,void* buf, size_t count, __off_t offset){
	return pread64(fs,buf,count,(__off64_t)offset);
}
#endif

#ifdef __NR_pwrite64
ssize_t pwrite64(int fs,const void* buf, size_t count, __off64_t offset){
	return _pure_syscall(__NR_pwrite64,fs,buf,count,
#if defined(__powerpc__) || defined(__arm__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(offset>>32),(__off_t)(offset&0xffffffff)));
}
ssize_t pwrite(int fs,const void* buf, size_t count, __off_t offset){
	return pwrite64(fs,buf,count,(__off64_t)offset);
}
#endif

#ifdef __NR_preadv
ssize_t preadv64(int fs,const struct iovec *iov, int iovcnt, __off64_t offset){
	ssize_t rv=_pure_syscall(__NR_preadv,fs,iov,iovcnt,
#ifdef __NR_pread64
#if defined(__powerpc__) || defined(__arm__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(offset>>32),(__off_t)(offset&0xffffffff))
#else
			offset
#endif
			);
	if (rv==-1 && errno==ENOSYS) {
		ssize_t totalsize;
		unsigned char *buf,*scan;
		int i;
		for (i=totalsize=0; i<iovcnt; i++)
			totalsize+=iov[i].iov_len;
		buf=malloc(totalsize);
		if (buf==NULL) {
			errno=ENOMEM;
			return -1;
		}
		totalsize=pread64(fs, buf, totalsize, offset);
		rv=totalsize;
		for (i=0,scan=buf; i<iovcnt && totalsize>0; i++,
				scan+=iov[i].iov_len,
				totalsize-=iov[i].iov_len)
			memcpy(iov[i].iov_base, scan, iov[i].iov_len);
		free(buf);
	}
	return rv;
}

ssize_t preadv(int fs,const struct iovec *iov, int iovcnt, __off_t offset){
	return preadv64(fs,iov,iovcnt,(__off64_t)offset);
}
#endif

#ifdef __NR_pwritev
ssize_t pwritev64(int fs,const struct iovec *iov, int iovcnt, __off64_t offset){
	ssize_t rv=_pure_syscall(__NR_pwritev,fs,iov,iovcnt,
#ifdef __NR_pwrite64
#if defined(__powerpc__) || defined(__arm__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(offset>>32),(__off_t)(offset&0xffffffff))
#else
			offset
#endif
			);
	if (rv==-1 && errno==ENOSYS) {
		ssize_t totalsize;
		unsigned char *buf,*scan;
		int i;
		for (i=totalsize=0; i<iovcnt; i++)
			totalsize+=iov[i].iov_len;
		buf=malloc(totalsize);
		if (buf==NULL) {
			errno=ENOMEM;
			return -1;
		}
		for (i=0,scan=buf; i<iovcnt; i++, scan+=iov[i].iov_len)
			memcpy(scan, iov[i].iov_base, iov[i].iov_len);
		rv=pwrite64(fs, buf, totalsize, offset);
		free(buf);
	}
	return rv;
}

ssize_t pwritev(int fs,const struct iovec *iov, int iovcnt, __off_t offset){
	return pwritev64(fs,iov,iovcnt,(__off64_t)offset);
}
#endif

/* getdents has no libc wrapper.
	 libc uses getdents64 only on 64 bit archs */
int getdents(int fd, void *dirp, unsigned int count){
#ifdef __NR_getdents
	return _pure_syscall(__NR_getdents, fd, dirp, count);
#else
	errno = ENOSYS;
	return -1;
#endif
}

__ssize_t getdents64(int fd, void *dirp, size_t count){
	return _pure_syscall(__NR_getdents64, fd, dirp, count);
}

__off_t lseek(int fd,__off_t offset,int whence){
	return _pure_syscall(__NR_lseek,fd,offset,whence);
}

#ifndef __NR__llseek
off64_t lseek64(int fd, off64_t offset, int whence) {
	return lseek(fd, offset, whence);
}
#endif

#ifdef __NR__llseek
__off64_t lseek64(int fd, __off64_t offset, int whence){
	unsigned long offset_high=offset >> (sizeof(unsigned long) * 8);
	unsigned long offset_low=offset;
	__off64_t result;
	int rv=_pure_syscall(__NR__llseek,fd,offset_high,offset_low,&result,whence);
	if (rv<0)
		return rv;
	else
		return result;
}

__off64_t llseek(int fd, __off64_t offset, int whence){
	return lseek64(fd,offset,whence);
}

int _llseek(unsigned int fd, unsigned long  offset_high,  unsigned  long  offset_low,  loff_t
		       *result, unsigned int whence){
	return _pure_syscall(__NR__llseek,fd,offset_high,offset_low,result,whence);
}
#endif

int fsync(int fd){
	return _pure_syscall(__NR_fsync,fd);
}

#if defined(__powerpc__)
/* DAMNED! Another kernel specific structure needs lib conversion! */
#include<sys/ioctl.h>
#include<termios.h>
#include"kernel_termios.ppc.h"

static void termios_k2l(struct termios *dst,struct __kernel_termios *src) {
	register int i;
	dst->c_iflag = src->c_iflag;
	dst->c_oflag = src->c_oflag;
	dst->c_cflag = src->c_cflag;
	dst->c_lflag = src->c_lflag;
	dst->c_line = src->c_line;
	dst->c_ispeed = src->c_ispeed;
	dst->c_ospeed = src->c_ospeed;
	for (i=0; i<__KERNEL_NCCS; i++)
		dst->c_cc[i]=src->c_cc[i];
	for (;i<NCCS;i++)
		dst->c_cc[i]=_POSIX_VDISABLE;
}

static void termios_l2k(struct __kernel_termios *dst,struct termios *src) {
	register int i;
	dst->c_iflag = src->c_iflag;
	dst->c_oflag = src->c_oflag;
	dst->c_cflag = src->c_cflag;
	dst->c_lflag = src->c_lflag;
	dst->c_line = src->c_line;
	dst->c_ispeed = src->c_ispeed;
	dst->c_ospeed = src->c_ospeed;
	for (i=0; i<__KERNEL_NCCS; i++)
		dst->c_cc[i]=src->c_cc[i];
}

static int ioctl_ppc(int fd,unsigned long int request, long int arg){
	int result;
	switch (request) {
		case TCGETS: {
									 struct __kernel_termios kt;
									 result = _pure_syscall (__NR_ioctl, fd, request, &kt);
									 termios_k2l((struct termios *) arg, &kt);
									 break;
								 }
		case TCSETS:
		case TCSETSW:
		case TCSETSF: {
										struct __kernel_termios kt;
										termios_l2k(&kt,(struct termios *) arg);
										result = _pure_syscall (__NR_ioctl, fd, request, &kt);
										break;
									}
		default:
									result = _pure_syscall (__NR_ioctl, fd, request, arg);
									break;
	}
	return result;
}
#endif

int ioctl(int fd,unsigned long int request, ...){
	va_list ap;
	long int arg;
	va_start(ap, request);
	arg=va_arg(ap,  long int);
	va_end(ap);
	int rv=0;
#if defined(__powerpc__)
		ioctl_ppc(fd,request,arg);
#else
		rv= _pure_syscall(__NR_ioctl,fd,request,arg);
#endif
	return rv;
}

int fcntl(int fd, int cmd, ...){
	va_list ap;
	long int arg1;
	long int arg2;
	va_start(ap, cmd);
	arg1=va_arg(ap,  long int);
	arg2=va_arg(ap,  long int);
	va_end(ap);
	/* XXX Check the fcntl->fcntl64 conversion */
#ifdef __NR_fcntl64
	switch (cmd) {
		case F_GETLK:
		case F_SETLK:
		case F_SETLKW:
			return _pure_syscall(__NR_fcntl,fd,cmd,arg1,arg2);
		default:
			return _pure_syscall(__NR_fcntl64,fd,cmd,arg1,arg2);
	}
#else
	return _pure_syscall(__NR_fcntl,fd,cmd,arg1,arg2);
#endif
}

#ifdef __NR_fcntl64
int fcntl64(int fd, int cmd, ...){
	va_list ap;
	long int arg1;
	long int arg2;
	va_start(ap, cmd);
	arg1=va_arg(ap,  long int);
	arg2=va_arg(ap,  long int);
	va_end(ap);
	return _pure_syscall(__NR_fcntl64,fd,cmd,arg1,arg2);
}
#endif

int mount(const char *source, const char *target, const char *filesystemtype, unsigned  mountflags, const void *data){
	return _pure_syscall(__NR_mount,source,target,filesystemtype,mountflags,data);
}

#ifndef __NR_umount
#define __NR_umount __NR_umount2
#endif
int umount(const char *target){
		// umount ignore the last argument, is only for umount2
	return _pure_syscall(__NR_umount,target,0);
}

int umount2(const char *target, int flags){
	return _pure_syscall(__NR_umount,target,flags);
}

pid_t getpid(void){
	return _pure_syscall(__NR_getpid);
}

pid_t getppid(void){
	return _pure_syscall(__NR_getppid);
}

int setpgid(pid_t pid, pid_t pgid){
	return _pure_syscall(__NR_setpgid,pid,pgid);
}

pid_t getpgid(pid_t pid){
	return _pure_syscall(__NR_getpgid,pid);
}

int setpgrp(void){
	return _pure_syscall(__NR_setpgid,0,0);
}

pid_t getpgrp(void){
	return _pure_syscall(__NR_getpgid,0);
}

int setuid(uid_t uid){
	return _pure_syscall(__NR_setuid,uid);
}

int setgid(gid_t gid){
	return _pure_syscall(__NR_setgid,gid);
}

int seteuid(uid_t euid){
	return _pure_syscall(__NR_setreuid,-1,euid);
}

int setegid(gid_t egid){
	return _pure_syscall(__NR_setregid,-1,egid);
}

uid_t getuid(void) {
	return _pure_syscall(__NR_getuid);
}
uid_t __getuid(void) {
	return getuid();
}

gid_t getgid(void) {
	return _pure_syscall(__NR_getgid);
}
gid_t __getgid(void) {
	return getgid();
}

uid_t geteuid(void) {
	return _pure_syscall(__NR_geteuid);
}
uid_t __geteuid(void) {
	return geteuid();
}

gid_t getegid(void) {
	return _pure_syscall(__NR_getegid);
}
gid_t __getegid(void) {
	return getegid();
}

int setreuid(uid_t ruid, uid_t euid){
	return _pure_syscall(__NR_setreuid,ruid,euid);
}

int setregid(gid_t rgid, gid_t egid){
	return _pure_syscall(__NR_setregid,rgid,egid);
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid){
	return _pure_syscall(__NR_setresuid,ruid,euid,suid);
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid){
	return _pure_syscall(__NR_setresgid,rgid,egid,sgid);
}

int pipe(int filedes[2]) {
#if defined(__NR_pipe2) && ! defined(__NR_pipe)
	return _pure_syscall(__NR_pipe2,filedes, 0);
#else
	return _pure_syscall(__NR_pipe,filedes);
#endif
}

#ifdef __NR_pipe2
int pipe2(int filedes[2],int flags) {
	  return _pure_syscall(__NR_pipe2,filedes,flags);
}
#endif

mode_t umask(mode_t mask){
	return _pure_syscall(__NR_umask,mask);
}

int chroot(const char *path){
	return _pure_syscall(__NR_chroot,path);
}

int execve(const char *filename, char *const argv [], char *const envp[])
{
	return _pure_syscall(__NR_execve,filename,argv,envp);
}

void _exit(int status){
	_pure_syscall(__NR_exit,status);
	/* never reached, just to avoid "noreturn" warnings */
	_exit(status);
}

void _Exit(int status){
	_pure_syscall(__NR_exit,status);
	/* never reached, just to avoid "noreturn" warnings */
	_exit(status);
}

pid_t fork(void){
#if defined(__ia64__)
	int child_tid;
	if (_pure_syscall(__NR_clone2,
				CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD,
				NULL, 0, NULL, &child_tid, NULL) < 0)
		return -1;
	else
		return child_tid;
#elif defined(__aarch64__)
	int child_tid;
	if (_pure_syscall(__NR_clone, NULL, CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, &child_tid) < 0)
		return -1;
	else
		return child_tid;
#else
	return _pure_syscall(__NR_fork);
#endif
}

pid_t vfork(void){
	 /*The  BSD  man  page  states:  "This system call will be eliminated when
	 * proper system sharing mechanisms are  implemented.   Users  should  not
	 * depend  on  the memory sharing semantics of vfork() as it will, in that
	 * case, be made synonymous to fork(2)." */
	return fork();
}

int stime(const time_t *t){
	struct timeval tivu = { *t,0};
	return _pure_syscall(__NR_settimeofday,&tivu,NULL);
}

long int ptrace (enum __ptrace_request request, ...){
	va_list ap;
	pid_t pid;
	void *addr;
	void *data;
	long int res, ret;
	va_start(ap, request);
	pid=va_arg(ap, pid_t);
	addr=va_arg(ap, void *);
	data=va_arg(ap, void *);
	va_end(ap);
	if (request > 0 && request < 4)
		data = &ret;
	res = _pure_syscall(__NR_ptrace,request,pid,addr,data);
	if (res >= 0 && request > 0 && request < 4) {
		errno = 0;
		return ret;
	} else
		return res;
}

int nice(int inc){
#if defined(__x86_64__) || defined(__ia64__) || \
	defined(__alpha__) || defined(__s390x__) || \
	(defined(__mips__) && defined(__LP64__)) || \
	defined(__aarch64__) || \
	defined(__riscv__)
	int nice = _pure_syscall(__NR_getpriority,PRIO_PROCESS,0);
	return _pure_syscall(__NR_setpriority,PRIO_PROCESS,0,nice + inc);
#else
	return _pure_syscall(__NR_nice,inc);
#endif
}

void sync(void){
	_pure_syscall(__NR_sync);
}

clock_t times(struct tms *buf){
	return _pure_syscall(__NR_times,buf);
}

struct ustat;
int ustat(dev_t dev, struct ustat *ubuf){
#ifdef __NR_ustat
	return _pure_syscall(__NR_ustat,dev,ubuf);
#else
	errno = ENOSYS;
	return -1;
#endif
}

pid_t getsid(pid_t pid){
	return _pure_syscall(__NR_getsid,pid);
}

pid_t setsid(void){
	return _pure_syscall(__NR_setsid);
}

int sethostname(const char *name, size_t len){
	return _pure_syscall(__NR_sethostname,name,len);
}

#ifdef __NR_prlimit64
int prlimit(pid_t pid, enum __rlimit_resource resource, const struct rlimit *new_limit,
		struct rlimit *old_limit) {
	return _pure_syscall(__NR_prlimit64, pid, resource, new_limit, old_limit);
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim){
	return prlimit(0,resource,rlim,NULL);
}

int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim){
	return prlimit(0,resource,NULL,rlim);
}
#else
int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim){
	return _pure_syscall(__NR_setrlimit,resource,rlim);
}

int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim){
	return _pure_syscall(__NR_getrlimit,resource,rlim);
}
#endif

int getrusage(int who, struct rusage *usage){
	return _pure_syscall(__NR_getrusage,usage);
}

#ifdef GETTIMEOFDAY_TZ
int gettimeofday(struct timeval *tv, struct timezone *tz)
#else
int gettimeofday(struct timeval *tv, void *tz)
#endif
{
	return _pure_syscall(__NR_gettimeofday, tv, tz);
}

int settimeofday(const struct timeval *tv , const struct timezone *tz){
	return _pure_syscall(__NR_settimeofday, tv, tz);
}

time_t time(time_t *t){
#ifdef __NR_time
	return _pure_syscall(__NR_time,t);
#else
	struct timeval tv;
	if (gettimeofday(&tv, NULL) == 0) {
		if (t) *t = tv.tv_sec;
		return tv.tv_sec;
	} else
		return -1;
#endif
}

int getgroups(int size, gid_t list[]){
	return _pure_syscall(__NR_getgroups,size,list);
}

#ifdef __NR_faccessat
static int _is_group_member(gid_t gid) {
  int len = getgroups(0, NULL);
  gid_t list[len];
  int i;
  len = getgroups(len, list);
  for (i = 0; i < len; i++) {
    if (gid == list[i])
      return 1;
  }
  return 0;
}
#endif

int setgroups(size_t size, const gid_t *list){
	return _pure_syscall(__NR_setgroups,size,list);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct timespec *timeout,
		const sigset_t *sigmask) {
	return _pure_syscall(__NR_pselect6,nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int ppoll(struct pollfd *fds, nfds_t nfds,
		const struct timespec *tmo_p, const sigset_t *sigmask) {
	return _pure_syscall(__NR_ppoll,fds,nfds,tmo_p,sigmask);
}

#ifdef __NR_epoll_create1
int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout){
#if defined(__x86_64__) || defined(__s390x__) || \
	defined(__alpha__) || defined(__ia64__) || \
	defined(__riscv__)
	return _pure_syscall(__NR_select,n,readfds,writefds,exceptfds,timeout);
#elif defined(__aarch64__)
	if (timeout == NULL)
		return pselect(n,readfds,writefds,exceptfds,NULL,NULL);
	else {
		struct timespec ts = {timeout->tv_sec, timeout->tv_usec * 1000};
		return pselect(n,readfds,writefds,exceptfds,&ts,NULL);
	}
#else
	return _pure_syscall(__NR__newselect,n,readfds,writefds,exceptfds,timeout);
#endif
}

int poll(struct pollfd *ufds, nfds_t nfds, int timeout){
#if defined(__NR_poll)
	return _pure_syscall(__NR_poll,ufds,nfds,timeout);
#else
	if (timeout < 0)
		return  _pure_syscall(__NR_ppoll,ufds,nfds, NULL, NULL);
	else {
		struct timespec ts = {timeout, 0};
		return  _pure_syscall(__NR_ppoll,ufds,nfds, &ts, NULL);
	}
#endif
}

int epoll_create1(int flags) {
	return _pure_syscall(__NR_epoll_create1, flags);
}

int epoll_create(int size) {
	if (size <= 0) {
		errno = EINVAL;
		return -1;
	} else
		return _pure_syscall(__NR_epoll_create1, 0);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
	return _pure_syscall(__NR_epoll_ctl,epfd,op,fd,event);
}

int epoll_wait(int epfd, struct epoll_event *events,
		int maxevents, int timeout) {
	return _pure_syscall(__NR_epoll_pwait,epfd,events,maxevents,timeout,NULL);
}

int epoll_pwait(int epfd, struct epoll_event *events,
		int maxevents, int timeout,
		const sigset_t *sigmask) {
	return _pure_syscall(__NR_epoll_pwait,epfd,events,maxevents,timeout,sigmask);
}
#endif

int truncate(const char *path, __off_t length){
	return _pure_syscall(__NR_truncate,path,length);
}

int ftruncate(int fd, __off_t length){
	return _pure_syscall(__NR_ftruncate,fd,length);
}

#ifdef __NR_truncate64
int truncate64(const char *path, __off64_t length){
	return _pure_syscall(__NR_truncate64,path,
#if defined(__powerpc__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(length>>32),(__off_t)(length&0xffffffff)));
}
#endif

#ifdef __NR_ftruncate64
int ftruncate64(int fd, __off64_t length){
	return _pure_syscall(__NR_ftruncate64,fd,
#if defined(__powerpc__)
			0,
#endif
			__LONG_LONG_PAIR( (__off_t)(length>>32),(__off_t)(length&0xffffffff)));
}
#endif

int getpriority(__priority_which_t which, id_t who){
	return _pure_syscall(__NR_getpriority,which,who);
}

int setpriority(__priority_which_t which, id_t who, int prio){
	return _pure_syscall(__NR_setpriority,which,who,prio);
}

int statfs(const char *path, struct statfs *buf){
	return _pure_syscall(__NR_statfs,path,buf);
}

int fstatfs(int fd, struct statfs *buf){
	return _pure_syscall(__NR_fstatfs,fd,buf);
}

#ifdef __NR_statfs64
/* LIBC add an extra arg: the buf size */
int statfs64(const char *path, struct statfs64 *buf){
	return _pure_syscall(__NR_statfs64,path,sizeof(struct statfs64), buf);
}
#endif 

#ifdef __NR_fstatfs64
int fstatfs64(int fd, struct statfs64 *buf){
	return _pure_syscall(__NR_fstatfs64,fd,sizeof(struct statfs64), buf);
}
#endif

int getitimer(__itimer_which_t which, struct itimerval *value){
	return _pure_syscall(__NR_getitimer,which,value);
}

int setitimer(__itimer_which_t which, const struct itimerval *value, struct itimerval *ovalue){
	return _pure_syscall(__NR_setitimer,which,value,ovalue);
}

pid_t waitpid(pid_t pid, int *status, int options){
	return _pure_syscall(__NR_wait4,pid,status,options,NULL);
}

#ifdef __NR_waitid
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options){
	return _pure_syscall(__NR_waitid,idtype,id,infop,options);
}
#endif

pid_t wait3(int *status, int options, struct rusage *rusage){
	return _pure_syscall(__NR_wait4,-1,status,options,rusage);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage){
	return _pure_syscall(__NR_wait4,pid,status,options,rusage);
}

int sysinfo(struct sysinfo *info){
	return _pure_syscall(__NR_sysinfo,info);
}

#ifdef __NR_ipc
int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth){
	return _pure_syscall(__NR_ipc,first,second,third,ptr,fifth);
}
#endif

int setdomainname(const char *name, size_t len){
	return _pure_syscall(__NR_setdomainname,name,len);
}

int uname(struct utsname *buf){
	return _pure_syscall(__NR_uname,buf);
}

int adjtimex(struct timex *buf){
	return _pure_syscall(__NR_adjtimex,buf);
}

#ifdef __NR_sysfs
int sysfs(int option,...){
	switch (option) {
		case 1: {
							va_list ap;
							char *fsname;
							va_start(ap, option);
							fsname=va_arg(ap, char *);
							va_end(ap);
							return _pure_syscall(__NR_sysfs,option,fsname);
						}
		case 2: {
							va_list ap;
							unsigned int fs_index;
							char *buf;
							va_start(ap, option);
							fs_index=va_arg(ap, unsigned int);
							buf=va_arg(ap, char *);
							va_end(ap);
							return _pure_syscall(__NR_sysfs,option,fs_index,buf);
						}
		case 3:
						 return _pure_syscall(__NR_sysfs,option);
		default:
						 errno=EINVAL;
						 return -1;
	}
}
#endif

int setfsuid(uid_t fsuid){
	return _pure_syscall(__NR_setfsuid,fsuid);
}

int setfsgid(uid_t fsgid){
	return _pure_syscall(__NR_setfsgid,fsgid);
}

int flock(int fd, int operation){
	return _pure_syscall(__NR_flock,fd,operation);
}

int fdatasync(int fd){
	return _pure_syscall(__NR_fdatasync,fd);
}

char *getcwd(char *buf, size_t size){
	int rsize;
	if (size == 0 && buf==NULL) {
		size=PATH_MAX;
		buf=malloc(size);
		if (buf==NULL)
			return NULL;
		else {
			rsize=_pure_syscall(__NR_getcwd,buf,size);
			if (rsize>=0) {
				buf=realloc(buf,rsize);
				return buf;
			} else {
				free(buf);
				return NULL;
			}
		}
	} else {
		rsize=_pure_syscall(__NR_getcwd,buf,size);
		if (rsize>=0)
			return buf;
		else
			return NULL;
	}
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count){
	return _pure_syscall(__NR_sendfile,out_fd,in_fd,offset,count);
}

/*
pid_t gettid(void){
	return _pure_syscall(__NR_gettid);
}*/
			
int setxattr (const char *path, const char *name,
		     const void *value, size_t size, int flags){
	return _pure_syscall(__NR_setxattr,path,name,value,size,flags);
}

int lsetxattr (const char *path, const char *name,
		      const void *value, size_t size, int flags){
	return _pure_syscall(__NR_lsetxattr,path,name,value,size,flags);
}

int fsetxattr (int fd, const char *name, const void *value,
		      size_t size, int flags){
	return _pure_syscall(__NR_fsetxattr,fd,name,value,size,flags);
}

ssize_t getxattr (const char *path, const char *name,
			 void *value, size_t size){
	return _pure_syscall(__NR_getxattr,path,name,value,size);
}

ssize_t lgetxattr (const char *path, const char *name,
			  void *value, size_t size){
	return _pure_syscall(__NR_lgetxattr,path,name,value,size);
}

ssize_t fgetxattr (int fd, const char *name, void *value,
			  size_t size) {
	return _pure_syscall(__NR_fgetxattr,fd,name,value,size);
}

ssize_t listxattr (const char *path, char *list, size_t size){
	return _pure_syscall(__NR_listxattr,path,list,size);
}

ssize_t llistxattr (const char *path, char *list, size_t size){
	return _pure_syscall(__NR_llistxattr,path,list,size);
}

ssize_t flistxattr (int fd, char *list, size_t size){
	return _pure_syscall(__NR_flistxattr,fd,list,size);
}

int removexattr (const char *path, const char *name){
	return _pure_syscall(__NR_removexattr,path,name);
}

int lremovexattr (const char *path, const char *name){
	return _pure_syscall(__NR_lremovexattr,path,name);
}

int fremovexattr (int fd, const char *name){
	return _pure_syscall(__NR_fremovexattr,fd,name);
}

int clock_getres(clockid_t clk_id, struct timespec *res){
	return _pure_syscall(__NR_clock_getres,clk_id,res);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp){
	return _pure_syscall(__NR_clock_gettime,clk_id,tp);
}

int clock_settime(clockid_t clk_id, const struct timespec *tp){
	return _pure_syscall(__NR_clock_settime,clk_id,tp);
}

static void statfs2vfs(struct statfs *sfs,struct statvfs *vsfs)
{
	vsfs->f_bsize=sfs->f_bsize;
	vsfs->f_frsize=0;
	vsfs->f_blocks=sfs->f_blocks;
	vsfs->f_bfree=sfs->f_bfree;
	vsfs->f_bavail=sfs->f_bavail;
	vsfs->f_files=sfs->f_files;
	vsfs->f_ffree=sfs->f_ffree;
	vsfs->f_favail=sfs->f_ffree;
	/*vsfs->f_fsid=sfs->f_fsid;*/
	vsfs->f_flag=0;
	vsfs->f_namemax=sfs->f_namelen;
}

int statvfs(const char *path, struct statvfs *buf){
	struct statfs sfs;
	int rv=_pure_syscall(__NR_statfs,path,&sfs);
	if (rv >= 0) statfs2vfs(&sfs,buf);
	return rv;
}

int fstatvfs(int fd, struct statvfs *buf){
	struct statfs sfs;
	int rv=_pure_syscall(__NR_fstatfs,fd,&sfs);
	if (rv >= 0) statfs2vfs(&sfs,buf);
	return rv;
}

void *mmap(void  *start, size_t length, int prot, int flags, int fd,
		       off_t offset)
{
#if defined(__NR_mmap2)
		return (void *) _pure_syscall(__NR_mmap2,start,length,prot,flags,fd,offset>> _pageshift());
#else
		return (void *) _pure_syscall(__NR_mmap,start,length,prot,flags,fd,offset);
#endif
}

#if defined(__NR_mmap2)
void *mmap2(void  *start, size_t length, int prot, int flags, int fd,
		       off_t pgoffset)
{
		return (void *) _pure_syscall(__NR_mmap2,start,length,prot,flags,fd,pgoffset);
}
#endif

int munmap(void *start, size_t length)
{
	return _pure_syscall(__NR_munmap,start,length);
}

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 5
void *mremap(void  *old_address,  size_t old_size , size_t new_size,
		       int flags, ...)
{
	va_list ap;
	va_start (ap, flags);
	void *newaddr = (flags & MREMAP_FIXED) ? va_arg (ap, void *) : NULL;
	va_end (ap);
	return (void *) _pure_syscall(__NR_mremap,old_address,old_size,new_size,flags,newaddr);
}
#else
void *mremap(void  *old_address,  size_t old_size , size_t new_size,
		       int flags)
{
	return (void *) _pure_syscall(__NR_mremap,old_address,old_size,new_size,flags);
}
#endif

int ftime(struct timeb *tp){
	struct timeval tv;
	struct timezone tz;
	int rv=gettimeofday(&tv,&tz);
	tp->time  = tv.tv_sec;
	tp->millitm = tv.tv_usec/1000;
	tp->timezone = timezone;
	tp->dstflag = daylight;
	return rv;
}

/* *at syscalls */

#ifdef __NR_openat
int openat(int dirfd,const char* pathname,int flags,...){
	va_list arg_list;
	if( flags &  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return _pure_syscall(__NR_openat,dirfd,pathname,flags,mode);
	}
	else
		return _pure_syscall(__NR_openat,dirfd,pathname,flags);
}

int openat64(int dirfd,const char* pathname,int flags,...){
	va_list arg_list;
	if( flags &  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return _pure_syscall(__NR_openat,dirfd,pathname,flags|O_LARGEFILE,mode);
	}
	else
		return _pure_syscall(__NR_openat,dirfd,pathname,flags|O_LARGEFILE);
}

int	__openat_2(int dirfd, const char *pathname, int flags)
{
	return _pure_syscall(__NR_openat,dirfd,pathname,flags);
}

int	__openat64_2(int dirfd, const char *pathname, int flags)
{
	return _pure_syscall(__NR_openat,dirfd,pathname,flags|O_LARGEFILE);
}
#endif

#ifdef __NR_mkdirat
int mkdirat(int dirfd,const char* pathname,mode_t mode){
	  return _pure_syscall(__NR_mkdirat,dirfd,pathname,mode);
}
#endif

#ifdef __NR_mknodat
int mknodat(int dirfd,const char *pathname, mode_t mode, dev_t dev) {
	  return _pure_syscall(__NR_mknodat,dirfd,pathname,mode,dev);
}
#endif

#ifdef __NR_fchownat
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
	return _pure_syscall(__NR_fchownat,dirfd,pathname,owner,group,flags);
}
#endif

#ifdef __NR_futimesat
int futimesat(int dirfd, const char *pathname, const struct timeval times[2]) {
	return _pure_syscall(__NR_futimesat,dirfd,pathname,times);
}
#endif

#ifdef __NR_FSTATAT64
int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
	return _pure_syscall(__NR_FSTATAT64,dirfd,pathname,buf,flags);
}
int __fxstatat64 (int ver, int dirfd, const char *pathname, struct stat64 *buf, int flags){
	return _pure_syscall(__NR_FSTATAT64,dirfd,pathname,buf,flags);
}
int __fxstatat(int ver, int fildes, const char *pathname, struct stat* buf_stat,int flags)
{
	IFNOT64(struct stat64 *buf_stat64 = alloca(sizeof(struct stat64));)
	int rv;
	switch(ver)
	{
		case _STAT_VER_LINUX:
			rv = _pure_syscall(__NR_FSTATAT64, fildes, pathname, MAKE_NAME(buf_, arch_stat64), flags);
			break;

		default:
			_pure_debug_printf("*** BUG! *** __fxstatat can't manage version %d!\n", ver);
			abort();
	}
	if (rv >= 0)
		arch_stat64_2_stat(MAKE_NAME(buf_, arch_stat64), buf_stat);
	return rv;
}
#endif

#ifdef __NR_unlinkat
int unlinkat(int dirfd, const char *pathname, int flags){
	return _pure_syscall(__NR_unlinkat,dirfd,pathname,flags);
}
#endif

#ifdef __NR_renameat
int renameat(int olddirfd, const char *oldpath,int newdirfd, const char *newpath){
	return _pure_syscall(__NR_renameat,olddirfd,oldpath,newdirfd,newpath);
}
#endif

#ifdef __NR_renameat2
int renameat2(int olddirfd, const char *oldpath,int newdirfd, const char *newpath, unsigned int flags){
	return _pure_syscall(__NR_renameat2,olddirfd,oldpath,newdirfd,newpath,flags);
}
#endif

#ifdef __NR_linkat
int linkat(int olddirfd, const char *oldpath,int newdirfd, const char *newpath, int flags){
	return _pure_syscall(__NR_linkat,olddirfd,oldpath,newdirfd,newpath,flags);
}
#endif

#ifdef __NR_symlinkat
int symlinkat(const char *oldpath, int newdirfd, const char *newpath){
	return _pure_syscall(__NR_symlinkat,oldpath,newdirfd,newpath);
}
#endif

#ifdef __NR_readlinkat
ssize_t readlinkat(int dirfd, const char *pathname,char *buf, size_t bufsiz){
	return _pure_syscall(__NR_readlinkat,dirfd,pathname,buf,bufsiz);
}
#endif

#ifdef __NR_fchmodat
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags){
	return _pure_syscall(__NR_fchmodat,dirfd,pathname,mode,flags);
}
#endif

#ifdef __NR_faccessat
//The raw faccessat() system call takes only the first  three  arguments
// this function has been inspired by glibc: sysdeps/unix/sysv/linux/faccessat.c
int faccessat(int dirfd, const char *pathname, int mode, int flags){
	if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW)) {
    errno = EINVAL;
    return -1;
  }

	if (flags == 0)
		return _pure_syscall(__NR_faccessat,dirfd,pathname,mode);
	else {
		struct stat stats;
		if (fstatat(dirfd, pathname, &stats, flags & AT_SYMLINK_NOFOLLOW) < 0)
			return -1;
		mode &= (R_OK | W_OK | X_OK);
		if (mode == F_OK)
			return 0;
		uid_t uid = (flags & AT_EACCESS) ? geteuid() : getuid();
		if (uid == 0) { // it is root
			if ((mode & X_OK) == 0) // RW are always allowed
				return 0;
			// X OK is X is okay for someone
			if (stats.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
				return 0;
		}

		int granted;
		if (uid == stats.st_uid)
			// user permissions
			granted = (int) ((stats.st_mode >> 6) & mode);
		else {
			gid_t gid = (flags & AT_EACCESS) ? getegid() : getgid();
			if (stats.st_gid == gid || _is_group_member(stats.st_gid))
				// group permissions
				granted = (int) ((stats.st_mode >> 3) & mode);
			else
				// other permissions
				granted = stats.st_mode & mode;
		}
		if (granted == mode)
			return 0;

		errno = EACCES;
		return -1;
	}
}

int euidaccess(const char *pathname, int mode){
	return faccessat(AT_FDCWD,pathname,mode,AT_EACCESS);
}
int eaccess(const char *pathname, int mode){
	return euidaccess(pathname,mode);
}
int __euidaccess(const char *pathname, int mode){
	return euidaccess(pathname,mode);
}
#endif

#ifdef __NR_utimensat
int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags){
	return _pure_syscall(__NR_utimensat,dirfd,pathname,times,flags);
}
#endif

int raise(int sig) {
	return kill(getpid(), sig);
}

static void init(void);
long int syscall(long int n,...)
{
	long int arg0,arg1,arg2,arg3,arg4,arg5;
	va_list ap;
	va_start(ap, n);
	arg0=va_arg(ap, long int);
	arg1=va_arg(ap, long int);
	arg2=va_arg(ap, long int);
	arg3=va_arg(ap, long int);
	arg4=va_arg(ap, long int);
	arg5=va_arg(ap, long int);
	va_end(ap);
	/* in case of pre-init call: emergency initialization */
	if (__builtin_expect(_pure_native_syscall == NULL,0))
		init();
	if (__builtin_expect(_pure_syscall == syscall,0))
		return _pure_native_syscall(n,arg0,arg1,arg2,arg3,arg4,arg5);
	else
		return _pure_syscall(n,arg0,arg1,arg2,arg3,arg4,arg5);
}

sfun _pure_start(sfun pure_syscall, int flags)
{
	int fdtmp;
	if (__builtin_expect(_pure_native_syscall == syscall,0))
		init();
	if (flags & PUREFLAG_STDIN) {
		fdtmp=dup(fileno(stdin));
		dup2(fdtmp,STDIN_FILENO);
		stdin=fdopen(STDIN_FILENO,"r");
		if (isatty(STDIN_FILENO))
			setlinebuf(stdin);
		close(fdtmp);
	}

	if (flags & PUREFLAG_STDOUT) {
		fdtmp=dup(fileno(stdout));
		dup2(fdtmp,STDOUT_FILENO);
		stdout=fdopen(STDOUT_FILENO,"w");
		if (isatty(STDOUT_FILENO))
			setlinebuf(stdout);
		close(fdtmp);
	}

	if (flags & PUREFLAG_STDERR) {
		fdtmp=dup(fileno(stderr));
		dup2(fdtmp,STDERR_FILENO);
		stderr=fdopen(STDERR_FILENO,"a");
		if (isatty(STDERR_FILENO))
			setlinebuf(stderr);
		close(fdtmp);
	}
	_pure_syscall=pure_syscall;
	return _pure_native_syscall;
}

/* this is convenient since casting the return value of dlsym() to
 * a function pointer erroneously procudes a warning */
#pragma GCC diagnostic ignored "-Wpedantic"

	__attribute__ ((constructor))
static void init (void)
{
	_pure_native_syscall = _pure_syscall = dlsym(RTLD_NEXT,"syscall");
}

