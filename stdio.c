/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * stdio.c: stdio calls
 * 
 * Copyright 2006-2017 Renzo Davoli University of Bologna - Italy
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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <pthread.h>

#define PURE_HASHSIZE 64
long _pure_debug_printf(const char *format, ...);

struct pure_file {
	int fd;
	FILE *f;
	struct pure_file *next;
};

static struct pure_file *pure_hash[PURE_HASHSIZE];
pthread_mutex_t _pure_mutex = PTHREAD_MUTEX_INITIALIZER;

static int pure_hfun(FILE *f)
{
	unsigned long l=(long)f;
	return (l+(l>>8)+(l>>16)) % PURE_HASHSIZE;
}

static ssize_t myread(void *cookie, char *buf, size_t count) {
	struct pure_file *p=cookie;
	return read(p->fd,buf,count);
}

static ssize_t mywrite(void *cookie, const char *buf, size_t count) {
	struct pure_file *p=cookie;
	return write(p->fd,buf,count);
}

static int mylseek(void *cookie, off64_t *offset, int whence) {
	struct pure_file *p=cookie;
	*offset=lseek64(p->fd,*offset,whence);
	if (*offset == -1)
		return -1;
	else
		return 0;
}

static void del_pure_file(struct pure_file *x);
static int myclose(void *cookie) {
	struct pure_file *p=cookie;
	int rv;
	rv=close(p->fd);
	del_pure_file(p);
	return rv;
}

static cookie_io_functions_t _pure_funcs={
	myread,
	mywrite,
	mylseek,
	myclose};

static FILE *new_pure_file(int fd, const char *modes)
{
	struct pure_file *n=malloc(sizeof(struct pure_file));
	if (n) {
		FILE *f=fopencookie(n,modes,_pure_funcs);
		if (f) {
			int hkey=pure_hfun(f);
			pthread_mutex_lock(&_pure_mutex);
			n->fd=fd;
			n->f=f;
			n->next=pure_hash[hkey];
			pure_hash[hkey]=n;
			pthread_mutex_unlock(&_pure_mutex);
			//_pure_debug_printf("+%p %d\n",n,hkey);
			return f;
		} else {
			free(n);
			return  NULL;
		}
	} else 
		return NULL;
}

static int _pure_file_fd(FILE *f,int locked)
{
	int hkey=pure_hfun(f);
	struct pure_file *n;
	int fd= -1;
	if (locked) pthread_mutex_lock(&_pure_mutex);
	n=pure_hash[hkey];
	while (n && n->f != f)
		n=n->next;
	if (n)
		fd=n->fd;
	if (locked) pthread_mutex_unlock(&_pure_mutex);
	return fd;
}

static void del_pure_file(struct pure_file *x)
{
	int hkey=pure_hfun(x->f);
	struct pure_file **n;
	pthread_mutex_lock(&_pure_mutex);
	n=&(pure_hash[hkey]);
	while (*n && *n != x)	
		n=&((*n)->next);
	if (*n == x)
		*n=x->next;
	//_pure_debug_printf("-%p %d\n",x,hkey);
	pthread_mutex_unlock(&_pure_mutex);
	free(x);
}

int _pure_parse_mode(const char *modes) {
	int flags=0;
	while (*modes) {
		switch (*modes) {
			case 'r':flags=O_RDONLY;break;
			case 'w':flags=O_WRONLY|O_CREAT|O_TRUNC;break;
			case 'a':flags=O_WRONLY|O_CREAT|O_APPEND;break;
			case '+':flags &= ~(O_WRONLY | O_RDONLY); flags |= O_RDWR;break;
		}
		modes++;
	}
	return flags;
}

static FILE *_pure_fopen (const char *filename, const char * modes, int flags){
	int fd;
	//_pure_debug_printf("_pure_fopen %s\n",filename);
	if ((fd=open(filename,flags,0666)) < 0)
		return NULL;
	else
		return new_pure_file(fd,modes);
}

#ifndef __USE_FILE_OFFSET64
FILE *fopen (const char *filename, const char *modes){
	return _pure_fopen(filename, modes, _pure_parse_mode(modes));
}
#endif

FILE *fopen64 (const char *filename, const char *modes){
	return _pure_fopen(filename, modes, _pure_parse_mode(modes)|O_LARGEFILE);
}

FILE *fdopen (int fd, const char *modes){
	return new_pure_file(fd,modes);
}

#ifndef __USE_FILE_OFFSET64
FILE *tmpfile (void){
	int fd;
	char template[20] = "/tmp/tmpfile-XXXXXX";
	if ((fd=mkstemp(template))<0)
		return 0;
	else {
		unlink(template);
		return new_pure_file(fd,"rw");
	}
}
#endif

FILE *tmpfile64 (void){
	int fd;
	char template[20] = "/tmp/tmpfile-XXXXXX";
	if ((fd=mkstemp(template))<0)
		return 0;
	else {
		unlink(template);
		return new_pure_file(fd,"rw");
	}
}

static FILE *_pure_freopen (const char *filename, const char *modes, FILE *stream){
	if (stream == NULL) {
		errno=EINVAL;
		return NULL;
	} else {
	 FILE *newstream=NULL;
	 int fd=-1;
	 int fdtmp=open(filename,_pure_parse_mode(modes),0666);
	 if (fdtmp >= 0) {
		 if (stream == stdout)
			 fd=STDOUT_FILENO;
		 else if (stream == stdin)
			 fd=STDIN_FILENO;
		 else if (stream == stderr)
			 fd=STDERR_FILENO;
		 fclose(stream);
		 if (fd>=0)
			 fd=dup2(fdtmp,fd);
		 else
			 fd=fdtmp;
		 if (fd>=0) 
			 newstream=fdopen(fd,modes);
		 if (isatty(fd))
			 setlinebuf(newstream);
		 close(fdtmp);
		 if (fd==STDOUT_FILENO) {
			 stdout=newstream;
			 return stdout;
		 } else if (fd==STDIN_FILENO) {
			 stdin=newstream;
			 return stdin;
		 } else if (fd==STDERR_FILENO) {
			 stderr=newstream;
			 return stderr;
		 } else
			 return newstream;
	 }
	 return newstream;
	}
}

#ifndef __USE_FILE_OFFSET64
FILE *freopen (const char *filename, const char *modes, FILE *stream){
	return _pure_freopen(filename, modes, stream);
}
#endif

FILE *freopen64 (const char *filename, const char *modes, FILE *stream){
	return _pure_freopen(filename, modes, stream);
}

int printf (const char *format, ...)
{
	va_list arg;
	int done;

	va_start (arg, format);
	done = vfprintf (stdout, format, arg);
	va_end (arg);

	return done;
}

int putchar (c)
	int c;
{
	return putc (c, stdout);
}

int scanf (const char *format, ...)
{
	va_list arg;
	int done;

	va_start (arg, format);
	done = vfscanf (stdin, format, arg);
	va_end (arg);

	return done;
}

int getchar (void)
{
	return getc(stdin);
}

char *gets(char *s)
{
	return fgets(s, INT_MAX, stdin);
}

int puts(const char *s)
{
	int rv;
	rv=fputs(s,stdout);
	if (rv!=EOF)
		rv=putc('\n',stdout);
	return rv;
}

/* this is convenient since casting the return value of dlsym() to
 * a function pointer erroneously procudes a warning */
#pragma GCC diagnostic ignored "-Wpedantic"

int fileno (FILE *stream){
	/*char buf[]="FNOxx\n";
		buf[3]=(stream == NULL)?'X':'-';
		buf[4]=(!_pure_magic(stream))?'X':'-';
		write (2,buf,6);*/
	if (stream == NULL) 
		return -1;
	else {
		int rv=0;
		int (*_fileno)()=dlsym(RTLD_NEXT,"fileno");
		if (_fileno) {
			rv=_fileno(stream);
			if (rv<0) {
				rv=_pure_file_fd(stream,1);
				if (rv>=0)
					errno=0;
			}
		} else
			rv= -1;
		return rv;
	}
}

int fileno_unlocked (FILE *stream){
	/*char buf[]="FNOxx\n";
		buf[3]=(stream == NULL)?'X':'-';
		buf[4]=(!_pure_magic(stream))?'X':'-';
		write (2,buf,6);*/
	if (stream == NULL) 
		return -1;
	else {
		int rv=0;
		int (*_fileno)()=dlsym(RTLD_NEXT,"fileno");
		if (_fileno) {
			rv=_fileno(stream);
			if (rv<0) {
				rv=_pure_file_fd(stream,0);
				if (rv>=0)
					errno=0;
			}
		} else
			rv= -1;
		return rv;
	}
}

