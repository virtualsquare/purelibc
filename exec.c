/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * exec.c: exec to execve conversion
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
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <alloca.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

#define _PURE_DEFAULT_PATH "/bin:/usr/bin"

int execl(const char *path, const char *arg, ...){
	va_list ap;
	int argc=2,i;
	va_start(ap,arg);
	while(va_arg(ap,char *) != 0)
		argc++;
	va_end(ap);
	char *argv[argc];
	assert(argv);
	argv[0]=(char *)arg;
	va_start(ap,arg);
	for (i=1;i<argc;i++)
		argv[i]=va_arg(ap,char*);
	argv[i]=(char *) 0;
	va_end(ap);
	return execve(path,argv,environ);
}

int execlp(const char *file, const char *arg, ...){
	va_list ap;
	int argc=2,i;
	va_start(ap,arg);
	while(va_arg(ap,char *) != 0)
		argc++;
	va_end(ap);
	char *argv[argc];
	assert(argv);
	argv[0]=(char *)arg;
	va_start(ap,arg);
	for (i=1;i<argc;i++)
		argv[i]=va_arg(ap,char*);
	va_end(ap);
	return execvp(file,argv);
}

int execle(const char *path, const char *arg , .../*, char * const envp[]*/){
	va_list ap;
	int argc=2,i;
	char **envp;
	va_start(ap,arg);
	while(va_arg(ap,char *) != 0)
		argc++;
	va_end(ap);
	char *argv[argc];
	assert(argv);
	argv[0]=(char *)arg;
	va_start(ap,arg);
	for (i=1;i<argc;i++)
		argv[i]=va_arg(ap,char*);
	envp=va_arg(ap,char**);
	va_end(ap);
	return execve(path,argv,envp);
}

int execv(const char *path, char *const argv[]){
	return execve(path,argv,environ);
}

int execvp(const char *file, char *const argv[]){
	if(strchr(file,'/') != NULL)
		return execve(file,argv,environ);
	else {
		char *path;
		char *envpath;
		char *pathelem;
		char buf[PATH_MAX];
		if ((envpath=getenv("PATH")) == NULL)
			envpath=_PURE_DEFAULT_PATH;
		path=strdup(envpath);
		while((pathelem=strsep(&path,":")) != NULL){
			if (*pathelem != 0) {
				register int i,j;
				for (i=0; i<PATH_MAX && pathelem[i]; i++)
					buf[i]=pathelem[i];
				if(buf[i-1] != '/' && i<PATH_MAX)
					buf[i++]='/';
				for (j=0; i<PATH_MAX && file[j]; j++,i++)
					buf[i]=file[j];
				buf[i]=0;
				if (execve(buf,argv,environ)<0 &&
						((errno != ENOENT) && (errno != ENOTDIR) && (errno != EACCES))) {
					free(path);
					return -1;
				}
			}
		}
		free(path);
		errno = ENOENT;
		return -1;
	}
}
