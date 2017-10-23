/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * dir.c: Directory management
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
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define PURE_DIRSTREAM_SIZE 2048
#define PURE_DIRBUF_SIZE (PURE_DIRSTREAM_SIZE - 3*sizeof(int))

struct __dirstream {
	int fd;
	int bufsize;
	int bufpos;
	char buf[PURE_DIRBUF_SIZE];
	struct dirent de32;
};

DIR *fdopendir(int fd)
{
	DIR *newdir = (DIR *) malloc (sizeof (struct __dirstream));
	if (!newdir)
		return NULL;
	else {
		newdir->fd=fd;
		newdir->bufsize=newdir->bufpos=0;
	}
	return newdir;
}

DIR *opendirat(int dirfd, const char *name)
{
	int fd;
	DIR *newdir=NULL;

	if (dirfd == AT_FDCWD)
		fd = open(name, O_RDONLY | O_DIRECTORY);
	else
		fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY);

	if (fd >= 0) {
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
			close(fd);
		else {
			newdir = fdopendir(fd);
			if (!newdir) {
				close(fd);
				return NULL;
			}
		}
	}
	return newdir;
}

DIR *opendir(const char *name) {
	return opendirat(AT_FDCWD, name);
}

int closedir(DIR *dir){
	int fd=dir->fd;
	free(dir);
	return close(fd);
}

#define _MAX_OFF_T ((__off_t) -1)

struct dirent *readdir(DIR *dir){
	register struct dirent64 *de64=readdir64(dir);
	if(de64 == NULL)
		return NULL;
	else {
		dir->de32.d_ino=de64->d_ino;
		dir->de32.d_off=(de64->d_off > _MAX_OFF_T)?_MAX_OFF_T:de64->d_off;
		dir->de32.d_reclen=de64->d_reclen;
		dir->de32.d_type=de64->d_type;
		strcpy(dir->de32.d_name,de64->d_name);
		return &(dir->de32);
	}
}

int getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count);
struct dirent64 *readdir64(DIR *dir){
	register struct dirent64 *this;
	this=((struct dirent64 *) (dir->buf + dir->bufpos));
	if (dir->bufsize == 0 || (dir->bufpos += this->d_reclen) >= dir->bufsize) {
		dir->bufsize = getdents64(dir->fd,(struct dirent64 *)dir->buf,PURE_DIRBUF_SIZE-1);
		if (dir->bufsize <= 0)
			return NULL;
		else
			dir->bufpos=0;
	}
	this=((struct dirent64 *) (dir->buf + dir->bufpos));
	return this;
}

int dirfd(DIR *dir){
	//if (dir) 
		return dir->fd;
	//else
		//return -1;
}

void rewinddir(DIR *dir){
	//if (dir) {
		lseek(dir->fd,0,SEEK_SET);
		dir->bufsize=dir->bufpos=0;
	//}
}

void seekdir(DIR *dir, off_t offset){
	//if (dir) {
		lseek(dir->fd,offset,SEEK_SET);
		dir->bufsize=dir->bufpos=0;
	//}
}

off_t telldir(DIR *dir){
	//if (dir) {
		off_t pos = lseek(dir->fd,0,SEEK_CUR);
		if (pos != (off_t) -1)
			return -1;
		else
			return pos + dir->bufpos;
	//} else
		//return -1;
}

#define NL_SIZE_INCR 100

typedef int(*filter_t)(const void *);
typedef int(*compar_t)(const void *, const void *);
typedef void *(*xreaddir_t)(DIR *dirp);
static int common_scandir(int dirfd, const char *dir, void ***namelist,
		filter_t filter, compar_t compar, xreaddir_t xreaddir, size_t elsize){
	int n = 0;
	int size = 0;
	DIR *d = opendirat(dirfd, dir);
	void *de;
	if (d == NULL)
		return -1;
	*namelist = NULL;
	while ((errno = 0, de = xreaddir(d)) != NULL) {
		if (filter && filter(de) == 0)
			continue;
		if (n >= size) {
			int newsize = size + NL_SIZE_INCR;
			void **newnamelist = realloc(*namelist, newsize * sizeof(void **));
			if (newnamelist == NULL)
				goto error;
			size = newsize;
			*namelist = newnamelist;
		}
		void *newel = malloc(elsize);
		if (newel == NULL)
			goto error;
		(*namelist)[n] = newel;
		memcpy(newel, de, elsize);
		n++;
	}
	*namelist = realloc(*namelist, n * sizeof(void **));
	if (n > 0)
		qsort(*namelist, n, sizeof(void *), compar);
	return n;
error:
	if (*namelist) {
		int i;
		for (i = 0; i < n; i++)
			free((*namelist)[i]);
		free(namelist);
	}
	return -1;
}

int scandir(const char *dirp, struct dirent ***namelist,
		int (*filter)(const struct dirent *),
		int (*compar)(const struct dirent **, const struct dirent **)) {
	return common_scandir(AT_FDCWD, dirp, (void *) namelist, (filter_t) filter, (compar_t) compar, (xreaddir_t) readdir, sizeof(struct dirent));
}

int scandir64(const char *dirp, struct dirent64 ***namelist,
		int (*filter)(const struct dirent64 *),
		int (*compar)(const struct dirent64 **, const struct dirent64 **)) {
	return common_scandir(AT_FDCWD, dirp, (void *) namelist, (filter_t) filter, (compar_t) compar, (xreaddir_t) readdir, sizeof(struct dirent64));
}

int scandirat(int dirfd, const char *dirp, struct dirent ***namelist,
		int (*filter)(const struct dirent *),
		int (*compar)(const struct dirent **, const struct dirent **)) {
	return common_scandir(dirfd, dirp, (void *) namelist, (filter_t) filter, (compar_t) compar, (xreaddir_t) readdir, sizeof(struct dirent));
}

int scandirat64(int dirfd, const char *dirp, struct dirent64 ***namelist,
		int (*filter)(const struct dirent64 *),
		int (*compar)(const struct dirent64 **, const struct dirent64 **)) {
	return common_scandir(dirfd, dirp, (void *) namelist, (filter_t) filter, (compar_t) compar, (xreaddir_t) readdir, sizeof(struct dirent64));
}


