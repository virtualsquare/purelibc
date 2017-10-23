/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * socketcall.c: socketcall mgmt
 * 
 * Copyright 2006-2017 Renzo Davoli University of Bologna - Italy
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License a
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */ 

#include <config.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/net.h>
#include "purelibc.h"

extern sfun _pure_syscall;

int socket(int domain, int type, int protocol){
	return _pure_syscall(__NR_socket,domain,type,protocol);
}
int bind(int sockfd, __CONST_SOCKADDR_ARG my_addr, socklen_t addrlen){
	return _pure_syscall(__NR_bind,sockfd,my_addr,addrlen);
}
int connect(int sockfd, __CONST_SOCKADDR_ARG serv_addr, socklen_t addrlen){
	return _pure_syscall(__NR_connect,sockfd,serv_addr,addrlen);
}
int listen(int sockfd, int backlog){
	return _pure_syscall(__NR_listen,sockfd,backlog);
}
int accept(int sockfd, __SOCKADDR_ARG addr, socklen_t *addrlen){
	return _pure_syscall(__NR_accept4,sockfd,addr,addrlen,0);
}
int accept4(int sockfd, __SOCKADDR_ARG addr, socklen_t *addrlen,int flags){
	return _pure_syscall(__NR_accept4,sockfd,addr,addrlen,flags);
}
int getsockname(int s, __SOCKADDR_ARG name, socklen_t *namelen){
	return _pure_syscall(__NR_getsockname,s,name,namelen);
}
int getpeername(int s, __SOCKADDR_ARG name, socklen_t *namelen){
	return _pure_syscall(__NR_getpeername,s,name,namelen);
}
int socketpair(int d, int type, int protocol, int sv[2]){
	return _pure_syscall(__NR_socketpair,d,type,protocol,sv);
}
ssize_t send(int s, const void *buf, size_t len, int flags){
	return sendto(s,buf,len,flags,NULL,0);
}
ssize_t recv(int s, void *buf, size_t len, int flags){
	return recvfrom(s,buf,len,flags,NULL,0);
}
ssize_t sendto(int s, const void *buf, size_t len, int flags,
		__CONST_SOCKADDR_ARG to, socklen_t tolen){
	return _pure_syscall(__NR_sendto,s,buf,len,flags,to,tolen);
}
ssize_t recvfrom(int s, void *buf, size_t len, int flags, 
		__SOCKADDR_ARG from, socklen_t *fromlen){
	return _pure_syscall(__NR_recvfrom,s,buf,len,flags,from,fromlen);
}
int shutdown(int s, int how){
	return _pure_syscall(__NR_shutdown,s,how);
}
int setsockopt(int s, int level, int optname, const void *optval,
		socklen_t optlen){
	return _pure_syscall(__NR_setsockopt,s,level,optname,optval,optlen);
}
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen){
	return _pure_syscall(__NR_getsockopt,s,level,optname,optval,optlen);
}
ssize_t sendmsg(int s, const struct msghdr *msg, int flags){
	return _pure_syscall(__NR_sendmsg,s,msg,flags);
}
ssize_t recvmsg(int s, struct msghdr *msg, int flags){
	return _pure_syscall(__NR_recvmsg,s,msg,flags);
}
