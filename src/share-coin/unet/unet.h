
/*
 * @copyright
 *
 *  Copyright 2015 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#ifndef __UNET__UNET_H__
#define __UNET__UNET_H__


#define UNET_NONE 0
#define UNET_STRATUM 1
#define UNET_RPC 2
#define UNET_COIN 3
#define MAX_UNET_MODES 4


/** The socket has been marked for disconnect and removal.  */
#define UNETF_DEAD (1 << 0)


#define UNDEFINED_SOCKET 0

#ifdef WIN32
#define MSG_NOSIGNAL        0
#define MSG_DONTWAIT        0
typedef int socklen_t;
#else
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1
#endif

#define MAX_UNET_SOCKETS 4096


typedef unsigned int SOCKET;
 
typedef void (*unet_op)(void);

typedef void (*unet_addr_op)(struct sockaddr_in *);


/* per unet mode */
typedef struct unet_bind_t
{
  /** the socket descriptor of the listening socket. */
  int fd;

  /** bitvector flags (UNETF_XXX) */
  int flag;

  /** the last time the timer callback was called. */
  shtime_t stamp;

  /** the timer callback */
  unet_op op_timer;

  /** called when a new socket is accepted. */
  unet_addr_op op_accept;
} unet_bind_t;

/* per client socket connection */
typedef struct unet_table_t
{

  /** server modes (UNET_XXX) */
  int mode;

  /** the underlying socket file descriptor. */
  SOCKET fd;

  /** bitvector flags (UNETF_XXX) */
  int flag;

  /** The last time that I/O was processed on socket. */
  shtime_t stamp;

  /** incoming data buffer */
  shbuf_t *rbuff;

  /** outgoing data buffer */
  shbuf_t *wbuff;
}




unet_bind_t *unet_bind_table(int mode);

int unet_bind(int mode, int port);

void unet_unbind(int mode);


int get_unet_table(int sk);

int unet_accept(int mode, SOCKET *sk_p);


int unet_close(SOCKET sk);
int unet_close_all(int mode);

int unet_timer_add(unet_timer_t timer_f);

int unet_sbuff_add(int sk, unsigned char *data, size_t data_len);

int unet_rbuff_add(int sk, unsigned char *data, size_t data_len);


int unet_read(SOCKET sk, char *data, size_t *data_len_p);

int unet_write(SOCKET sk, char *data, size_t data_len);

int unet_timer_set(int mode, unet_op timer_f);
void unet_timer_unset(int mode);


int unet_connect(int mode, struct sockaddr_in *net_addr, SOCKET *sk_p);



#endif /* ndef __UNET__UNET_H__ */

