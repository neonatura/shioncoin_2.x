
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

#ifndef __SHCOIND_OPT_H__
#define __SHCOIND_OPT_H__

#ifdef __cplusplus
extern "C" {
#endif



#define OPT_DEBUG "debug"
#define OPT_MAX_CONN "max-conn"
#define OPT_PEER_SEED "peer-seed"
#define OPT_BAN_SPAN "ban-span"
#define OPT_BAN_THRESHOLD "ban-threshold"



void opt_init(void);

void opt_term(void);

int opt_num(char *tag);

void opt_num_set(char *tag, int num);

const char *opt_str(char *tag);

void opt_str_set(char *tag, char *str);

int opt_bool(char *tag);

void opt_bool_set(char *tag, int b);




#ifdef __cplusplus
}
#endif


#endif /* ndef __SHCOIND_OPT_H__ */


