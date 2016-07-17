
/*
 * @copyright
 *
 *  Copyright 2014 Neo Natura
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

#ifndef __SERVER__SPRING_H__
#define __SERVER__SPRING_H__

#if 0
#include <boost/foreach.hpp>
#include <vector>

#include "uint256.h"
#include "serialize.h"
#include "util.h"
#include "scrypt.h"
#include "protocol.h"
#include "net.h"
#include "script.h"
#include "coin_proto.h"
#include "txext.h"
#include "matrix.h"

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
using namespace std;
using namespace json_spirit;
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**
 * The matrix grid's latitude offset adjustment.
 * @note The continental US ranges from (49°23'4.1" N) to (24°31′15″ N) latitude. */
#define SPRING_OFFSET_LATITUDE 30.0
/**
 * The matrix grid's longitude offset adjustment.
 * @note The continental US ranges from (66°57' W) to (124°46' W) longitude. 
 */  
#define SPRING_OFFSET_LONGITUDE 70.0

#define SPRING_Y_FACTOR 13.4

#define SPRING_X_FACTOR 5.2



/**
 * Set's a particular location as active inside the matrix.
 */
void spring_loc_set(double lat, double lon);

/**
 * Whether or not a particular location is set in the matrix.
 * @returns TRUE if the location matches and FALSE if not.
 */
int is_spring_loc(double lat, double lon);

/**
 * Search the surrounding area for a location registered in the matrix.
 */
int spring_loc_search(shnum_t cur_lat, shnum_t cur_lon, shnum_t *lat_p, shnum_t *lon_p);

/**
 * Render the spring matrix as a fractal image with optional [centered] zoom.
 */
int spring_render_fractal(char *img_path, double zoom);

void spring_loc_claim(double lat, double lon);

void spring_matrix_compress(uint32_t matrix[3][3]);


#ifdef __cplusplus
}
#endif

#endif /* ndef __SERVER_SPRING_H__ */




