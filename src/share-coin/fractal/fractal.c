
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

#include <math.h>
#include "shcoind.h"
#include "fractal.h"

int fractal_render(char *img_path, double in_seed, double zoom, double span, double x_of, double y_of)
{
  static const unsigned int width = 256, height = 256;
  BMP *bmp;
  uint32_t val;
  shnum_t seed;
  shnum_t rate;
  shnum_t K;
  shnum_t Z;
  shnum_t C;
  shnum_t min_cord;
  shnum_t max_cord;
  shnum_t dx, dy;
  unsigned int x, y;
  int cval;
  int idx;
  unsigned char r, g, b;
  int px_width, px_height;

  seed = (shnum_t)in_seed / (shnum_t)65536;

fprintf(stderr, "DEBUG: fractal_render: seed %Lf\n", seed);

  px_width = (int)((shnum_t)256 / (shnum_t)span);
  px_height = (int)((shnum_t)256 / (shnum_t)span);
  bmp = BMP_Create(px_width, px_height, 32);

  zoom = MAX(0.001, MIN(100.0, zoom));
  rate = (shnum_t)span * (shnum_t)zoom;
  min_cord = (-128 * zoom);
  max_cord = (128 * zoom);
  for (dy = min_cord; dy <= max_cord; dy += rate) {
    for (dx = min_cord; dx <= max_cord; dx += rate) {
      C = (dx * dy) + seed;

      Z = 0;
      for (idx = 0; idx < 16; idx++) {
        Z = Z * Z + C;
        if (fabs(Z) >= 2)
          break;
      }
      if (idx == 16) {
        r = g = b = 0;
      } else {
        K = fabs(Z*C);
        val = 4294967296 % (uint32_t)(K+1);
        r = (val >> 16) & 0xff;
        g = (val >> 8) & 0xff;
        b = val & 0xff;

        r = MIN(255, r + idx);
        g = MIN(255, g + idx);
        b = MIN(255, b + idx);
      }
      x = (int)((dx + max_cord) / rate) % px_width;
      y = (int)((dy + max_cord) / rate) % px_height;
      BMP_SetPixelRGB( bmp, x, y, r, g, b);
    }
  }

  BMP_WriteFile(bmp, img_path);
  BMP_CHECK_ERROR( stdout, -2 );
  BMP_Free( bmp );

  return 0;
}

