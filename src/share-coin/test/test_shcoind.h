
#ifndef __TEST__SHTEST_H__
#define __TEST__SHTEST_H__


#include "shcoind.h"
#include "CuTest.h"

#define _TEST(_name) void TEST_##_name(CuTest *ct) 
#define _END_TEST

#define _TRUE(testexpr) \
  CuAssertTrue(ct, (testexpr))
#define _FALSE(testexpr) \
  CuAssertTrue(ct, !(testexpr))
  

static void *_cutest_ptr;
#define _TRUEPTR(testptr) \
  _cutest_ptr = (testptr); CuAssertPtrNotNull(ct, _cutest_ptr)

int test_shcoind_main(void);



#endif /* ndef __TEST__SHTEST_H__ */


