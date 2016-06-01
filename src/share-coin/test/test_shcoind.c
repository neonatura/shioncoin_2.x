

#include "test_shcoind.h"


user_t *client_list;

extern TEST_coin_key(CuTest*);
extern TEST_wallet_accounting(CuTest*);
extern TEST_bignum(CuTest*);
extern TEST_sha256transform(CuTest*);

extern void test_shcoind_init(void);


int main(int argc, char *argv[])
{
  CuString *output = CuStringNew();
  CuSuite* suite = CuSuiteNew();
  int fails;

  test_shcoind_init();


  /* test suits */
  SUITE_ADD_TEST(suite, TEST_coin_key);
  SUITE_ADD_TEST(suite, TEST_wallet_accounting);
  SUITE_ADD_TEST(suite, TEST_bignum);
  SUITE_ADD_TEST(suite, TEST_sha256transform);

  CuSuiteRun(suite);
  CuSuiteSummary(suite, output);
  CuSuiteDetails(suite, output);
  printf("%s\n", output->buffer);
  CuStringDelete(output);
  fails = suite->failCount;
  CuSuiteDelete(suite);
  return (fails);
}


