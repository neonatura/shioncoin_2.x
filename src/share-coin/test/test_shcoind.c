

#include "test_shcoind.h"


user_t *client_list;

extern TEST_coin_key(CuTest*);
extern TEST_wallet(CuTest*);
extern TEST_bignum(CuTest*);
extern TEST_sha256transform(CuTest*);
extern TEST_blockchain(CuTest*);
extern TEST_reorganize(CuTest*);

extern void test_shcoind_init(void);


int main(int argc, char *argv[])
{
  CuString *output = CuStringNew();
  CuSuite* suite = CuSuiteNew();
  int fails;

  test_shcoind_init();


  /* test suits */
  SUITE_ADD_TEST(suite, TEST_coin_key);
  SUITE_ADD_TEST(suite, TEST_wallet);
  SUITE_ADD_TEST(suite, TEST_bignum);
  SUITE_ADD_TEST(suite, TEST_sha256transform);
  SUITE_ADD_TEST(suite, TEST_blockchain);
  SUITE_ADD_TEST(suite, TEST_reorganize);

  CuSuiteRun(suite);
  CuSuiteSummary(suite, output);
  CuSuiteDetails(suite, output);
  printf("%s\n", output->buffer);
  CuStringDelete(output);
  fails = suite->failCount;
  CuSuiteDelete(suite);
  return (fails);
}


