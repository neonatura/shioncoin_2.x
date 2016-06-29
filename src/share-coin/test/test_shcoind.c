

#include "test_shcoind.h"
#include "coin_proto.h"
#include "test_proto.h"


user_t *client_list;

extern TEST_coin_key(CuTest*);
extern TEST_wallet(CuTest*);
extern TEST_bignum(CuTest*);
extern TEST_sha256transform(CuTest*);
extern TEST_blockchain(CuTest*);
extern TEST_reorganize(CuTest*);
extern TEST_serializetx(CuTest*);
extern TEST_cointx(CuTest*);
extern TEST_aliastx(CuTest*);
extern TEST_assettx(CuTest*);
extern TEST_certtx(CuTest*);

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
  SUITE_ADD_TEST(suite, TEST_serializetx);
  SUITE_ADD_TEST(suite, TEST_cointx);
  SUITE_ADD_TEST(suite, TEST_aliastx);
  SUITE_ADD_TEST(suite, TEST_assettx);
  SUITE_ADD_TEST(suite, TEST_certtx);

  CuSuiteRun(suite);
  CuSuiteSummary(suite, output);
  CuSuiteDetails(suite, output);
  printf("%s\n", output->buffer);
  CuStringDelete(output);
  fails = suite->failCount;
  CuSuiteDelete(suite);

  CIface *iface = GetCoinByIndex(TEST_COIN_IFACE);
  iface->op_term(iface, NULL);

  return (fails);
}


