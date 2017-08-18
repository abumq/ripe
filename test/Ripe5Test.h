#ifndef RIPE_5_TEST_H
#define RIPE_5_TEST_H

#include "include/Ripe5.h"
#include "test.h"

// numb, expected
static TestData<Ripe5::BigInteger, bool> IsPrimeData = {
    TestCase(1, true),
    TestCase(2, true),
    TestCase(44, false),
    TestCase(43, true),
    TestCase(57, false),
    TestCase(257, true),
};

// a, b, expected mod, expected mov_inv
static TestData<int, int, int, int> ModuloData = {
    TestCase(1, 2, 1, 1),
    TestCase(199, 2443, 199, 1510),
    TestCase(2443, 199, 55, 76),
};

TEST(Ripe5Test, IsPrime)
{
    for (const auto& item : IsPrimeData) {
        LOG(INFO) << "Testing " << PARAM(0) << " == prime: to be " << std::boolalpha << PARAM(1);
        ASSERT_EQ(Ripe5::isPrime(PARAM(0)), PARAM(1));
    }
}

TEST(Ripe5Test, Modulo)
{
    for (const auto& item : ModuloData) {
        ASSERT_EQ(Ripe5::modulo(PARAM(0), PARAM(1)), PARAM(2));
        ASSERT_EQ(Ripe5::modInverse(PARAM(0), PARAM(1)), PARAM(3));
    }
}

TEST(Ripe5Test, Key)
{
    Ripe5::KeyPair k(3, 11);
    ASSERT_EQ(k.p(), 3);
    ASSERT_EQ(k.q(), 11);
    ASSERT_EQ(k.n(), 33);
    ASSERT_EQ(k.coeff(), 2);
    ASSERT_EQ(k.d(), 13);
    ASSERT_EQ(k.e(), Ripe5::KeyPair::DEFAULT_PUBLIC_EXPONENT);
    ASSERT_EQ(k.publicKey()->n(), k.n());
    ASSERT_EQ(k.publicKey()->e(), k.e());
    ASSERT_EQ(k.privateKey()->d(), k.d());
    ASSERT_EQ(k.privateKey()->e(), k.e());
}


#endif // RIPE_5_TEST_H
