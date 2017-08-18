#ifndef RIPE_5_TEST_H
#define RIPE_5_TEST_H

#include "include/Ripe5.h"
#include "test.h"

// numb, expected
static TestData<Ripe5::BigInteger, bool> IsPrimeData = {
    TestCase(1, false),
    TestCase(2, true),
    TestCase(44, false),
    TestCase(43, true),
    TestCase(57, false),
    TestCase(257, true),
};

// a, b, expected mod, expected mod_inv
static TestData<int, int, int> InvModuloData = {
    TestCase(3, 11, 4),
    TestCase(1, 2, 1),
    TestCase(199, 2443, 1510),
    TestCase(2443, 199, 76),
    TestCase(17, 3120, 2753),
};

// m, k, n, exp
static TestData<Ripe5::BigInteger, Ripe5::BigInteger, Ripe5::BigInteger, long long int> PowerModData = {
    TestCase(5, 3, 1, 0),
    TestCase(5, 3, 19, 11),
    TestCase(3, 11, 4, 3),
    TestCase(5, 117, 19, 1),
    TestCase(5, 64, 19, 5),
    TestCase(5, 2, 19, 6),
    TestCase(5, 4, 19, 17),
    TestCase(5, 8, 19, 4),
    TestCase(7, 256, 13, 9),
};

// a, b, expected
static TestData<int, int, int> GCDData = {
    TestCase(270, 192, 6),
};

// p, q, d, e
static TestData<Ripe5::BigInteger, Ripe5::BigInteger, Ripe5::BigInteger, unsigned int> RawKeyData = {
    TestCase(173, 149, 16971, 3),
    TestCase(7, 11, 53, Ripe5::KeyPair::DEFAULT_PUBLIC_EXPONENT),
    TestCase(53, 59, 2011, 3),
    TestCase(3, 11, 13, Ripe5::KeyPair::DEFAULT_PUBLIC_EXPONENT),
    TestCase(11, 3, 13, Ripe5::KeyPair::DEFAULT_PUBLIC_EXPONENT),
    TestCase(11, 17, 107, 3),
    TestCase(60779, 53003, 1986380529, 65537),
    TestCase("176360517760307645469197766454483974235511085138581196179561347493397045582678676376582697316359235034160209749898412011153924577295946180206410049279151818330310786286636241193330444606031071350600285897477381895748147316188740513022461102919987041280831098968434434553879045380055670995086500659087065302403", "169163723758010117173450277772073715921803592964927638245731997826080549397171438893995388301374973303599758650257957793677462633788535432641753359275162340138639711102283198388259082836510170614304484108899685152902783320622394241970680405511348370667697428176827008839392860840538166537806520720483413747299", "19889201272149546443463155392252159315174210881947747082976069645146016944350039871470895772510979533532867685298201602992918775321216324576337623180033432704404378220468328792827286239010112541240591233928213472506415790478729110344923198900414497739281740852945910987895868475178794593401701658716065890906852003893420692929407600046549070094684609746581564079903528672418432707811264082243503362255422665241970781850081871999244191153644696361248245946591425338244340405196223004592171521190997670962141503496215757774355742872186005655701283224796723544068646999720522489543729822936326934344869201943856253606531", 3),
    TestCase("108806323825932706977307191097259117033353572146991115579334232319532442798209", "75778358732466892022501809496541864532894038434008219546470758430052996329071", "5496776426161658798940200169671739270887755348701962910881820208997794909110934102331035956003239535747096593580882262107967594097892650413676521849537707", 3),
};

// p, q, e, msg, expected
static TestData<Ripe5::BigInteger, Ripe5::BigInteger, unsigned int, int, long long int> RSABasicEncryption = {
    TestCase(11, 17, 3, 8, 138),
    TestCase(11, 17, 3, 72, 183),
    TestCase(11, 17, 3, 105, 95),
    TestCase(53, 59, 3, 8, 512),
    TestCase(53, 59, 3, 1, 1),
    TestCase(53, 59, 3, 2, 8),
    TestCase(53, 59, 3, 3, 27),
    TestCase(53, 59, 3, 4, 64)
};

// p, q, e, msg, expected
static TestData<Ripe5::BigInteger, Ripe5::BigInteger, unsigned int, std::string, std::vector<long long int>> RSADetailedEncryption = {
    TestCase(11, 17, 3, "Hi", std::vector<long long int> { 183, 95 }),
    TestCase(53, 59, 3, "Hi", std::vector<long long int> { 1135, 635 }),
    TestCase(60779, 53003, 65537, "Hi", std::vector<long long int> { 569814661, 1696284635 }),    TestCase("108806323825932706977307191097259117033353572146991115579334232319532442798209", "75778358732466892022501809496541864532894038434008219546470758430052996329071", 3, "Hi", std::vector<long long int> { 373248, 1157625 }),
    TestCase("176360517760307645469197766454483974235511085138581196179561347493397045582678676376582697316359235034160209749898412011153924577295946180206410049279151818330310786286636241193330444606031071350600285897477381895748147316188740513022461102919987041280831098968434434553879045380055670995086500659087065302403", "169163723758010117173450277772073715921803592964927638245731997826080549397171438893995388301374973303599758650257957793677462633788535432641753359275162340138639711102283198388259082836510170614304484108899685152902783320622394241970680405511348370667697428176827008839392860840538166537806520720483413747299", 3, "Hi", std::vector<long long int> { 373248, 1157625 }),
};

TEST(Ripe5Test, FindGCD)
{
    for (const auto& item : GCDData) {
        LOG(INFO) << "Finding GCD for " << PARAM(0) << " and " << PARAM(1);
        ASSERT_EQ(Ripe5::gcd(PARAM(0), PARAM(1)), PARAM(2));
    }
}

TEST(Ripe5Test, IsPrime)
{
    for (const auto& item : IsPrimeData) {
        LOG(INFO) << "Testing " << PARAM(0) << " == prime: to be " << std::boolalpha << PARAM(1);
        ASSERT_EQ(Ripe5::isPrime(PARAM(0)), PARAM(1));
    }
}

TEST(Ripe5Test, PowerMod)
{
    for (const auto& item : PowerModData) {
        ASSERT_EQ(Ripe5::powerMod(PARAM(0), PARAM(1), PARAM(2)), PARAM(3));
    }
}

TEST(Ripe5Test, InvModulo)
{
    for (const auto& item : InvModuloData) {
        ASSERT_EQ(Ripe5::modInverse(PARAM(0), PARAM(1)), PARAM(2));
    }
}

TEST(Ripe5Test, Key)
{
    for (const auto& item : RawKeyData) {
        Ripe5::KeyPair k(PARAM(0), PARAM(1), PARAM(3));
        ASSERT_EQ(k.p(), PARAM(0));
        ASSERT_EQ(k.q(), PARAM(1));
        ASSERT_EQ(k.d(), PARAM(2));
        ASSERT_EQ(k.e(), PARAM(3));
        ASSERT_EQ(k.publicKey()->n(), k.n());
        ASSERT_EQ(k.publicKey()->e(), k.e());
        LOG(INFO) << "Key:\n-----------\n" << k.exportDER() << "\n---------------------\n\n";
    }
}

TEST(Ripe5Test, BasicEncryption)
{
    for (const auto& item : RSABasicEncryption) {
        LOG(INFO) << "Generating key ...";
        Ripe5::KeyPair k(PARAM(0), PARAM(1), PARAM(2));
        LOG(INFO) << "Encrypting ...";
        ASSERT_EQ(Ripe5::encrypt(k.publicKey(), PARAM(3)), PARAM(4));
        LOG(INFO) << "Decrypting ...";
        ASSERT_EQ(Ripe5::decrypt(k.privateKey(), PARAM(4)), PARAM(3));
    }
}

TEST(Ripe5Test, DetailedEncryption)
{
    for (const auto& item : RSADetailedEncryption) {
        LOG(INFO) << "Generating key ... len(p) = "
                  << PARAM(0).numberOfDigits() << ", len(q) = "
                  << PARAM(1).numberOfDigits();
        Ripe5::KeyPair k(PARAM(0), PARAM(1), PARAM(2));
        LOG(INFO) << "Encrypting ...";
        ASSERT_EQ(Ripe5::encrypt(k.publicKey(), PARAM(3)), PARAM(4));
        LOG(INFO) << "Decrypting ...";
        ASSERT_EQ(Ripe5::decrypt(k.privateKey(), PARAM(4)), PARAM(3));
        LOG(INFO) << "Done!";
    }
}


#endif // RIPE_5_TEST_H
