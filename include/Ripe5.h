#include <cmath>
#include <stdexcept>

///
/// \brief Ripe class
///
/// PLEASE NOTE, THIS IS FROM UPCOMING VERSION OF RIPE
/// DO NOT USE UNTIL THE FINAL RELEASE (Ripe 5.x)
///

class Ripe5 {
public:
    typedef long long BigInteger;

    class BigInteger2 {
    public:
        typedef long long underlying_type;

        BigInteger2() : m_n(0) {}

        BigInteger2(const long long n) : m_n(n) {}

        BigInteger2 operator-(const BigInteger2& b) {
            return BigInteger2(m_n - b.m_n);
        }

        BigInteger2 operator+(const BigInteger2& b) {
            return BigInteger2(m_n + b.m_n);
        }

        BigInteger2 operator*(const BigInteger2& b) {
            return BigInteger2(m_n * b.m_n);
        }

        BigInteger2 operator%(underlying_type b) {
            return BigInteger2(m_n % b);
        }

        bool operator==(const BigInteger2& b) {
            return m_n == b.m_n;
        }

        underlying_type n() const { return m_n; }

    private:
        underlying_type m_n;
    };

    class PublicKey {
    public:
        PublicKey() = default;

        PublicKey(BigInteger n, BigInteger e) :
            m_n(n),
            m_e(e) {
        }

        virtual ~PublicKey() = default;

        inline BigInteger n() const { return m_n; }
        inline BigInteger e() const { return m_e; }

    private:
        BigInteger m_n;
        BigInteger m_e;
    };
    typedef RawKey PrivateKey;

    class KeyPair : public RawKey {
    public:
        KeyPair(BigInteger p, BigInteger q, BigInteger exp = DEFAULT_PUBLIC_EXPONENT) :
            RawKey(p, q, exp) {
            m_publicKey = PublicKey(n(), e());
        }

        inline const PublicKey* publicKey() const { return &m_publicKey; }
        inline const PrivateKey* privateKey() const { return this; }

    private:
        PublicKey m_publicKey;
    };

private:
    class RawKey {
    public:
        static const BigInteger DEFAULT_PUBLIC_EXPONENT = 65537;

        RawKey(BigInteger p, BigInteger q, BigInteger e = DEFAULT_PUBLIC_EXPONENT) :
            m_p(p),
            m_q(q),
            m_e(e)
        {
            if (!isPrime(p) || !isPrime(q) || p == q) {
                throw std::invalid_argument("p and q must be prime numbers unique to each other");
            }

            BigInteger phi = (m_p - 1) * (m_q - 1);

            if (gcd(phi, m_e) != 1) {
                throw std::invalid_argument("Invalid prime numbers.");
            }
            m_n = m_p * m_q;

            BigInteger bigE = m_e; // for type safety
            m_d = modInverse(bigE, phi);

            m_dp = modulo(m_d, m_p - 1);
            m_dq = modulo(m_d, m_q - 1);
            m_coeff = modInverse(m_q, m_p);
        }

        virtual ~RawKey() = default;

        inline BigInteger p() const { return m_p; }
        inline BigInteger q() const { return m_q; }
        inline BigInteger coeff() const { return m_coeff; }
        inline BigInteger n() const { return m_n; }
        inline unsigned int e() const { return m_e; }
        inline BigInteger d() const { return m_d; }
    private:
        BigInteger m_p;
        BigInteger m_q;
        BigInteger m_coeff;
        BigInteger m_n;
        unsigned int m_e;
        BigInteger m_d;
        BigInteger m_dp;
        BigInteger m_dq;
    };

    static BigInteger gcd(BigInteger a, BigInteger b)
    {
        BigInteger c;
        while (a != 0) {
            c = a;
            a = b % a;
            b = c;
        }
        return b;
    }

    static BigInteger modulo(const BigInteger& n, const BigInteger& p)
    {
        BigInteger r = n % p;
        if (((p > 0) && (r < 0)) || ((p < 0) && (r > 0))) {
            r += p;
        }
        return r;
    }

    static BigInteger modInverse(const BigInteger& n, const BigInteger& p) {
        BigInteger n2 = modulo(n, p);
        for (BigInteger x = 1; x < p; x++) {
            if (modulo(n2 * x, p) == 1) {
                return x;
            }
        }
        return 0;
    }

    static bool isPrime(BigInteger numb)
    {
        BigInteger j = sqrt(numb);
        for (BigInteger i = 2; i <= j; i++) {
            if (numb % i == 0) {
                return false;
            }
        }
        return true;
    }

    // for tests
    friend class Ripe5Test_IsPrime_Test;
    friend class Ripe5Test_Modulo_Test;
};
