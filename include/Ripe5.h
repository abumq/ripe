#include <cmath>
#include <stdexcept>
#include <map>
#include <string>
#include <vector>
#include "include/InfInt.h"

///
/// \brief Ripe class
///
/// PLEASE NOTE, THIS IS FROM UPCOMING VERSION OF RIPE
/// DO NOT USE UNTIL THE FINAL RELEASE (Ripe 5.x)
///
class Ripe5 {
public:
    typedef InfInt BigInteger;
    typedef long long BigIntegerOld;

    class PublicKey {
    public:
        PublicKey() = default;

        PublicKey(BigInteger n, unsigned int e) :
            m_n(n),
            m_e(e) {
        }

        virtual ~PublicKey() = default;

        inline BigInteger n() const { return m_n; }
        inline unsigned int e() const { return m_e; }

    private:
        BigInteger m_n;
        unsigned int m_e;
    };

    class RawKey {
    public:
        static const unsigned int DEFAULT_PUBLIC_EXPONENT = 65537;

        RawKey(BigInteger p, BigInteger q, unsigned int e = DEFAULT_PUBLIC_EXPONENT, bool skipPrimeCheck = true) :
            m_p(p),
            m_q(q),
            m_e(e)
        {
            if (!skipPrimeCheck && (!isPrime(p) || !isPrime(q))) {
                throw std::invalid_argument("p and q must be prime numbers unique to each other");
            }
            if (p == q || p == 0 || q == 0) {
                throw std::invalid_argument("p and q must be prime numbers unique to each other");
            }

            BigInteger pMinus1 = m_p - 1;
            BigInteger qMinus1 = m_q - 1;
            BigInteger phi = pMinus1 * qMinus1;

            if (gcd(m_e, phi) != 1) {
                throw std::invalid_argument("Invalid exponent, it must not share factor with phi");
            }
            m_n = m_p * m_q;
            m_coeff = modInverse(m_q, m_p);

            m_d = modInverse(m_e, phi);

            // note:
            // https://www.ipa.go.jp/security/rfc/RFC3447EN.html#2 says to use m_e
            // openssl says to use m_d
            m_dp = BigInteger(m_d) % pMinus1;
            m_dq = BigInteger(m_d) % qMinus1;
        }

        virtual ~RawKey() = default;

        inline BigInteger p() const { return m_p; }
        inline BigInteger q() const { return m_q; }
        inline BigInteger coeff() const { return m_coeff; }
        inline BigInteger n() const { return m_n; }
        inline unsigned int e() const { return m_e; }
        inline BigInteger d() const { return m_d; }
        inline BigInteger dp() const { return m_dq; }
        inline BigInteger dq() const { return m_dp; }

        friend std::ostream& operator<<(std::ostream& ss, const RawKey& k)
        {
            ss << "modulus: " << k.m_n << "\npublicExponent: " << k.m_e << "\nprivateExponent: " << k.m_d
               << "\nprime1: " << k.m_p << "\nprime2: " << k.m_q << "\nexponent1: " << k.m_dp << "\nexponent2: "
               << k.m_dq << "\ncoefficient: " << k.m_coeff;
            return ss;
        }

        std::string exportDER() const
        {
            std::stringstream ss;
            ss << "asn1=SEQUENCE:rsa_key\n\n";
            ss << "[rsa_key]\n";
            ss << "version=INTEGER:0\n";
            ss << "modulus=INTEGER:" << m_n << "\n";
            ss << "pubExp=INTEGER:" << m_e << "\n";
            ss << "privExp=INTEGER:" << m_d << "\n";
            ss << "p=INTEGER:" << m_p << "\n";
            ss << "q=INTEGER:" << m_q << "\n";
            ss << "e1=INTEGER:" << m_dp << "\n";
            ss << "e2=INTEGER:" << m_dq << "\n";
            ss << "coeff=INTEGER:" << m_coeff;
            return ss.str();
        }

    private:
        BigInteger m_p;
        BigInteger m_q;
        unsigned int m_e;
        BigInteger m_coeff;
        BigInteger m_n;
        BigInteger m_d;
        BigInteger m_dp;
        BigInteger m_dq;
    };

    typedef RawKey PrivateKey;

    class KeyPair : public RawKey {
    public:
        KeyPair(BigInteger p, BigInteger q, unsigned int exp = DEFAULT_PUBLIC_EXPONENT) :
            RawKey(p, q, exp) {
            m_publicKey = PublicKey(n(), e());
        }

        inline const PublicKey* publicKey() const { return &m_publicKey; }
        inline const PrivateKey* privateKey() const { return this; }

    private:
        PublicKey m_publicKey;
    };

    static long long int encrypt(const PublicKey* publicKey, long long int m)
    {
        return powerMod(BigInteger(m), publicKey->e(), publicKey->n());
    }

    static long long int decrypt(const PrivateKey* privateKey, long long int m)
    {
        return powerMod(BigInteger(m), privateKey->d(), privateKey->n());
    }

    static std::vector<long long int> encrypt(const PublicKey* publicKey, const std::string& m)
    {
        std::vector<long long int> result;
        std::size_t len = m.size();
        for (std::size_t i = 0; i < len; ++i) {
            long long int mi = static_cast<long long int>(m[i]);
            long long int mienc = encrypt(publicKey, mi);
            result.push_back(mienc);
        }
        return result;
    }

    static std::string decrypt(const PrivateKey* privateKey, const std::vector<long long int>& m)
    {
        std::stringstream ss;
        std::size_t len = m.size();
        for (std::size_t i = 0; i < len; ++i) {
            long long int mi = static_cast<long long int>(m[i]);
            ss << static_cast<char>(decrypt(privateKey, mi));
        }
        return ss.str();
    }
private:
#if 0
    ///
    /// \brief Only for fun
    ///
    static std::string reverseDecrypt(const PublicKey* publicKey, const std::vector<long long int>& m)
    {
        if (publicKey->n().numberOfDigits() > 1024) {
            throw std::runtime_error("Modulus too big. Giving up!");
        }

        std::pair<BigInteger, BigInteger> pq = findPrimeFactors(publicKey->n());
        PrivateKey privateKey(pq.first, pq.second, publicKey->e());
        return decrypt(&privateKey, m);
    }

    static std::pair<BigInteger, BigInteger> findPrimeFactors(BigInteger n) {
        std::pair<BigInteger, BigInteger> result;
        BigInteger z = 2;
        while (z * z <= n) {
            if (n % z == 0) {
                result.first = z;
                n /= z;
            } else {
                z++;
            }
        }
        if (n > 1 && isPrime(n)) {
            result.second = n;
        }
        return result;
    }
#endif

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

    static long long powerMod(BigInteger b, BigInteger e, BigInteger m) {
        BigInteger res = 1;
        while (e > 0) {
            if (e % 2 != 0) {
                res = (b * res) % m;
            }
            b = (b * b) % m;
            e /= 2;
        }
        return res.toLongLong();
    }

    static BigInteger modInverse(BigInteger a, BigInteger b)
    {
        BigInteger b0 = b, t, q;
        BigInteger x0 = 0, x1 = 1;
        if (b == 1) return 1;
        while (a > 1) {
            q = a / b;
            t = b, b = a % b, a = t;
            t = x0, x0 = x1 - q * x0, x1 = t;
        }
        if (x1 < 0) x1 += b0;
        return x1;
    }

    static bool isPrime(BigInteger n)
    {
        // https://en.wikipedia.org/wiki/Primality_test#Pseudocode
        if (n <= 1) {
            return false;
        }
        if (n <= 3) {
            return true;
        }
        if (n % 2 == 0 || n % 3 == 0) {
            return false;
        }
        for (BigInteger i = 5; i * i <= n; i += 6) {
            if (n % i == 0 || n % (i + 2) == 0) {
               return false;
            }
        }
        return true;
    }

    // for tests
    friend class Ripe5Test_IsPrime_Test;
    friend class Ripe5Test_FindGCD_Test;
    friend class Ripe5Test_InvModulo_Test;
    friend class Ripe5Test_PowerMod_Test;
};
