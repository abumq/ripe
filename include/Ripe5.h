#include <cmath>
#include <stdexcept>
#include <map>
#include <string>
#include <vector>
#include "include/Ripe.h"
//#include "include/InfInt.h"
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>

///
/// \brief Ripe class
///
/// PLEASE NOTE, THIS IS FROM UPCOMING VERSION OF RIPE
/// DO NOT USE UNTIL THE FINAL RELEASE (Ripe 5.x)
///
class Ripe5 {
public:
    typedef CryptoPP::Integer BigInteger; // this is only temp as InfInt does not support shifting of bits
    typedef long long BigIntegerOld;
    typedef long long int byte_t;

    enum class PaddingType {
        PKCS_1v1_5,
        NO_PADDING
    };

    class PublicKey {
    public:
        PublicKey() = default;

        PublicKey(BigInteger n, int e) :
            m_n(n),
            m_e(e) {
        }

        virtual ~PublicKey() = default;

        inline BigInteger n() const { return m_n; }
        inline int e() const { return m_e; }

    private:
        BigInteger m_n;
        int m_e;
    };

    class RawKey {
    public:
        static const unsigned int DEFAULT_PUBLIC_EXPONENT = 65537;

        RawKey(BigInteger p, BigInteger q, int e = DEFAULT_PUBLIC_EXPONENT, bool skipPrimeCheck = true) :
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
        inline int e() const { return m_e; }
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
        int m_e;
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

    static std::map<unsigned long, int> pkcs1pad2(const std::string& s, unsigned long n) {
        if (n < s.size() + 11) { // TODO: fix for utf-8
            throw std::runtime_error("Message too long for RSA");
        }
        std::map<unsigned long, int> ba; // TODO: Use int for key too?? as this is bit length
        long long i = s.size() - 1;
        while(i >= 0 && n > 0) {
            int c = static_cast<int>(s.at(i--));
            if (c < 128) { // encode using utf-8
                ba[--n] = c;
            }
            else if ((c > 127) && (c < 2048)) {
                ba[--n] = (c & 63) | 128;
                ba[--n] = (c >> 6) | 192;
            }
            else {
                ba[--n] = (c & 63) | 128;
                ba[--n] = ((c >> 6) & 63) | 128;
                ba[--n] = (c >> 12) | 224;
            }
        }
        ba[--n] = 0;
        int r = rand() % 100 + 1;

        srand (time(NULL));
        while(n > 2) { // random non-zero pad
            r = 0;
            while(r == 0) r = rand() % 100 + 1;
            ba[--n] = r;
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return ba;
    }

    static std::string pkcs1unpad2(BigInteger m, unsigned long n) {
        byte b[n];
        m.Encode(b, n);
        /*
        var b = d.toByteArray();
        var i = 0;
        while(i < b.length && b[i] == 0) ++i;
        if(b.length-i != n-1 || b[i] != 2)
            return null;
        ++i;
        while(b[i] != 0)
            if(++i >= b.length) return null;
        var ret = "";
        while(++i < b.length) {
            var c = b[i] & 255;
            if(c < 128) { // utf-8 decode
                ret += String.fromCharCode(c);
            }
            else if((c > 191) && (c < 224)) {
                ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
                ++i;
            }
            else {
                ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
                i += 2;
            }
        }
        return ret;*/
        return "";
    }

    static std::string encrypt(const PublicKey* publicKey,
                               const std::string& m,
                               PaddingType paddingType = PaddingType::PKCS_1v1_5)
    {

        std::string result;
        if (paddingType == PaddingType::PKCS_1v1_5) {
            std::map<unsigned long, int> msg = pkcs1pad2(m, (publicKey->n().BitCount() + 7) >> 3);
            std::for_each(msg.begin(), msg.end(), [&](const std::pair<unsigned long, int>& item) {
                result.append(std::to_string(item.second));
            });
        } else {
            std::for_each(m.begin(), m.end(), [&](char c) {
                result.append(std::to_string(static_cast<int>(c)));
            });
        }

        std::cout << "padded m = " << result << std::endl;
        BigInteger bi(result.c_str());
        BigInteger b5(5);

        std::cout << "b5=" << powerMod(b5, 3, 19) << std::endl;

        std::stringstream ss;
        ss << powerMod(bi, publicKey->e(), publicKey->n());
        return ss.str();
    }

    static std::string decrypt(const PrivateKey* privateKey,
                               const std::string& m,
                               PaddingType paddingType = PaddingType::NO_PADDING)
    {
        BigInteger msg(m.c_str());
        BigInteger decr(powerMod(msg, privateKey->d(), privateKey->n()));
        std::string result;

        if (paddingType == PaddingType::PKCS_1v1_5) {
            result = pkcs1unpad2(decr, (privateKey->n().BitCount() + 7) >> 3);
        } else {
            // todo: convert to chars e.g, 72105 => Hi
            result = std::to_string(decr.ConvertToLong());
        }
        return result;
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

    static BigInteger powerMod(BigInteger b, BigInteger e, BigInteger m)
    {
        BigInteger res = 1;
        while (e > 0) {
            if (e % 2 != 0) {
                res = (b * res) % m;
            }
            b = (b * b) % m;
            e /= 2;
        }
        return res;
    }

    static BigInteger modInverse(BigInteger a, BigInteger b)
    {
        return a.InverseMod(b);/*
        BigInteger b0 = b, t, q;
        BigInteger x0 = 0, x1 = 1;
        if (b == 1) return 1;
        while (a > 1) {
            q = a / b;
            t = b, b = a % b, a = t;
            t = x0, x0 = x1 - q * x0, x1 = t;
        }
        if (x1 < 0) x1 += b0;
        return x1;*/
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
