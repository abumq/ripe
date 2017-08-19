//
//  Ripe5.h
//
//  Copyright © 2017 Muflihun Labs.
//  All rights reserved.
//
//  http://muflihun.com
//  https://muflihun.github.io/ripe
//  https://github.com/muflihun
//

#include <cmath>
#include <stdexcept>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include "include/Ripe.h"
#include <cryptopp/integer.h>

///
/// \brief Ripe5 is minimal cryptography library purely written in C++11
/// It is single header-only does not dependent on any third-party library.
///
/// Please note, the above statement is not true yet as we're still developing
/// version 5 of library (a.k.a Ripe5)
///
/// PLEASE NOTE, THIS IS FROM UPCOMING VERSION OF RIPE
/// DO NOT USE UNTIL THE FINAL RELEASE (Ripe 5.x)
///
class Ripe5 {
public:

    typedef CryptoPP::Integer BigInteger; // temp

    class PublicKey {
    public:
        PublicKey() = default;

        PublicKey(BigInteger n, int e) :
            m_n(n),
            m_e(e) {
            m_octetLengthOfN = (m_n.BitCount() + 7) >> 3;
        }

        virtual ~PublicKey() = default;

        inline BigInteger n() const { return m_n; }
        inline int e() const { return m_e; }

        inline int octetLengthOfN() const { return m_octetLengthOfN; }

    private:
        BigInteger m_n;
        int m_e;
        int m_octetLengthOfN;
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
            m_octetLengthOfN = (m_n.BitCount() + 7) >> 3;
            m_coeff = modInverse(m_q, m_p);

            m_d = modInverse(m_e, phi);

            // note:
            // https://www.ipa.go.jp/security/rfc/RFC3447EN.html#2 says to use m_e
            // openssl says to use m_d
            m_dp = BigInteger(m_d) % pMinus1;
            m_dq = BigInteger(m_d) % qMinus1;
        }

        virtual ~RawKey() = default;

        inline int octetLengthOfN() const
        {
            return m_octetLengthOfN;
        }

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

        int m_octetLengthOfN;
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

    ///
    /// \brief PKCS #1 padding
    /// \see https://tools.ietf.org/html/rfc3447#page-23
    /// \return corresponding nonnegative integer
    ///
    template <class T = std::wstring>
    static BigInteger pkcs1pad2(const T& s, int n) {
        if (n < s.size() + 11) {
            throw std::runtime_error("Message too long");
        }
        std::vector<int> byteArray(n);
        long long i = s.size() - 1;
        while(i >= 0 && n > 0) {
            int c = static_cast<int>(s.at(i--));
            if (c < 128) {
                // utf
                byteArray[--n] = c;
            } else if ((c > 127) && (c < 2048)) {
                // 16-bit
                byteArray[--n] = (c & 63) | 128;
                byteArray[--n] = (c >> 6) | 192;
            } else {
                // 24-bit
                byteArray[--n] = (c & 63) | 128;
                byteArray[--n] = ((c >> 6) & 63) | 128;
                byteArray[--n] = (c >> 12) | 224;
            }
        }

        // now padding i.e, 0x00 || 0x02 || PS || 0x00
        // see point #2 on https://tools.ietf.org/html/rfc3447#section-7.2.1 under EME-PKCS1-v1_5 encoding

        byteArray[--n] = 0;

        srand(time(NULL));
        int r = rand() % 100 + 1;
        while (n > 2) {
            r = 0;
            while (r == 0) {
                r = rand() % 100 + 1;
            }
            byteArray[--n] = r;
        }
        byteArray[--n] = 2;
        byteArray[--n] = 0;

        // https://tools.ietf.org/html/rfc3447#section-4.2 => steps
        BigInteger result = 0;
        std::size_t len = byteArray.size();
        BigInteger b256 = 256;
        for (std::size_t i = len; i > 0; --i) {
            result += BigInteger(byteArray[i - 1]) * power(b256, BigInteger(len - i));
        }
        return result;
    }

    template <class T = std::wstring>
    static T pkcs1unpad2(const BigInteger& m, unsigned long n)
    {
        // see https://tools.ietf.org/html/rfc3447#section-4.1
        std::vector<int> ba(n);

        BigInteger b256 = 256;
        BigInteger r;
        BigInteger q;
        BigInteger currM = m;

        // TODO: Do error checking as per RFC
        for (int i = 1; i <= n; ++i) {
            currM.Divide(r, q, currM, power(b256, BigInteger(n - i)));
            ba[i - 1] = static_cast<int>(q.ConvertToLong()); // todo: Check!
            currM = r;
        }
        std::size_t baLen = ba.size();
        int i = 0;
        while (i < baLen && ba[i] == 0) {
            // ignore first zeros
            ++i;
        }
        if (baLen - 1 != n - 1 // reached end
                || ba[i] != 2) { // next available char is not 2 as per padding standard
            throw std::runtime_error("Incorrect padding PKCS#1");
        }
        ++i; // we're all good so far,
        // lets check for the <PS>

        // if we hit end while still we're still with zeros, it's a padding error
        while (ba[i] != 0) {
            if (++i >= baLen) { // already ended!
                throw std::runtime_error("Incorrect padding PKCS#1");
            }
        }
        ++i;
        // now we should be at the first non-zero byte
        // which is our first item, we concat all

        std::basic_stringstream<typename T::value_type> ss;
        for (; i < baLen; ++i) {
            // reference: http://en.cppreference.com/w/cpp/language/types -> range of values
            int c = ba[i] & 0xFF;
            if (c < 128) {
                // utf-8
                ss << static_cast<char>(c);
            } else if ((c > 191) && (c < 224)) { // 16-bit char
                ss << static_cast<wchar_t>(((c & 31) << 6) | (ba[i+1] & 63));
                ++i;
            } else { // 24-bit char
                ss << static_cast<wchar_t>(((c & 15) << 12) | ((ba[i+1] & 63) << 6) | (ba[i+2] & 63));
                i += 2;
            }
        }
        return ss.str();
    }

    ///
    /// \brief Encrypts wstring msg using public key.
    ///
    /// \return hex of cipher. Padded using PKCS#1 padding scheme
    ///
    static std::string encrypt(const PublicKey* publicKey,
                               const std::wstring& m)
    {
        return encrypt<decltype(m)>(publicKey, m);
    }

    ///
    /// \brief Encrypts string msg using public key
    ///
    /// \return hex of cipher. Padded using PKCS#1 padding scheme
    ///
    static std::string encrypt(const PublicKey* publicKey,
                               const std::string& m)
    {
        return encrypt<decltype(m)>(publicKey, m);
    }

    ///
    /// \brief Decrypts RSA hex message m using private key
    ///
    /// \return Plain text, return type depends on TResult
    ///
    template <class TResult = std::wstring>
    static TResult decrypt(const PrivateKey* privateKey, const std::string& m)
    {
        // TODO: Add checks https://tools.ietf.org/html/rfc3447#section-7.2.2

        std::string readableMsg = "0x" + m; // 0x helps BigInteger read m as 16-bit integer
        BigInteger msg(readableMsg.c_str());
        // https://tools.ietf.org/html/rfc3447#section-4.1
        int xlen = privateKey->octetLengthOfN();
        if (msg >= power(BigInteger(256), BigInteger(xlen))) {
            throw std::runtime_error("Integer too large");
        }
        BigInteger decr(powerMod(msg, privateKey->d(), privateKey->n()));
        return pkcs1unpad2<TResult>(decr, xlen);
    }

private:

    ///
    /// \brief Generic RSA encryption. T can of std::string or std::wstring
    ///
    template <class T>
    static std::string encrypt(const PublicKey* publicKey, const T& m)
    {
        BigInteger paddedMsg = pkcs1pad2<T>(m, publicKey->octetLengthOfN());
        // TODO: It can be made better
        std::stringstream ss;
        ss << std::hex << powerMod(paddedMsg, publicKey->e(), publicKey->n());
        std::string h(ss.str());
        // https://www.cryptopp.com/docs/ref/class_integer.html#a760aaed96fd0318e21673868ce6e7845
        // says "There is currently no way to suppress the suffix." so we suppress it!!!
        h.erase(h.end() - 1);
        return ((h.size() & 1) == 0) ? h : ("0" + h);
    }

    ///
    /// \brief Fast GCD
    /// \see https://en.wikipedia.org/wiki/Euclidean_algorithm#Extended_Euclidean_algorithm
    ///
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

    ///
    /// \brief Simple (base ^ e) mod m implementation
    /// \param b Base
    /// \param e Exponent
    /// \param m Mod
    ///
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

    ///
    /// \brief Power of numb i.e, b ^ e
    ///
    static BigInteger power(BigInteger b, BigInteger e)
    {
        BigInteger result = 1;
        while (e > 0) {
            if (e.IsOdd()) {
                // we decrement exponent to make it even
                e--;
                // store this multiplication directly to the
                // result
                result *= b;
                // we modify this alg to ignore the next multiplication
                // if we have already reached 0 (for speed)
                // here are details and what we changed and how it all works
                //
                // Let's say we have case of 2 ^ 4 [expected answer = 16]
                // 2 ^ 4 -- b = 4, e = 2 [result = 1]
                // 2 ^ 2 -- b = 16, e = 1 [result = 1]
                // 2 ^ 1 -- e = 0 [result = 1 * 16]
                //
                // here is what we changed here
                // now we have result set and we have e set to zero
                // doing another b ^= b means b = 16 * 16 = 256 (in our case)
                // which is useless so we end here
                if (e == 0) {
                    break;
                }
            }
            e /= 2;
            b *= b;
        }
        return result;
    }

    static BigInteger modInverse(BigInteger a, BigInteger b)
    {
        BigInteger b0 = b, t, q;
        BigInteger x0 = 0, x1 = 1;
        if (b == 1) {
            return 1;
        }
        while (a > 1) {
            q = a / b;
            t = b;
            b = a % b;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) {
            x1 += b0;
        }
        return x1;
    }

    ///
    /// \brief Checks whether n is prime or not
    /// This is fast, see https://en.wikipedia.org/wiki/Primality_test#Pseudocode
    /// for details
    ///
    static bool isPrime(BigInteger n)
    {
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

    ///
    /// \brief Decimal to specific base
    /// \param n Number
    /// \param b Base - default is 8 (octet)
    ///
    template <typename T>
    static T d2o(T n, T b = 8)
    {
        T r, i = 1, o = 0;
        while (n != 0) {
            r = n % b;
            n /= b;
            o += r * i;
            i *= 10;
        }
        return o;
    }

    ///
    /// \brief Specific base to decimal
    /// \param n Number
    /// \param b Base - default is from octet (base 8)
    ///
    template <typename T>
    static T o2d(T n, T b = 8)
    {
        T r, i = 0, o = 0;
        while (n != 0) {
            r = n % 10;
            n /= 10;
            o += r * power(b, i);
            ++i;
        }
        return o;
    }

    // for tests
    friend class Ripe5Test_IsPrime_Test;
    friend class Ripe5Test_FindGCD_Test;
    friend class Ripe5Test_InvModulo_Test;
    friend class Ripe5Test_PowerMod_Test;
};
