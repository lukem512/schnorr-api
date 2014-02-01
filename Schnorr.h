#ifndef _Schnorr
#define _Schnorr


#include <string>
#include <iostream>
using namespace std;

#include "cryptopp/osrng.h"      // Random Number Generator
#include "cryptopp/eccrypto.h"   // Elliptic Curve
#include "cryptopp/ecp.h"        // F(p) EC
#include "cryptopp/integer.h"    // Integer Operations
using namespace CryptoPP;

// A class encapsulating the secp256r1 curve
// and Schnorr signing functions
class CCurve {
private:
	static const size_t SCHNORR_SECRET_KEY_SIZE = 32;
	static const size_t SCHNORR_SIG_SIZE = 32;
	static const size_t SCHNORR_PUBLIC_KEY_COMPRESSED_SIZE = 33;
	static const size_t SCHNORR_PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;

	bool secretKeySet;
	bool publicKeySet;

	ECP ec;
    ECPPoint G;
    Integer q;
    AutoSeededRandomPool rng;

    Integer secretKey;
    ECPPoint Q; // public key

    Integer HashPointMessage(const ECPPoint& R, const byte* message, int mlen);

public:
	CCurve();

	~CCurve();

	bool GenerateSecretKey();
	bool GeneratePublicKey();
	bool GenerateKeys();

	bool SetVchPublicKey(std::vector<unsigned char> vchPubKey);
	bool GetVchPublicKey(std::vector<unsigned char>& vchPubKey);

	bool SetVchSecretKey(std::vector<unsigned char> vchSecret);
	bool GetVchSecretKey(std::vector<unsigned char>& vchSecret);

	bool GetSignatureFromVch(std::vector<unsigned char> vchSig, Integer& sigE, Integer& sigS);
	bool GetVchFromSignature(std::vector<unsigned char>& vchSig, Integer sigE, Integer sigS);

	Integer GetPublicKeyX();
	Integer GetPublicKeyY();
	Integer GetSecretKey();

	void Sign(Integer& sigE, Integer& sigS, const byte* message, int mlen);
	bool Verify(const Integer& sigE, const Integer& sigS,
				const byte* message, int mlen);
};

void KeyGen(Integer& sk,Integer& pk1,Integer& pk2,AutoSeededRandomPool& rng);

void Sign(Integer& sig1,Integer& sig2,const Integer& sk,
          const byte* message,int mlen,AutoSeededRandomPool& rng);

bool Verify(const Integer& pk1,const Integer& pk2,
            const Integer& sig1,const Integer& sig2,
            const byte* message,int mlen);

#endif
