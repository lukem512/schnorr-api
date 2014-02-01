// Schnorr.cpp : Defines the entry point for the console application.
//

#include "Schnorr.h"

int main(int argc, char* argv[])
{
	byte message[30] = "Hello There";
	cout << message << endl;

	// generate curve & keys
	CCurve curve;
	curve.GenerateKeys();

	// retrieve public keys
	Integer pk1, pk2;
	pk1 = curve.GetPublicKeyX();
	pk2 = curve.GetPublicKeyY();
	cout << "pk1: " << pk1 << endl;
    cout << "pk2: " << pk2 << endl;
	
	// sign the message
	Integer sig1, sig2;
	curve.Sign(sig1, sig2, message, 30);

	// display the signatures
	cout << "sig1: " << sig1 << endl;
    cout << "sig2: " << sig2 << endl;
        
	bool ans = curve.Verify(sig1, sig2, message, 30);
	cout << "verified: " << ans << endl;

	// TESTING PUBLIC KEYS

    cout << "Testing public key encoding/decoding..." << endl;

    std::vector<unsigned char> vchPubKey;
	if (!curve.GetVchPublicKey(vchPubKey))
		cout << "GetVchPublicKey failed" << endl;

    if (!curve.SetVchPublicKey(vchPubKey))
    	cout << "SetVchPublicKey failed" << endl;

    Integer pk3, pk4;
    pk3 = curve.GetPublicKeyX();
    pk4 = curve.GetPublicKeyY();

    if (pk1 == pk3 && pk2 == pk4)
    	cout << "Public keys match" << endl;
    else
    	cout << "Public keys do not match" << endl;

    // TESTING SECRET KEY

    cout << "Testing secret key encoding/decoding..." << endl;

    Integer sk1;
    sk1 = curve.GetSecretKey();

    std::vector<unsigned char> vchSecretKey;
    if (!curve.GetVchSecretKey(vchSecretKey))
    	cout << "GetVchSecretKey failed" << endl;

    if (!curve.SetVchSecretKey(vchSecretKey))
    	cout << "SetVchPublicKey failed" << endl;

    Integer sk2;
    sk2 = curve.GetSecretKey();

    if (sk1 == sk2)
    	cout << "Secret keys match" << endl;
    else
    	cout << "ERROR: Secret keys do not match" << endl;

    // TESTING SIGNATURES

	cout << "Testing signature encoding/decoding..." << endl;

	std::vector<unsigned char> vchSig;
	if (!curve.GetVchFromSignature(vchSig, sig1, sig2))
		cout << "GetVchFromSignature failed" << endl;

	Integer sig3, sig4;
	if (!curve.GetSignatureFromVch(vchSig, sig3, sig4))
		cout << "GetSignatureFromVch failed" << endl;

    if (sig1 == sig3 && sig2 == sig4)
    	cout << "Signatures match" << endl;
    else
    	cout << "Signatures do not match" << endl;

	return 0;
}

