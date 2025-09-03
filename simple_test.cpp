#include <iostream>
#include <string>
#include "secp256k1lib/secp256k1.h"
#include "addressutil/addressutil.h"

int main() {
    std::cout << "=== simple base58 test ===" << std::endl;
    
    // test direct base58 encoding with known values
    // test case with 2 leading zeros (should produce '11' prefix)
    unsigned int testwords1[8] = {0, 0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0};
    secp256k1::uint256 testvalue1(testwords1, secp256k1::uint256::bigendian);
    std::string base58result1 = base58::tobase58(testvalue1);
    std::cout << "base58 with 2 leading zeros: " << base58result1 << std::endl;
    
    // test case with 1 leading zero (should produce '1' prefix)
    unsigned int testwords2[8] = {0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678};
    secp256k1::uint256 testvalue2(testwords2, secp256k1::uint256::bigendian);
    std::string base58result2 = base58::tobase58(testvalue2);
    std::cout << "base58 with 1 leading zero: " << base58result2 << std::endl;
    
    // test case with 3 leading zeros (should produce '111' prefix)
    unsigned int testwords3[8] = {0, 0, 0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678};
    secp256k1::uint256 testvalue3(testwords3, secp256k1::uint256::bigendian);
    std::string base58result3 = base58::tobase58(testvalue3);
    std::cout << "base58 with 3 leading zeros: " << base58result3 << std::endl;
    
    // test address generation
    std::cout << "\n=== address generation test ===" << std::endl;
    
    // use a simple test private key
    std::string privkeyhex = "0000000000000000000000000000000000000000000000000000000000000001";
    secp256k1::uint256 privkey = secp256k1::uint256(privkeyhex.c_str());
    
    // generate public key
    secp256k1::ecpoint pubkey = secp256k1::multiplypoint(privkey, secp256k1::g());
    
    // generate address
    std::string address = address::frompublickey(pubkey, false);
    std::cout << "generated address: " << address << std::endl;
    
    // check if it starts with '11'
    if(address.length() >= 2 && address.substr(0, 2) == "11") {
        std::cout << "success: address starts with '11'!" << std::endl;
    } else {
        std::cout << "issue: address does not start with '11'" << std::endl;
    }
    
    return 0;
}