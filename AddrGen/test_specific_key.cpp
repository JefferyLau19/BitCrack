#include <iostream>
#include <string>
#include "secp256k1.h"
#include "AddressUtil.h"

int main() {
    std::cout << "=== Testing Address Generation Fix ===" << std::endl;
    
    // Test 1: The specific private key that's causing issues
    std::cout << "\n--- Test 1: Original Issue ---" << std::endl;
    std::string privKeyHex1 = "8C59EE3A427165F336038CFEBE275CDCE721FCFAD33B1DEC26760A5F9F930AC1";
    
    std::cout << "Testing private key: " << privKeyHex1 << std::endl;
    
    // Convert hex string to uint256
    secp256k1::uint256 privKey1 = secp256k1::uint256(privKeyHex1.c_str());
    
    // Generate public key
    secp256k1::ecpoint pubKey1 = secp256k1::multiplyPoint(privKey1, secp256k1::G());
    
    // Test both compressed and uncompressed addresses
    std::string uncompressedAddr1 = Address::fromPublicKey(pubKey1, false);
    std::string compressedAddr1 = Address::fromPublicKey(pubKey1, true);
    
    std::cout << "Uncompressed address: " << uncompressedAddr1 << std::endl;
    std::cout << "Compressed address: " << compressedAddr1 << std::endl;
    
    // Expected address according to user
    std::string expectedAddr1 = "133FgAwQ2PJDF165xV2TvdLzHsLxcWNRi8";
    std::cout << "Expected address: " << expectedAddr1 << std::endl;
    
    // Check if either matches
    if(uncompressedAddr1 == expectedAddr1) {
        std::cout << "MATCH: Uncompressed address matches expected!" << std::endl;
    } else if(compressedAddr1 == expectedAddr1) {
        std::cout << "MATCH: Compressed address matches expected!" << std::endl;
    } else {
        std::cout << "NO MATCH: Neither address matches expected!" << std::endl;
    }
    
    // Test 2: Test the '11' prefix issue
    std::cout << "\n--- Test 2: '11' Prefix Issue ---" << std::endl;
    // This is a test private key - replace with actual key that produces 11... address
    std::string privKeyHex2 = "0000000000000000000000000000000000000000000000000000000000000001";
    
    std::cout << "Testing private key: " << privKeyHex2 << std::endl;
    
    // Convert hex string to uint256
    secp256k1::uint256 privKey2 = secp256k1::uint256(privKeyHex2.c_str());
    
    // Generate public key
    secp256k1::ecpoint pubKey2 = secp256k1::multiplyPoint(privKey2, secp256k1::G());
    
    // Test both compressed and uncompressed addresses
    std::string uncompressedAddr2 = Address::fromPublicKey(pubKey2, false);
    std::string compressedAddr2 = Address::fromPublicKey(pubKey2, true);
    
    std::cout << "Uncompressed address: " << uncompressedAddr2 << std::endl;
    std::cout << "Compressed address: " << compressedAddr2 << std::endl;
    
    // Check if address starts with '11' (for uncompressed) or '1' followed by non-'1' (for compressed)
    if(uncompressedAddr2.length() >= 2 && uncompressedAddr2.substr(0, 2) == "11") {
        std::cout << "SUCCESS: Uncompressed address starts with '11'!" << std::endl;
    } else {
        std::cout << "ISSUE: Uncompressed address does not start with '11'" << std::endl;
    }
    
    if(compressedAddr2.length() >= 2 && compressedAddr2[0] == '1' && compressedAddr2[1] != '1') {
        std::cout << "SUCCESS: Compressed address starts with '1' followed by non-'1'!" << std::endl;
    } else {
        std::cout << "INFO: Compressed address pattern: " << compressedAddr2.substr(0, 2) << std::endl;
    }
    
    // Test 3: Direct base58 test with known values
    std::cout << "\n--- Test 3: Direct Base58 Encoding Test ---" << std::endl;
    
    // Test case with 2 leading zeros (should produce '11' prefix)
    unsigned int testWords1[8] = {0, 0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0};
    secp256k1::uint256 testValue1(testWords1, secp256k1::uint256::BigEndian);
    std::string base58Result1 = Base58::toBase58(testValue1);
    std::cout << "Base58 with 2 leading zeros: " << base58Result1 << std::endl;
    
    // Test case with 1 leading zero (should produce '1' prefix)
    unsigned int testWords2[8] = {0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678};
    secp256k1::uint256 testValue2(testWords2, secp256k1::uint256::BigEndian);
    std::string base58Result2 = Base58::toBase58(testValue2);
    std::cout << "Base58 with 1 leading zero: " << base58Result2 << std::endl;
    
    // Test case with 3 leading zeros (should produce '111' prefix)
    unsigned int testWords3[8] = {0, 0, 0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678};
    secp256k1::uint256 testValue3(testWords3, secp256k1::uint256::BigEndian);
    std::string base58Result3 = Base58::toBase58(testValue3);
    std::cout << "Base58 with 3 leading zeros: " << base58Result3 << std::endl;
    
    std::cout << "\n=== Test Completed ===" << std::endl;
    
    return 0;
}