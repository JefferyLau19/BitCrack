#include <iostream>
#include "AddressUtil/AddressUtil.h"
#include "secp256k1.h"

int main() {
    std::cout << "Testing address generation fix..." << std::endl;
    
    // Test with a known private key that should produce an 11... address
    // This is just an example - you would need to use the actual private key
    // that produces the address mentioned in the issue
    
    secp256k1::uint256 privateKey;
    // Set a test private key (this is just an example)
    unsigned int keyWords[8] = {0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 
                               0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0};
    privateKey = secp256k1::uint256(keyWords, secp256k1::uint256::BigEndian);
    
    // Generate public key
    secp256k1::ecpoint publicKey = secp256k1::multiplyPoint(privateKey, secp256k1::G());
    
    // Generate address
    std::string address = Address::fromPublicKey(publicKey, false);
    
    std::cout << "Generated address: " << address << std::endl;
    
    // Test the Base58 encoding directly
    unsigned int addressWords[8] = {0, 0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0};
    secp256k1::uint256 addressBigInt(addressWords, secp256k1::uint256::BigEndian);
    std::string base58Address = Base58::toBase58(addressBigInt);
    
    std::cout << "Base58 address with 2 leading zeros: " << base58Address << std::endl;
    
    // Test with 1 leading zero
    unsigned int addressWords2[8] = {0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678};
    secp256k1::uint256 addressBigInt2(addressWords2, secp256k1::uint256::BigEndian);
    std::string base58Address2 = Base58::toBase58(addressBigInt2);
    
    std::cout << "Base58 address with 1 leading zero: " << base58Address2 << std::endl;
    
    return 0;
}