#include <iostream>
#include <string>
#include "secp256k1.h"
#include "AddressUtil.h"
#include "../CryptoUtil/CryptoUtil.h"

int main() {
    std::cout << "=== Testing WIF Private Key ===" << std::endl;
    
    // The WIF private key provided by user
    std::string wifPrivKey = "KzzsmhLXdJXD5wRmGvgDQzJjWo8Rr6K3kHmCi6PUwPbYAvnJ7xqD";
    
    std::cout << "WIF Private Key: " << wifPrivKey << std::endl;
    
    // Note: This is a WIF format private key, which needs to be decoded first
    // For now, let's test with a hex representation that we know works
    // We'll need to implement WIF decoding to properly test this key
    
    // Test with multiple hex keys provided by user
    std::vector<std::string> hexPrivKeys = {
        "26B9E42F0374FF2BD4DD9B6E2ED163809ECA8B19A0DFDEACBBFE00A814ED2FC8",
        "E6BCDE14A1473FD2A4A434C706CF6E6EE8FC9337412CA1163EB2DDD0EE525DA0",
        "4EEFC96B4D1B50B27FFE1C5C98DC040DF86563333E0EE7C15BB2ACC384BA98EB"
    };
    
    for(size_t i = 0; i < hexPrivKeys.size(); i++) {
        std::string hexPrivKey = hexPrivKeys[i];
        std::cout << "\nTesting with known hex key #" << (i+1) << ": " << hexPrivKey << std::endl;
    
    // Convert hex string to uint256
    secp256k1::uint256 privKey = secp256k1::uint256(hexPrivKey.c_str());
    
    // Generate public key
    secp256k1::ecpoint pubKey = secp256k1::multiplyPoint(privKey, secp256k1::G());
    
    // Generate addresses
    std::string uncompressedAddr = Address::fromPublicKey(pubKey, false);
    std::string compressedAddr = Address::fromPublicKey(pubKey, true);
    
    std::cout << "Uncompressed address: " << uncompressedAddr << std::endl;
    std::cout << "Compressed address: " << compressedAddr << std::endl;
    
    // Debug: Let's check the hash160 value for compressed address
    unsigned int digest[5];
    Hash::hashPublicKeyCompressed(pubKey, digest);
    std::cout << "Hash160 (first byte): " << std::hex << (digest[0] >> 24) << std::endl;
    std::cout << "Hash160 (full): ";
    for(int i = 0; i < 5; i++) {
        std::cout << std::hex << digest[i] << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Debug: Let's check the addressWords structure
    unsigned int checksum = crypto::checksum(digest);
    unsigned int addressWords[8] = { 0 };
    for(int i = 0; i < 5; i++) {
        addressWords[2 + i] = digest[i];
    }
    addressWords[7] = checksum;
    
    std::cout << "AddressWords structure:" << std::endl;
    for(int i = 0; i < 8; i++) {
        std::cout << "words[" << i << "] = " << std::hex << addressWords[i] << " (first byte: " << ((addressWords[i] >> 24) & 0xFF) << ")" << std::endl;
    }
    std::cout << std::dec << std::endl;
    
    }
    
    std::cout << "\nNote: To test the WIF key " << wifPrivKey << std::endl;
    std::cout << "We would need to implement WIF decoding first." << std::endl;
    std::cout << "WIF format includes version byte, compression flag, and checksum." << std::endl;
    
    return 0;
}