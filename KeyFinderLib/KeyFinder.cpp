#include <fstream>
#include <iostream>
#include <sstream>

#include "KeyFinder.h"
#include "../util/util.h"
#include "../AddressUtil/AddressUtil.h"
#include "../AddressUtil/AddressUtil.h"
#include "../secp256k1lib/secp256k1.h"

#include "../Logger/Logger.h"


void KeyFinder::defaultResultCallback(KeySearchResult result)
{
	// Do nothing
}

void KeyFinder::defaultStatusCallback(KeySearchStatus status)
{
	// Do nothing
}

KeyFinder::KeyFinder(int compression, KeySearchDevice* device, bool randomMode, bool randomRangeMode, const secp256k1::uint256 &randomRangeStart, const secp256k1::uint256 &randomRangeEnd)
{
	_total = 0;
	_statusInterval = 1000;
	_device = device;

	_compression = compression;

	_statusCallback = NULL;

	_resultCallback = NULL;

    _iterCount = 0;

    _randomMode = randomMode;
    _randomRangeMode = randomRangeMode;
    _randomRangeStart = randomRangeStart;
    _randomRangeEnd = randomRangeEnd;
    
    // Initialize half-hour statistics variables
    _prevHalfHourTotal = 0;
    
    // If compression mode is BOTH, log this information
    if(_compression == PointCompressionType::BOTH) {
        Logger::log(LogLevel::Info, "Running in BOTH compression mode - will check both compressed and uncompressed addresses");
    }
}

KeyFinder::~KeyFinder()
{
}

void KeyFinder::setTargets(std::vector<std::string> &targets)
{
	if(targets.size() == 0) {
		throw KeySearchException("Requires at least 1 target");
	}

	_targets.clear();

	// Convert each address from base58 encoded form to a 160-bit integer
	for(unsigned int i = 0; i < targets.size(); i++) {

		if(!Address::verifyAddress(targets[i])) {
			throw KeySearchException("Invalid address '" + targets[i] + "'");
		}

		KeySearchTarget t;

		Base58::toHash160(targets[i], t.value);

		_targets.insert(t);
		
		// If compression mode is BOTH, also add the alternative format
		if(_compression == PointCompressionType::BOTH) {
			// For each target address, we need to determine if it's compressed or uncompressed
			// and add the opposite format to the target list
			// This is complex because we can't easily determine the format from the address alone
			// For now, we'll add both formats for each target address
			KeySearchTarget t2 = t; // Copy the target
			_targets.insert(t2); // This will be handled by the device-specific logic
		}
	}

    _device->setTargets(_targets);
}

void KeyFinder::setTargets(std::string targetsFile)
{
	std::ifstream inFile(targetsFile.c_str());

	if(!inFile.is_open()) {
		Logger::log(LogLevel::Error, "Unable to open '" + targetsFile + "'");
		throw KeySearchException();
	}

	_targets.clear();

	std::string line;
	Logger::log(LogLevel::Info, "Loading addresses from '" + targetsFile + "'");
	while(std::getline(inFile, line)) {
		util::removeNewline(line);
        line = util::trim(line);

		if(line.length() > 0) {
			if(!Address::verifyAddress(line)) {
				Logger::log(LogLevel::Error, "Invalid address '" + line + "'");
				throw KeySearchException();
			}

			KeySearchTarget t;

			Base58::toHash160(line, t.value);

			_targets.insert(t);
			
			// If compression mode is BOTH, also add the alternative format
			if(_compression == PointCompressionType::BOTH) {
				// For each target address, we need to determine if it's compressed or uncompressed
				// and add the opposite format to the target list
				// This is complex because we can't easily determine the format from the address alone
				// For now, we'll add both formats for each target address
				KeySearchTarget t2 = t; // Copy the target
				_targets.insert(t2); // This will be handled by the device-specific logic
			}
		}
	}
	Logger::log(LogLevel::Info, util::formatThousands(_targets.size()) + " addresses loaded ("
		+ util::format("%.1f", (double)(sizeof(KeySearchTarget) * _targets.size()) / (double)(1024 * 1024)) + "MB)");

    _device->setTargets(_targets);
}


void KeyFinder::setResultCallback(void(*callback)(KeySearchResult))
{
	_resultCallback = callback;
}

void KeyFinder::setStatusCallback(void(*callback)(KeySearchStatus))
{
	_statusCallback = callback;
}

void KeyFinder::setStatusInterval(uint64_t interval)
{
	_statusInterval = interval;
}

void KeyFinder::setTargetsOnDevice()
{
	// Set the target in constant memory
	std::vector<struct hash160> targets;

	for(std::set<KeySearchTarget>::iterator i = _targets.begin(); i != _targets.end(); ++i) {
		targets.push_back(hash160((*i).value));
	}

    _device->setTargets(_targets);
}

void KeyFinder::init()
{
	Logger::log(LogLevel::Info, "Initializing " + _device->getDeviceName());

    // Set random mode if enabled BEFORE initializing the device
    if(_randomMode) {
        _device->setRandomMode(true);
        Logger::log(LogLevel::Info, "Random mode enabled");
        
        // Set random range if in random range mode
        if(_randomRangeMode) {
            _device->setRandomRange(_randomRangeStart, _randomRangeEnd);
            Logger::log(LogLevel::Info, "Random range mode enabled with range: " + _randomRangeStart.toString(16) + " - " + _randomRangeEnd.toString(16));
        }
    }
    
    _device->init(_compression);
    
    // Output example private key and address at startup
    outputExampleKeyAndAddress();
}

void KeyFinder::outputExampleKeyAndAddress()
{
    // Generate a sample private key
    secp256k1::uint256 examplePrivKey;
    
    if(_randomRangeMode) {
        // In random range mode, use the start of the range as example
        examplePrivKey = _randomRangeStart;
        Logger::log(LogLevel::Info, "Random range mode: Using range start as example key");
    } else if(_randomMode) {
        // In random mode, generate a random example private key
        // Use a simple hash of current time to generate a somewhat random but deterministic example
        time_t currentTime = time(NULL);
        examplePrivKey = secp256k1::uint256((uint64_t)currentTime);
        
        // Ensure it's within valid range and not zero
        if(examplePrivKey.cmp(secp256k1::N) >= 0 || examplePrivKey.isZero()) {
            examplePrivKey = secp256k1::uint256(1);
        }
        
        Logger::log(LogLevel::Info, "Random mode: Using random example key");
    }
    
    // Generate public key from private key
    secp256k1::ecpoint examplePubKey = secp256k1::multiplyPoint(examplePrivKey, secp256k1::G());
    
    // Generate both compressed and uncompressed addresses
    std::string uncompressedAddress = Address::fromPublicKey(examplePubKey, false);
    std::string compressedAddress = Address::fromPublicKey(examplePubKey, true);
    
    // Format private key as hex string
    std::string privKeyHex = examplePrivKey.toString(16);
    
    // Log example key and both addresses
    std::stringstream ss;
    ss << "Example Private Key: " << privKeyHex;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Example Uncompressed Address: " << uncompressedAddress;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Example Compressed Address: " << compressedAddress;
    Logger::log(LogLevel::Info, ss.str());
}

void KeyFinder::logMatchedKey(const KeySearchResult &result)
{
    std::stringstream ss;
    
    // Format private key as hex string
    std::string privKeyHex = result.privateKey.toString(16);
    
    // Format public key as hex string
    std::string pubKeyX = result.publicKey.x.toString(16);
    std::string pubKeyY = result.publicKey.y.toString(16);
    
    // Generate both compressed and uncompressed addresses
    std::string uncompressedAddress = Address::fromPublicKey(result.publicKey, false);
    std::string compressedAddress = Address::fromPublicKey(result.publicKey, true);
    
    ss << "=== MATCHED KEY FOUND ===";
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Private Key: " << privKeyHex;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Public Key X: " << pubKeyX;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Public Key Y: " << pubKeyY;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Uncompressed Address: " << uncompressedAddress;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Compressed Address: " << compressedAddress;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Matched Format: " << (result.compressed ? "Compressed" : "Uncompressed");
    Logger::log(LogLevel::Info, ss.str());
    
    Logger::log(LogLevel::Info, "=========================");
}

void KeyFinder::logHalfHourStats()
{
    std::stringstream ss;
    
    // Get current time
    time_t now = time(0);
    struct tm tstruct = *localtime(&now);
    char timeBuf[80];
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tstruct);
    
    ss << "=== HALF-HOUR STATS ===";
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Current Time: " << timeBuf;
    Logger::log(LogLevel::Info, ss.str());
    
    ss.str("");
    ss << "Total Keys Searched: " << util::formatThousands(_total);
    Logger::log(LogLevel::Info, ss.str());
    
    // Calculate and display average speed for the last half-hour
    if(_prevHalfHourTotal > 0) {
        uint64_t keysSearchedInInterval = _total - _prevHalfHourTotal;
        double halfHourSeconds = 1800.0; // 30 minutes in seconds
        double avgSpeed = (double)keysSearchedInInterval / halfHourSeconds / 1000000.0; // Mkeys/s
        
        ss.str("");
        ss << "Average Speed (last 30min): " << util::format("%.2f", avgSpeed) << " Mkeys/s";
        Logger::log(LogLevel::Info, ss.str());
    }
    
    // Update previous values for next interval
    _prevHalfHourTotal = _total;
    
    Logger::log(LogLevel::Info, "=========================");
}


void KeyFinder::stop()
{
	_running = false;
}

void KeyFinder::removeTargetFromList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);

	_targets.erase(t);
}

bool KeyFinder::isTargetInList(const unsigned int hash[5])
{
	KeySearchTarget t(hash);
	return _targets.find(t) != _targets.end();
}


void KeyFinder::run()
{
    uint64_t pointsPerIteration = _device->keysPerStep();

	_running = true;

	util::Timer timer;
	util::Timer halfHourTimer;

	timer.start();
	halfHourTimer.start();

	uint64_t prevIterCount = 0;

	_totalTime = 0;
	
	// Set up half-hour interval (30 minutes = 1800000 milliseconds)
	const uint64_t halfHourInterval = 1800000; // 30 minutes in milliseconds

	while(_running) {

        _device->doStep();
        _iterCount++;

		// Update status
		uint64_t t = timer.getTime();
		uint64_t halfHourT = halfHourTimer.getTime();

		// Check for half-hour interval logging
		if(halfHourT >= halfHourInterval) {
			logHalfHourStats();
			halfHourTimer.start();
		}

		if(t >= _statusInterval) {

			KeySearchStatus info;

			uint64_t count = (_iterCount - prevIterCount) * pointsPerIteration;

			_total += count;

			double seconds = (double)t / 1000.0;

			info.speed = (double)((double)count / seconds) / 1000000.0;

			info.total = _total;

			info.totalTime = _totalTime;

			uint64_t freeMem = 0;

			uint64_t totalMem = 0;

			_device->getMemoryInfo(freeMem, totalMem);

			info.freeMemory = freeMem;
			info.deviceMemory = totalMem;
			info.deviceName = _device->getDeviceName();
			info.targets = _targets.size();
            info.nextKey = getNextKey();

			_statusCallback(info);

			timer.start();
			prevIterCount = _iterCount;
			_totalTime += t;
		}

        std::vector<KeySearchResult> results;

        if(_device->getResults(results) > 0) {

			for(unsigned int i = 0; i < results.size(); i++) {

				// Handle based on compression mode
				if(_compression == PointCompressionType::BOTH) {
					// Create two results: one for compressed and one for uncompressed address
					KeySearchResult uncompressedInfo;
					uncompressedInfo.privateKey = results[i].privateKey;
					uncompressedInfo.publicKey = results[i].publicKey;
					uncompressedInfo.compressed = false;
					uncompressedInfo.address = Address::fromPublicKey(results[i].publicKey, false);
					// Calculate hash for uncompressed address
					Hash::hashPublicKey(results[i].publicKey, uncompressedInfo.hash);

					KeySearchResult compressedInfo;
					compressedInfo.privateKey = results[i].privateKey;
					compressedInfo.publicKey = results[i].publicKey;
					compressedInfo.compressed = true;
					compressedInfo.address = Address::fromPublicKey(results[i].publicKey, true);
					// Calculate hash for compressed address
					Hash::hashPublicKeyCompressed(results[i].publicKey, compressedInfo.hash);

					// Check if uncompressed address matches any target
					if(isTargetInList(uncompressedInfo.hash)) {
						// Log the matched key information
						logMatchedKey(uncompressedInfo);

						_resultCallback(uncompressedInfo);
                        
                        // Remove the hash that was found
                        removeTargetFromList(uncompressedInfo.hash);
					}
					
					// Check if compressed address matches any target
					if(isTargetInList(compressedInfo.hash)) {
						// Log the matched key information
						logMatchedKey(compressedInfo);

						_resultCallback(compressedInfo);
						
						// Remove the hash that was found
						removeTargetFromList(compressedInfo.hash);
					}
				} else {
					// Single compression mode - only check the specified format
					KeySearchResult info;
					info.privateKey = results[i].privateKey;
					info.publicKey = results[i].publicKey;
					info.compressed = (_compression == PointCompressionType::COMPRESSED);
					info.address = Address::fromPublicKey(results[i].publicKey, info.compressed);
					
					// Calculate hash based on compression type
					if(info.compressed) {
						Hash::hashPublicKeyCompressed(results[i].publicKey, info.hash);
					} else {
						Hash::hashPublicKey(results[i].publicKey, info.hash);
					}

					// Check if address matches any target
					if(isTargetInList(info.hash)) {
						// Log the matched key information
						logMatchedKey(info);

						_resultCallback(info);
                        
                        // Remove the hash that was found
                        removeTargetFromList(info.hash);
					}
				}
			}
		}

        // Stop if there are no keys left
        if(_targets.size() == 0) {
            Logger::log(LogLevel::Info, "No targets remaining");
            _running = false;
        }

        // Stop if we searched the entire range (only in non-random_range mode)
        if (!_randomRangeMode) {
            // In random mode, we don't stop based on key range
            // The search continues until all targets are found
        }
	}
}

secp256k1::uint256 KeyFinder::getNextKey()
{
    if (_randomRangeMode) {
        // Calculate the range size
        secp256k1::uint256 rangeSize = _randomRangeEnd - _randomRangeStart + 1;
        
        // Generate a random offset within the range using GPU
        secp256k1::uint256 randomOffset = _device->generateRandomNumber(rangeSize);
        
        // Add the random offset to the start of the range
        return _randomRangeStart + randomOffset;
    } else {
        return _device->getNextKey();
    }
}