#include "CudaKeySearchDevice.h"
#include "../Logger/Logger.h"
#include "../util/util.h"
#include "cudabridge.h"
#include "AddressUtil.h"
#include "../CryptoUtil/CryptoUtil.h"
#include <fstream>
#include <cstdio>

// CUDA内核包装函数声明
void callMarkFoundKeys(int blocks, int threads, unsigned int *d_foundKeyIndices, int foundKeyCount);
void callGenerateRandomPrivateKeys(int blocks, int threads, unsigned int *devPrivateKeys, GpuRngState *devRngStates, uint64_t totalPoints);
void callGenerateRandomPrivateKeysRange(int blocks, int threads, unsigned int *devPrivateKeys, GpuRngState *devRngStates, uint64_t totalPoints, unsigned int *devRangeStart, unsigned int *devRangeEnd);

// 设备常量声明（用于cudaMemcpyToSymbol）
extern __constant__ unsigned int *_PRIVATE_KEYS[1];
extern __constant__ GpuRngState *_RNG_STATES[1];
extern __constant__ bool _USE_RANGE;
extern __constant__ unsigned int _RANGE_START[8];
extern __constant__ unsigned int _RANGE_END[8];

void CudaKeySearchDevice::cudaCall(cudaError_t err)
{
    if(err) {
        std::string errStr = cudaGetErrorString(err);

        throw KeySearchException(errStr);
    }
}

CudaKeySearchDevice::CudaKeySearchDevice(int device, int threads, int pointsPerThread, int blocks)
{
    cuda::CudaDeviceInfo info;
    try {
        info = cuda::getDeviceInfo(device);
        _deviceName = info.name;
    } catch(cuda::CudaException ex) {
        throw KeySearchException(ex.msg);
    }

    if(threads <= 0 || threads % 32 != 0) {
        throw KeySearchException("The number of threads must be a multiple of 32");
    }

    if(pointsPerThread <= 0) {
        throw KeySearchException("At least 1 point per thread required");
    }

    // Specifying blocks on the commandline is depcreated but still supported. If there is no value for
    // blocks, devide the threads evenly among the multi-processors
    if(blocks == 0) {
        if(threads % info.mpCount != 0) {
            throw KeySearchException("The number of threads must be a multiple of " + util::format("%d", info.mpCount));
        }

        _threads = threads / info.mpCount;

        _blocks = info.mpCount;

        while(_threads > 512) {
            _threads /= 2;
            _blocks *= 2;
        }
    } else {
        _threads = threads;
        _blocks = blocks;
    }

    _iterations = 0;

    _device = device;

    _pointsPerThread = pointsPerThread;

    _randomMode = true;
    _randomRangeMode = false;
    
    // 初始化GPU随机数生成器状态为NULL
    _devRngStates = NULL;
}

// 析构函数
CudaKeySearchDevice::~CudaKeySearchDevice()
{
    // 释放GPU随机数生成器状态
    if(_devRngStates != NULL) {
        freeGpuRngStates(_devRngStates);
        _devRngStates = NULL;
    }
}

void CudaKeySearchDevice::init(int compression)
{
    _compression = compression;

    cudaCall(cudaSetDevice(_device));

    // Block on kernel calls
    cudaCall(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));

    // Use a larger portion of shared memory for L1 cache
    cudaCall(cudaDeviceSetCacheConfig(cudaFuncCachePreferL1));

    generateStartingPoints();

    cudaError_t err = allocateChainBuf(_threads * _blocks * _pointsPerThread);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to allocate chain buffer: " + std::string(cudaGetErrorString(err)));
        throw KeySearchException("Failed to allocate chain buffer: " + std::string(cudaGetErrorString(err)));
    }
    cudaCall(err);

    // Set the incrementor point (not used in random mode, but still required by the kernel)
    secp256k1::ecpoint g = secp256k1::G();
    secp256k1::ecpoint p = secp256k1::multiplyPoint(secp256k1::uint256((uint64_t)_threads * _blocks * _pointsPerThread), g);

    err = _resultList.init(sizeof(CudaDeviceResult), 16);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to initialize result list: " + std::string(cudaGetErrorString(err)));
        throw KeySearchException("Failed to initialize result list: " + std::string(cudaGetErrorString(err)));
    }
    cudaCall(err);

    err = setIncrementorPoint(p.x, p.y);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to set incrementor point: " + std::string(cudaGetErrorString(err)));
        throw KeySearchException("Failed to set incrementor point: " + std::string(cudaGetErrorString(err)));
    }
    cudaCall(err);
    
    // 初始化GPU随机数生成器状态
    err = initializeGpuRngStates(&_devRngStates, _threads * _blocks);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to initialize GPU RNG states: " + std::string(cudaGetErrorString(err)));
        throw KeySearchException("Failed to initialize GPU RNG states: " + std::string(cudaGetErrorString(err)));
    }
    cudaCall(err);
}


void CudaKeySearchDevice::generateStartingPoints()
{
    uint64_t totalPoints = (uint64_t)_pointsPerThread * _threads * _blocks;
    uint64_t totalMemory = totalPoints * 40;

    std::vector<secp256k1::uint256> exponents;

    Logger::log(LogLevel::Info, "Generating " + util::formatThousands(totalPoints) + " starting points (" + util::format("%.1f", (double)totalMemory / (double)(1024 * 1024)) + "MB)");

    if(_randomMode) {
        // 使用GPU生成随机私钥
        generateRandomPrivateKeysGPU(exponents);
    } else {
        // Random mode is always enabled, so this code should not be reached
        Logger::log(LogLevel::Error, "Non-random mode should not be used");
        throw KeySearchException("Non-random mode should not be used");
    }

    // Output first 2048 private keys and their addresses to test_add.txt
    outputTestAddresses(exponents);

    // 注意：已经在generateRandomPrivateKeysGPU中初始化了设备密钥
    // cudaCall(_deviceKeys.init(_blocks, _threads, _pointsPerThread, exponents));

    // Show progress in 10% increments
    double pct = 10.0;
    for(int i = 1; i <= 256; i++) {
        cudaCall(_deviceKeys.doStep());

        if(((double)i / 256.0) * 100.0 >= pct) {
            Logger::log(LogLevel::Info, util::format("%.1f%%", pct));
            pct += 10.0;
        }
    }

    Logger::log(LogLevel::Info, "Done");

    _deviceKeys.clearPrivateKeys();
}


void CudaKeySearchDevice::setTargets(const std::set<KeySearchTarget> &targets)
{
    _targets.clear();
    
    for(std::set<KeySearchTarget>::iterator i = targets.begin(); i != targets.end(); ++i) {
        hash160 h(i->value);
        _targets.push_back(h);
    }

    cudaCall(_targetLookup.setTargets(_targets));
}

void CudaKeySearchDevice::doStep()
{
    try {
        // In random mode, we always call the kernel with false for the initial step
        callKeyFinderKernel(_blocks, _threads, _pointsPerThread, false, _compression);
    } catch(cuda::CudaException ex) {
        throw KeySearchException(ex.msg);
    }

    getResultsInternal();

    _iterations++;
}

uint64_t CudaKeySearchDevice::keysPerStep()
{
    return (uint64_t)_blocks * _threads * _pointsPerThread;
}

std::string CudaKeySearchDevice::getDeviceName()
{
    return _deviceName;
}

void CudaKeySearchDevice::getMemoryInfo(uint64_t &freeMem, uint64_t &totalMem)
{
    cudaCall(cudaMemGetInfo(&freeMem, &totalMem));
}

void CudaKeySearchDevice::removeTargetFromList(const unsigned int hash[5])
{
    size_t count = _targets.size();

    while(count) {
        if(memcmp(hash, _targets[count - 1].h, 20) == 0) {
            _targets.erase(_targets.begin() + count - 1);
            return;
        }
        count--;
    }
}

bool CudaKeySearchDevice::isTargetInList(const unsigned int hash[5])
{
    size_t count = _targets.size();

    while(count) {
        if(memcmp(hash, _targets[count - 1].h, 20) == 0) {
            return true;
        }
        count--;
    }

    return false;
}

uint32_t CudaKeySearchDevice::getPrivateKeyOffset(int thread, int block, int idx)
{
    // Total number of threads
    int totalThreads = _blocks * _threads;

    int base = idx * totalThreads;

    // Global ID of the current thread
    int threadId = block * _threads + thread;

    return base + threadId;
}

void CudaKeySearchDevice::outputTestAddresses(const std::vector<secp256k1::uint256> &exponents)
{
    // Only output first 2048 private keys or less if there are fewer
    uint64_t count = exponents.size() > 2048 ? 2048 : exponents.size();
    
    Logger::log(LogLevel::Info, "Outputting " + util::formatThousands(count) + " test addresses to test_add.txt");
    
    std::ofstream outFile("test_add.txt");
    if(!outFile.is_open()) {
        Logger::log(LogLevel::Error, "Failed to open test_add.txt for writing");
        return;
    }
    
    // Write header
    outFile << "PrivateKey,UncompressedAddress,CompressedAddress\n";
    
    // Generate base point G
    secp256k1::ecpoint g = secp256k1::G();
    
    for(uint64_t i = 0; i < count; i++) {
        // Generate public key from private key
        secp256k1::ecpoint pubKey = secp256k1::multiplyPoint(exponents[i], g);
        
        // Generate both compressed and uncompressed addresses
        std::string uncompressedAddress = Address::fromPublicKey(pubKey, false);
        std::string compressedAddress = Address::fromPublicKey(pubKey, true);
        
        // Write to file
        outFile << exponents[i].toString(16) << "," << uncompressedAddress << "," << compressedAddress << "\n";
    }
    
    outFile.close();
    Logger::log(LogLevel::Info, "Test addresses written to test_add.txt");
}

void CudaKeySearchDevice::getResultsInternal()
{
    int count = _resultList.size();
    int actualCount = 0;
    if(count == 0) {
        return;
    }

    unsigned char *ptr = new unsigned char[count * sizeof(CudaDeviceResult)];

    _resultList.read(ptr, count);
    
    // 创建一个数组来存储已找到的私钥索引，防止它们被重新生成
    int *foundKeyIndices = new int[count];
    int foundKeyCount = 0;

    for(int i = 0; i < count; i++) {
        struct CudaDeviceResult *rPtr = &((struct CudaDeviceResult *)ptr)[i];

        // might be false-positive
        if(!isTargetInList(rPtr->digest)) {
            continue;
        }
        actualCount++;

        KeySearchResult minerResult;

        // In random mode, we retrieve the actual private key from the device
        // Calculate the global key index based on block, thread, and point index
        int globalKeyIndex = rPtr->block * _threads * _pointsPerThread + rPtr->thread * _pointsPerThread + rPtr->idx;
        
        // 记录已找到的私钥索引
        foundKeyIndices[foundKeyCount++] = globalKeyIndex;
        
        // Get the private key from device memory
        unsigned int privateKeyWords[8];
        unsigned int *devicePrivateKeys = NULL;
        
        // Get the pointer to device private keys
        cudaCall(cudaMemcpyFromSymbol(&devicePrivateKeys, _PRIVATE_KEYS, sizeof(unsigned int *)));
        
        // Copy the private key from device to host
        cudaCall(cudaMemcpy(privateKeyWords, devicePrivateKeys + globalKeyIndex * 8, 8 * sizeof(unsigned int), cudaMemcpyDeviceToHost));
        
        // Convert to secp256k1::uint256
        secp256k1::uint256 privateKey = secp256k1::uint256(privateKeyWords, secp256k1::uint256::BigEndian);

        minerResult.privateKey = privateKey;
        minerResult.compressed = rPtr->compressed;

        memcpy(minerResult.hash, rPtr->digest, 20);

        minerResult.publicKey = secp256k1::ecpoint(secp256k1::uint256(rPtr->x, secp256k1::uint256::BigEndian), secp256k1::uint256(rPtr->y, secp256k1::uint256::BigEndian));

        removeTargetFromList(rPtr->digest);

        _results.push_back(minerResult);
    }
    
    // 如果找到了匹配的私钥，将它们的索引复制到设备内存并标记
    if(foundKeyCount > 0) {
        // 将已找到的私钥索引复制到设备内存，标记这些私钥不应被重新生成
        unsigned int *d_foundKeyIndices = NULL;
        cudaCall(cudaMalloc(&d_foundKeyIndices, foundKeyCount * sizeof(int)));
        cudaCall(cudaMemcpy(d_foundKeyIndices, foundKeyIndices, foundKeyCount * sizeof(int), cudaMemcpyHostToDevice));
        
        // 调用设备函数标记这些私钥
        callMarkFoundKeys(1, 1, d_foundKeyIndices, foundKeyCount);
        cudaCall(cudaDeviceSynchronize());
        
        // 释放设备内存
        cudaCall(cudaFree(d_foundKeyIndices));
    }
    
    delete[] foundKeyIndices;
    delete[] ptr;

    _resultList.clear();

    // Reload the bloom filters
    if(actualCount) {
        cudaCall(_targetLookup.setTargets(_targets));
    }
}

// Verify a private key produces the public key and hash
bool CudaKeySearchDevice::verifyKey(const secp256k1::uint256 &privateKey, const secp256k1::ecpoint &publicKey, const unsigned int hash[5], bool compressed)
{
    secp256k1::ecpoint g = secp256k1::G();

    secp256k1::ecpoint p = secp256k1::multiplyPoint(privateKey, g);

    if(!(p == publicKey)) {
        return false;
    }

    unsigned int xWords[8];
    unsigned int yWords[8];

    p.x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    p.y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

    unsigned int digest[5];
    if(compressed) {
        Hash::hashPublicKeyCompressed(xWords, yWords, digest);
    } else {
        Hash::hashPublicKey(xWords, yWords, digest);
    }

    for(int i = 0; i < 5; i++) {
        if(digest[i] != hash[i]) {
            return false;
        }
    }

    return true;
}

size_t CudaKeySearchDevice::getResults(std::vector<KeySearchResult> &resultsOut)
{
    for(int i = 0; i < _results.size(); i++) {
        resultsOut.push_back(_results[i]);
    }
    _results.clear();

    return resultsOut.size();
}

secp256k1::uint256 CudaKeySearchDevice::getNextKey()
{
    // In random mode, there is no "next key" in the sequential sense
    // Return the first random key as an example
    return _firstRandomKey;
}

bool CudaKeySearchDevice::supportsRandomGeneration()
{
    // CUDA设备支持随机生成
    return true;
}

secp256k1::uint256 CudaKeySearchDevice::generateRandomNumber(const secp256k1::uint256 &maxValue)
{
    // 注意：此方法已弃用，所有随机数生成现在都在GPU上进行
    // 此方法仅保留用于向后兼容，实际不会在CPU上生成随机数
    Logger::log(LogLevel::Warning, "Warning: generateRandomNumber called on CPU, but all random number generation should happen on GPU");
    
    // 返回0，因为实际随机数生成应该在GPU上进行
    return secp256k1::uint256(0);
}

void CudaKeySearchDevice::setRandomMode(bool randomMode)
{
    _randomMode = randomMode;
    if(_randomMode) {
        Logger::log(LogLevel::Info, "CUDA device random mode enabled");
    } else {
        Logger::log(LogLevel::Info, "CUDA device random mode disabled");
    }
}

void CudaKeySearchDevice::setRandomRange(const secp256k1::uint256 &start, const secp256k1::uint256 &end)
{
    _randomRangeStart = start;
    _randomRangeEnd = end;
    _randomRangeMode = true;
    Logger::log(LogLevel::Info, "CUDA device random range set to: " + start.toString(16) + " - " + end.toString(16));
}

// 使用GPU生成随机私钥
void CudaKeySearchDevice::generateRandomPrivateKeysGPU(std::vector<secp256k1::uint256> &exponents)
{
    uint64_t totalPoints = (uint64_t)_pointsPerThread * _threads * _blocks;
    uint64_t totalMemory = totalPoints * 40;
    
    Logger::log(LogLevel::Info, "GPU Random mode: generating " + util::formatThousands(totalPoints) + " random private keys (" + util::format("%.1f", (double)totalMemory / (double)(1024 * 1024)) + "MB)");
    
    // 检查是否设置了随机范围
    if(_randomRangeMode) {
        Logger::log(LogLevel::Info, "GPU Random range mode: generating keys in specified range");
        Logger::log(LogLevel::Info, "Range start: " + _randomRangeStart.toString(16));
        Logger::log(LogLevel::Info, "Range end: " + _randomRangeEnd.toString(16));
    }
    
    // 分配设备内存用于存储私钥
    unsigned int *devPrivateKeys = NULL;
    cudaError_t err = cudaMalloc(&devPrivateKeys, totalPoints * 8 * sizeof(unsigned int));
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to allocate device memory for private keys: " + std::string(cudaGetErrorString(err)));
        throw KeySearchException("Failed to allocate device memory for private keys: " + std::string(cudaGetErrorString(err)));
    }
    
    // 准备范围参数（如果使用范围模式）
    unsigned int *devRangeStart = NULL;
    unsigned int *devRangeEnd = NULL;
    
    if(_randomRangeMode) {
        // 分配设备内存用于存储范围参数
        err = cudaMalloc(&devRangeStart, 8 * sizeof(unsigned int));
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to allocate device memory for range start: " + std::string(cudaGetErrorString(err)));
            cudaFree(devPrivateKeys);
            throw KeySearchException("Failed to allocate device memory for range start: " + std::string(cudaGetErrorString(err)));
        }
        
        err = cudaMalloc(&devRangeEnd, 8 * sizeof(unsigned int));
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to allocate device memory for range end: " + std::string(cudaGetErrorString(err)));
            cudaFree(devPrivateKeys);
            cudaFree(devRangeStart);
            throw KeySearchException("Failed to allocate device memory for range end: " + std::string(cudaGetErrorString(err)));
        }
        
        // 将范围参数复制到设备内存
        err = cudaMemcpy(devRangeStart, _randomRangeStart.v, 8 * sizeof(unsigned int), cudaMemcpyHostToDevice);
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to copy range start to device: " + std::string(cudaGetErrorString(err)));
            cudaFree(devPrivateKeys);
            cudaFree(devRangeStart);
            cudaFree(devRangeEnd);
            throw KeySearchException("Failed to copy range start to device: " + std::string(cudaGetErrorString(err)));
        }
        
        err = cudaMemcpy(devRangeEnd, _randomRangeEnd.v, 8 * sizeof(unsigned int), cudaMemcpyHostToDevice);
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to copy range end to device: " + std::string(cudaGetErrorString(err)));
            cudaFree(devPrivateKeys);
            cudaFree(devRangeStart);
            cudaFree(devRangeEnd);
            throw KeySearchException("Failed to copy range end to device: " + std::string(cudaGetErrorString(err)));
        }
    }
    
    // 启动内核函数生成随机私钥
    if(_randomRangeMode) {
        // 随机范围模式：使用优化的内核函数
        callGenerateRandomPrivateKeysRange(_blocks, _threads,
            devPrivateKeys,      // 输出：生成的私钥
            _devRngStates,       // 输入/输出：随机数生成器状态
            totalPoints,         // 输入：需要生成的私钥总数
            devRangeStart,       // 输入：范围起始值
            devRangeEnd          // 输入：范围结束值
        );
    } else {
        // 普通随机模式：使用标准内核函数
        callGenerateRandomPrivateKeys(_blocks, _threads,
            devPrivateKeys,      // 输出：生成的私钥
            _devRngStates,       // 输入/输出：随机数生成器状态
            totalPoints          // 输入：需要生成的私钥总数
        );
    }
    
    // 检查内核执行是否成功
    err = cudaGetLastError();
    if(err != cudaSuccess) {
        // 释放设备内存
        if(devPrivateKeys) cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        
        std::string errStr = cudaGetErrorString(err);
        Logger::log(LogLevel::Error, "CUDA kernel launch failed: " + errStr);
        throw KeySearchException(errStr);
    }
    
    // 等待内核执行完成
    err = cudaDeviceSynchronize();
    if(err != cudaSuccess) {
        // 释放设备内存
        if(devPrivateKeys) cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        
        std::string errStr = cudaGetErrorString(err);
        Logger::log(LogLevel::Error, "CUDA kernel synchronization failed: " + errStr);
        throw KeySearchException(errStr);
    }
    
    // 分配主机内存用于存储生成的私钥
    unsigned int *hostPrivateKeys = NULL;
    try {
        hostPrivateKeys = new unsigned int[totalPoints * 8];
    } catch(std::bad_alloc&) {
        Logger::log(LogLevel::Error, "Failed to allocate host memory for private keys");
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to allocate host memory for private keys");
    }
    
    // 将生成的私钥从设备内存复制到主机内存
    err = cudaMemcpy(hostPrivateKeys, devPrivateKeys, totalPoints * 8 * sizeof(unsigned int), cudaMemcpyDeviceToHost);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to copy private keys from device to host: " + std::string(cudaGetErrorString(err)));
        delete[] hostPrivateKeys;
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to copy private keys from device to host: " + std::string(cudaGetErrorString(err)));
    }
    
    // 将私钥转换为secp256k1::uint256格式并添加到exponents向量中
    for(uint64_t i = 0; i < totalPoints; i++) {
        secp256k1::uint256 key;
        for(int j = 0; j < 8; j++) {
            key.v[j] = hostPrivateKeys[i * 8 + j];
        }
        
        // Save the first random key for example output
        if(i == 0) {
            _firstRandomKey = key;
        }
        
        exponents.push_back(key);
    }
    
    // 使用设备内存中的私钥直接初始化设备密钥
    err = _deviceKeys.initWithDeviceKeys(_blocks, _threads, _pointsPerThread, devPrivateKeys, totalPoints);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to initialize device keys: " + std::string(cudaGetErrorString(err)));
        delete[] hostPrivateKeys;
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to initialize device keys: " + std::string(cudaGetErrorString(err)));
    }
    
    // 设置设备变量，以便在设备端访问私钥数组和RNG状态
    err = cudaMemcpyToSymbol(&_PRIVATE_KEYS, &devPrivateKeys, sizeof(unsigned int *), 0, cudaMemcpyHostToDevice);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to copy private keys pointer to device symbol: " + std::string(cudaGetErrorString(err)));
        delete[] hostPrivateKeys;
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to copy private keys pointer to device symbol: " + std::string(cudaGetErrorString(err)));
    }
    
    err = cudaMemcpyToSymbol(&_RNG_STATES, &_devRngStates, sizeof(GpuRngState *), 0, cudaMemcpyHostToDevice);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to copy RNG states pointer to device symbol: " + std::string(cudaGetErrorString(err)));
        delete[] hostPrivateKeys;
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to copy RNG states pointer to device symbol: " + std::string(cudaGetErrorString(err)));
    }
    
    // 使用地址操作符获取设备符号的地址
    err = cudaMemcpyToSymbol(&_USE_RANGE, &_randomRangeMode, sizeof(bool), 0, cudaMemcpyHostToDevice);
    if(err != cudaSuccess) {
        Logger::log(LogLevel::Error, "Failed to copy use range flag to device symbol: " + std::string(cudaGetErrorString(err)));
        delete[] hostPrivateKeys;
        cudaFree(devPrivateKeys);
        if(devRangeStart) cudaFree(devRangeStart);
        if(devRangeEnd) cudaFree(devRangeEnd);
        throw KeySearchException("Failed to copy use range flag to device symbol: " + std::string(cudaGetErrorString(err)));
    }
    
    if(_randomRangeMode) {
        // 设置范围参数到设备常量内存
        unsigned int rangeStart[8];
        unsigned int rangeEnd[8];
        
        for(int i = 0; i < 8; i++) {
            rangeStart[i] = _randomRangeStart.v[i];
            rangeEnd[i] = _randomRangeEnd.v[i];
        }
        
        err = cudaMemcpyToSymbol(&_RANGE_START, rangeStart, sizeof(unsigned int) * 8, 0, cudaMemcpyHostToDevice);
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to copy range start to device symbol: " + std::string(cudaGetErrorString(err)));
            delete[] hostPrivateKeys;
            cudaFree(devPrivateKeys);
            if(devRangeStart) cudaFree(devRangeStart);
            if(devRangeEnd) cudaFree(devRangeEnd);
            throw KeySearchException("Failed to copy range start to device symbol: " + std::string(cudaGetErrorString(err)));
        }
        
        err = cudaMemcpyToSymbol(&_RANGE_END, rangeEnd, sizeof(unsigned int) * 8, 0, cudaMemcpyHostToDevice);
        if(err != cudaSuccess) {
            Logger::log(LogLevel::Error, "Failed to copy range end to device symbol: " + std::string(cudaGetErrorString(err)));
            delete[] hostPrivateKeys;
            cudaFree(devPrivateKeys);
            if(devRangeStart) cudaFree(devRangeStart);
            if(devRangeEnd) cudaFree(devRangeEnd);
            throw KeySearchException("Failed to copy range end to device symbol: " + std::string(cudaGetErrorString(err)));
        }
    }
    
    // 释放主机内存，但保留设备内存
    delete[] hostPrivateKeys;
    // 注意：不释放devPrivateKeys，因为它现在由_deviceKeys管理
    if(devRangeStart) cudaFree(devRangeStart);
    if(devRangeEnd) cudaFree(devRangeEnd);
    
    Logger::log(LogLevel::Info, "GPU random private key generation completed");
}

// CUDA内核包装函数实现
void callMarkFoundKeys(int blocks, int threads, unsigned int *d_foundKeyIndices, int foundKeyCount)
{
    void *args[] = { &d_foundKeyIndices, &foundKeyCount };
    cudaError_t err = cudaLaunchKernel((const void*)markFoundKeys, dim3(blocks), dim3(threads), args, 0, NULL);
    if(err != cudaSuccess) {
        throw KeySearchException(cudaGetErrorString(err));
    }
}

void callGenerateRandomPrivateKeys(int blocks, int threads, unsigned int *devPrivateKeys, GpuRngState *devRngStates, uint64_t totalPoints)
{
    void *args[] = { &devPrivateKeys, &devRngStates, &totalPoints };
    cudaError_t err = cudaLaunchKernel((const void*)generateRandomPrivateKeysKernel, dim3(blocks), dim3(threads), args, 0, NULL);
    if(err != cudaSuccess) {
        throw KeySearchException(cudaGetErrorString(err));
    }
}

void callGenerateRandomPrivateKeysRange(int blocks, int threads, unsigned int *devPrivateKeys, GpuRngState *devRngStates, uint64_t totalPoints, unsigned int *devRangeStart, unsigned int *devRangeEnd)
{
    void *args[] = { &devPrivateKeys, &devRngStates, &totalPoints, &devRangeStart, &devRangeEnd };
    cudaError_t err = cudaLaunchKernel((const void*)generateRandomPrivateKeysRangeKernel, dim3(blocks), dim3(threads), args, 0, NULL);
    if(err != cudaSuccess) {
        throw KeySearchException(cudaGetErrorString(err));
    }
}