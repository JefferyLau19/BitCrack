#ifndef _CUDA_KEY_SEARCH_DEVICE
#define _CUDA_KEY_SEARCH_DEVICE

#include "KeySearchDevice.h"
#include <vector>
#include <cuda_runtime.h>
#include "secp256k1.h"
#include "CudaDeviceKeys.h"
#include "CudaHashLookup.h"
#include "CudaAtomicList.h"
#include "cudaUtil.h"

// GPU随机数生成器状态结构体前向声明
struct GpuRngState;

// Structures that exist on both host and device side
struct CudaDeviceResult {
    int thread;
    int block;
    int idx;
    bool compressed;
    unsigned int x[8];
    unsigned int y[8];
    unsigned int digest[5];
};

class CudaKeySearchDevice : public KeySearchDevice {

private:

    int _device;

    int _blocks;

    int _threads;

    int _pointsPerThread;

    int _compression;

    std::vector<KeySearchResult> _results;

    std::string _deviceName;

    uint64_t _iterations;

    void cudaCall(cudaError_t err);

    void generateStartingPoints();

    void outputTestAddresses(const std::vector<secp256k1::uint256> &exponents);

    CudaDeviceKeys _deviceKeys;

    CudaAtomicList _resultList;

    CudaHashLookup _targetLookup;
    
    // GPU随机数生成器状态
    GpuRngState *_devRngStates;
    
    void getResultsInternal();

    std::vector<hash160> _targets;

    bool isTargetInList(const unsigned int hash[5]);
    
    void removeTargetFromList(const unsigned int hash[5]);

    uint32_t getPrivateKeyOffset(int thread, int block, int point);

    bool _randomMode;
    
    // Random range mode variables
    bool _randomRangeMode;
    secp256k1::uint256 _randomRangeStart;
    secp256k1::uint256 _randomRangeEnd;

    bool verifyKey(const secp256k1::uint256 &privateKey, const secp256k1::ecpoint &publicKey, const unsigned int hash[5], bool compressed);

public:

    CudaKeySearchDevice(int device, int threads, int pointsPerThread, int blocks = 0);
    
    // 析构函数
    virtual ~CudaKeySearchDevice();

    virtual void init(int compression);

    virtual void doStep();

    virtual void setTargets(const std::set<KeySearchTarget> &targets);

    virtual size_t getResults(std::vector<KeySearchResult> &results);

    virtual uint64_t keysPerStep();

    virtual std::string getDeviceName();

    virtual void getMemoryInfo(uint64_t &freeMem, uint64_t &totalMem);

    virtual secp256k1::uint256 getNextKey();

    virtual void setRandomMode(bool randomMode);
    
    // Set random range for random range mode
    virtual void setRandomRange(const secp256k1::uint256 &start, const secp256k1::uint256 &end);
    
    // Get the first randomly generated private key (for random mode example)
    secp256k1::uint256 getFirstRandomKey() const { return _firstRandomKey; }
    
    // Check if device supports random generation
    virtual bool supportsRandomGeneration();
    
    // Generate a random number
    virtual secp256k1::uint256 generateRandomNumber(const secp256k1::uint256 &maxValue);
    
    // 使用GPU生成随机私钥
    void generateRandomPrivateKeysGPU(std::vector<secp256k1::uint256> &exponents);
    
private:
    secp256k1::uint256 _firstRandomKey;};

// 设备函数声明
__global__ void markFoundKeys(unsigned int *foundKeyIndices, int count);
__device__ bool isKeyFound(int keyIndex);

// GPU随机数生成器状态管理函数声明
__host__ cudaError_t initializeGpuRngStates(GpuRngState **states, unsigned int count);
__host__ void freeGpuRngStates(GpuRngState *states);

// 随机私钥生成内核函数声明
__global__ void generateRandomPrivateKeysKernel(unsigned int *privateKeys, GpuRngState *rngStates, unsigned int totalPoints);
__global__ void generateRandomPrivateKeysRangeKernel(unsigned int *privateKeys, GpuRngState *rngStates, unsigned int totalPoints, const unsigned int *rangeStart, const unsigned int *rangeEnd);
#endif