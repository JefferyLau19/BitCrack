#include <cuda.h>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include "KeySearchTypes.h"
#include "CudaKeySearchDevice.h"
#include "ptx.cuh"
#include "secp256k1.cuh"

#include "sha256.cuh"
#include "ripemd160.cuh"

// GPU random number generator state structure
struct GpuRngState {
    unsigned int state[16];
    unsigned int counter;
};

#include "secp256k1.h"

#include "CudaHashLookup.cuh"
#include "CudaAtomicList.cuh"
#include "CudaDeviceKeys.cuh"

// 添加缺失的常量定义
__constant__ unsigned int _SECP256K1_N[8] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
    0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141
};

// 设备端SHA-256初始化函数
__device__ void gpuSha256Init(unsigned int *digest)
{
    for(int i = 0; i < 8; i++) {
        digest[i] = _IV[i];
    }
}

// 设备端SHA-256处理函数
__device__ void gpuSha256ProcessBlock(unsigned int *msg, unsigned int *digest)
{
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int w[64];
    
    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];
    f = digest[5];
    g = digest[6];
    h = digest[7];
    
    // 复制消息到工作数组
    for(int i = 0; i < 16; i++) {
        w[i] = msg[i];
    }
    
    // 扩展消息
    for(int i = 16; i < 64; i++) {
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    }
    
    // 主循环
    for(int i = 0; i < 64; i++) {
        unsigned int temp1 = h + CH(e, f, g) + ((rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25))) + _K[i] + w[i];
        unsigned int temp2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22))) + MAJ(a, b, c);
        
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // 更新摘要
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
    digest[5] += f;
    digest[6] += g;
    digest[7] += h;
}

// 设备端随机数生成函数
__device__ void gpuGenerateRandomBytes(GpuRngState *state, unsigned char *buf, int len)
{
    int index = 0;
    while(len > 0) {
        if(state->counter++ == 0xffffffff) {
            // 重新播种：使用当前状态生成新的种子
            unsigned int seedDigest[8];
            gpuSha256Init(seedDigest);
            gpuSha256ProcessBlock(state->state, seedDigest);
            
            // 更新状态
            for(int j = 0; j < 16; j++) {
                state->state[j] = seedDigest[j % 8];
            }
            state->counter = 0;
        }
        
        state->state[15] = state->counter;
        
        unsigned int digest[8];
        gpuSha256Init(digest);
        gpuSha256ProcessBlock(state->state, digest);
        
        if(len >= 32) {
            memcpy(&buf[index], digest, 32);
            index += 32;
            len -= 32;
        } else {
            memcpy(&buf[index], digest, len);
            index += len;
            len = 0;
        }
    }
}

// 比较两个256位整数，返回1表示a >= b，0表示a < b
__device__ int gpuCmp256(const unsigned int *a, const unsigned int *b)
{
    for(int i = 7; i >= 0; i--) {
        if(a[i] > b[i]) return 1;
        if(a[i] < b[i]) return 0;
    }
    return 1; // 相等
}

// 检查是否为零
__device__ int gpuIsZero256(const unsigned int *a)
{
    for(int i = 0; i < 8; i++) {
        if(a[i] != 0) return 0;
    }
    return 1;
}

// 256位加法
__device__ void gpuAdd256(const unsigned int *a, const unsigned int *b, unsigned int *result)
{
    unsigned long long carry = 0;
    
    for(int i = 0; i < 8; i++) {
        unsigned long long sum = (unsigned long long)a[i] + (unsigned long long)b[i] + carry;
        result[i] = (unsigned int)sum;
        carry = sum >> 32;
    }
}

// 256位减法，result = a - b
__device__ void gpuSub256(const unsigned int *a, const unsigned int *b, unsigned int *result)
{
    unsigned long long borrow = 0;
    
    for(int i = 0; i < 8; i++) {
        unsigned long long diff = (unsigned long long)a[i] - (unsigned long long)b[i] - borrow;
        result[i] = (unsigned int)diff;
        borrow = (diff >> 32) & 1;
    }
}

// 重新生成单个随机私钥的设备函数 - 普通随机模式
__device__ void regenerateSinglePrivateKeyDevice(
    unsigned int *privateKeys,  // 输入/输出：私钥数组
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    int keyIndex               // 输入：需要重新生成的私钥索引
) {
    // 每个私钥在输出数组中的位置
    unsigned int *keyPtr = privateKeys + keyIndex * 8;
    
    // 生成随机字节
    unsigned char randomBytes[32];
    gpuGenerateRandomBytes(&rngStates[0], randomBytes, 32);
    
    // 转换为256位整数
    for(int j = 0; j < 8; j++) {
        keyPtr[j] = (randomBytes[j*4] << 24) | 
                   (randomBytes[j*4+1] << 16) | 
                   (randomBytes[j*4+2] << 8) | 
                   (randomBytes[j*4+3]);
    }
    
    // 确保私钥在有效范围内 [1, N-1]
    while(gpuCmp256(keyPtr, _SECP256K1_N) == 1 || gpuIsZero256(keyPtr)) {
        // 如果超出范围，重新生成
        gpuGenerateRandomBytes(&rngStates[0], randomBytes, 32);
        
        for(int j = 0; j < 8; j++) {
            keyPtr[j] = (randomBytes[j*4] << 24) | 
                       (randomBytes[j*4+1] << 16) | 
                       (randomBytes[j*4+2] << 8) | 
                       (randomBytes[j*4+3]);
        }
    }
}

// 重新生成单个随机私钥的内核函数 - 普通随机模式
__global__ void regenerateSinglePrivateKeyKernel(
    unsigned int *privateKeys,  // 输入/输出：私钥数组
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    int keyIndex               // 输入：需要重新生成的私钥索引
) {
    // 计算全局线程ID
    int globalId = blockIdx.x * blockDim.x + threadIdx.x;
    
    // 只有索引为0的线程执行私钥重新生成
    if(globalId == 0) {
        regenerateSinglePrivateKeyDevice(privateKeys, rngStates, keyIndex);
    }
}

// 重新生成单个随机私钥的设备函数 - 随机范围模式（优化版本）
__device__ void regenerateSinglePrivateKeyRangeDevice(
    unsigned int *privateKeys,  // 输入/输出：私钥数组
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    int keyIndex,              // 输入：需要重新生成的私钥索引
    const unsigned int *rangeStart, // 输入：范围起始值
    const unsigned int *rangeEnd    // 输入：范围结束值
) {
    // 每个私钥在输出数组中的位置
    unsigned int *keyPtr = privateKeys + keyIndex * 8;
    
    // 计算范围大小：rangeSize = rangeEnd - rangeStart
    unsigned int rangeSize[8];
    gpuSub256(rangeEnd, rangeStart, rangeSize);
    
    // 计算rangeSize的位数，确定需要生成的随机数位数
    int bits = 0;
    for(int j = 7; j >= 0; j--) {
        if(rangeSize[j] != 0) {
            // 找到最高非零字
            uint32_t word = rangeSize[j];
            while(word) {
                word >>= 1;
                bits++;
            }
            bits += j * 32;
            break;
        }
    }
    
    // 如果rangeSize为0，直接使用rangeStart作为结果
    if(bits == 0) {
        for(int j = 0; j < 8; j++) {
            keyPtr[j] = rangeStart[j];
        }
        return;
    }
    
    int bytesNeeded = (bits + 7) / 8; // 向上取整
    
    // 生成不超过rangeSize的随机数
    unsigned int randomOffset[8] = {0};
    
    do {
        unsigned char randomBytes[32];
        gpuGenerateRandomBytes(&rngStates[0], randomBytes, 32);
        
        // 只使用需要的字节，其余置零
        for(int j = 0; j < 8; j++) {
            randomOffset[j] = 0;
        }
        
        for(int j = 0; j < bytesNeeded && j < 32; j++) {
            int wordIndex = j / 4;
            int byteIndex = j % 4;
            randomOffset[wordIndex] |= (randomBytes[j] << (byteIndex * 8));
        }
        
        // 确保随机数不超过rangeSize
        // 使用位掩码而不是循环减法，提高效率
        if (bits < 256) {
            uint32_t mask = (1 << (bits % 32)) - 1;
            if (bits % 32 != 0) {
                randomOffset[bytesNeeded / 4] &= mask;
            }
        }
        
    } while(gpuCmp256(randomOffset, rangeSize) >= 0);
    
    // 最终私钥 = rangeStart + 随机数
    gpuAdd256(rangeStart, randomOffset, keyPtr);
}

// 重新生成单个随机私钥的内核函数 - 随机范围模式（优化版本）
__global__ void regenerateSinglePrivateKeyRangeKernel(
    unsigned int *privateKeys,  // 输入/输出：私钥数组
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    int keyIndex,              // 输入：需要重新生成的私钥索引
    const unsigned int *rangeStart, // 输入：范围起始值
    const unsigned int *rangeEnd    // 输入：范围结束值
) {
    // 计算全局线程ID
    int globalId = blockIdx.x * blockDim.x + threadIdx.x;
    
    // 只有索引为0的线程执行私钥重新生成
    if(globalId == 0) {
        regenerateSinglePrivateKeyRangeDevice(privateKeys, rngStates, keyIndex, rangeStart, rangeEnd);
    }
}

// 生成随机私钥的内核函数 - 普通随机模式
__global__ void generateRandomPrivateKeysKernel(
    unsigned int *privateKeys,  // 输出：生成的私钥
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    unsigned int totalPoints     // 输入：需要生成的私钥总数
) {
    // 计算全局线程ID
    int globalId = blockIdx.x * blockDim.x + threadIdx.x;
    
    // 每个线程处理多个点
    for(int i = 0; i < totalPoints; i += gridDim.x * blockDim.x) {
        int pointIndex = globalId + i;
        
        if(pointIndex >= totalPoints) {
            break;
        }
        
        // 每个私钥在输出数组中的位置
        unsigned int *keyPtr = privateKeys + pointIndex * 8;
        
        // 生成随机字节
        unsigned char randomBytes[32];
        gpuGenerateRandomBytes(&rngStates[globalId], randomBytes, 32);
        
        // 转换为256位整数
        for(int j = 0; j < 8; j++) {
            keyPtr[j] = (randomBytes[j*4] << 24) | 
                       (randomBytes[j*4+1] << 16) | 
                       (randomBytes[j*4+2] << 8) | 
                       (randomBytes[j*4+3]);
        }
        
        // 确保私钥在有效范围内 [1, N-1]
        while(gpuCmp256(keyPtr, _SECP256K1_N) == 1 || gpuIsZero256(keyPtr)) {
            // 如果超出范围，重新生成
            gpuGenerateRandomBytes(&rngStates[globalId], randomBytes, 32);
            
            for(int j = 0; j < 8; j++) {
                keyPtr[j] = (randomBytes[j*4] << 24) | 
                           (randomBytes[j*4+1] << 16) | 
                           (randomBytes[j*4+2] << 8) | 
                           (randomBytes[j*4+3]);
            }
        }
    }
}

// 生成随机私钥的内核函数 - 随机范围模式（优化版本）
__global__ void generateRandomPrivateKeysRangeKernel(
    unsigned int *privateKeys,  // 输出：生成的私钥
    GpuRngState *rngStates,     // 输入/输出：随机数生成器状态
    unsigned int totalPoints,    // 输入：需要生成的私钥总数
    const unsigned int *rangeStart, // 输入：范围起始值
    const unsigned int *rangeEnd    // 输入：范围结束值
) {
    // 计算全局线程ID
    int globalId = blockIdx.x * blockDim.x + threadIdx.x;
    
    // 计算范围大小：rangeSize = rangeEnd - rangeStart
    unsigned int rangeSize[8];
    gpuSub256(rangeEnd, rangeStart, rangeSize);
    
    // 每个线程处理多个点
    for(int i = 0; i < totalPoints; i += gridDim.x * blockDim.x) {
        int pointIndex = globalId + i;
        
        if(pointIndex >= totalPoints) {
            break;
        }
        
        // 每个私钥在输出数组中的位置
        unsigned int *keyPtr = privateKeys + pointIndex * 8;
        
        // 计算rangeSize的位数，确定需要生成的随机数位数
        int bits = 0;
        for(int j = 7; j >= 0; j--) {
            if(rangeSize[j] != 0) {
                // 找到最高非零字
                uint32_t word = rangeSize[j];
                while(word) {
                    word >>= 1;
                    bits++;
                }
                bits += j * 32;
                break;
            }
        }
        
        // 如果rangeSize为0，直接使用rangeStart作为结果
        if(bits == 0) {
            for(int j = 0; j < 8; j++) {
                keyPtr[j] = rangeStart[j];
            }
            continue;
        }
        
        int bytesNeeded = (bits + 7) / 8; // 向上取整
        
        // 生成不超过rangeSize的随机数
        unsigned int randomOffset[8] = {0};
        
        do {
            unsigned char randomBytes[32];
            gpuGenerateRandomBytes(&rngStates[globalId], randomBytes, 32);
            
            // 只使用需要的字节，其余置零
            for(int j = 0; j < 8; j++) {
                randomOffset[j] = 0;
            }
            
            for(int j = 0; j < bytesNeeded && j < 32; j++) {
                int wordIndex = j / 4;
                int byteIndex = j % 4;
                randomOffset[wordIndex] |= (randomBytes[j] << (byteIndex * 8));
            }
            
            // 确保随机数不超过rangeSize
            // 使用位掩码而不是循环减法，提高效率
            if (bits < 256) {
                uint32_t mask = (1 << (bits % 32)) - 1;
                if (bits % 32 != 0) {
                    randomOffset[bytesNeeded / 4] &= mask;
                }
            }
            
        } while(gpuCmp256(randomOffset, rangeSize) >= 0);
        
        // 最终私钥 = rangeStart + 随机数
        gpuAdd256(rangeStart, randomOffset, keyPtr);
    }
}

// 初始化GPU随机数生成器状态
__host__ cudaError_t initializeGpuRngStates(GpuRngState **states, unsigned int count)
{
    cudaError_t err;
    
    // 检查输入参数
    if(states == NULL) {
        return cudaErrorInvalidValue;
    }
    
    if(count == 0) {
        return cudaErrorInvalidValue;
    }
    
    // 分配设备内存
    err = cudaMalloc(states, count * sizeof(GpuRngState));
    if(err != cudaSuccess) {
        return err;
    }
    
    // 在主机上创建临时状态
    GpuRngState *hostStates = NULL;
    try {
        hostStates = new GpuRngState[count];
    } catch(std::bad_alloc&) {
        cudaFree(*states);
        *states = NULL;
        return cudaErrorMemoryAllocation;
    }
    
    // 初始化每个状态
    for(unsigned int i = 0; i < count; i++) {
        // 使用系统随机数生成器初始化状态
        for(int j = 0; j < 16; j++) {
            hostStates[i].state[j] = rand();
        }
        hostStates[i].counter = 0;
    }
    
    // 复制到设备
    err = cudaMemcpy(*states, hostStates, count * sizeof(GpuRngState), cudaMemcpyHostToDevice);
    
    // 释放主机内存
    delete[] hostStates;
    
    // 如果复制失败，释放设备内存
    if(err != cudaSuccess) {
        cudaFree(*states);
        *states = NULL;
    }
    
    return err;
}

// 释放GPU随机数生成器状态
__host__ void freeGpuRngStates(GpuRngState *states)
{
    if(states != NULL) {
        cudaFree(states);
    }
}

__constant__ unsigned int _INC_X[8];

__constant__ unsigned int _INC_Y[8];

__constant__ unsigned int *_CHAIN[1];

// 设备变量，用于私钥重新生成
__constant__ unsigned int *_PRIVATE_KEYS[1];
__constant__ GpuRngState *_RNG_STATES[1];
__constant__ bool _USE_RANGE;
__constant__ unsigned int _RANGE_START[8];
__constant__ unsigned int _RANGE_END[8];

static unsigned int *_chainBufferPtr = NULL;

// 最大可存储的已找到私钥数量
#define MAX_FOUND_KEYS 1000

// 设备变量，用于存储已找到的私钥索引数量
__device__ int d_foundKeyCount = 0;

// 设备变量，用于存储已找到的私钥索引
__device__ int d_foundKeyIndices[MAX_FOUND_KEYS];

// 检查指定索引的私钥是否已被标记为已找到
__device__ bool isKeyFound(int keyIndex)
{
    for(int i = 0; i < d_foundKeyCount; i++) {
        if(d_foundKeyIndices[i] == keyIndex) {
            return true;
        }
    }
    return false;
}


__device__ void doRMD160FinalRound(const unsigned int hIn[5], unsigned int hOut[5])
{
    const unsigned int iv[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0
    };

    for(int i = 0; i < 5; i++) {
        hOut[i] = endian(hIn[i] + iv[(i + 1) % 5]);
    }
}


/**
 * Allocates device memory for storing the multiplication chain used in
 the batch inversion operation
 */
cudaError_t allocateChainBuf(unsigned int count)
{
    // 检查输入参数
    if(count == 0) {
        return cudaErrorInvalidValue;
    }
    
    // 确保之前的缓冲区已释放
    if(_chainBufferPtr != NULL) {
        cudaFree(_chainBufferPtr);
        _chainBufferPtr = NULL;
    }
    
    cudaError_t err = cudaMalloc(&_chainBufferPtr, count * sizeof(unsigned int) * 8);
    if(err != cudaSuccess) {
        _chainBufferPtr = NULL;
        return err;
    }

    err = cudaMemcpyToSymbol(_CHAIN, &_chainBufferPtr, sizeof(unsigned int *));
    if(err) {
        cudaFree(_chainBufferPtr);
        _chainBufferPtr = NULL;
    }

    return err;
}

void cleanupChainBuf()
{
    if(_chainBufferPtr != NULL) {
        cudaFree(_chainBufferPtr);
        _chainBufferPtr = NULL;
    }
}

/**
 *Sets the EC point which all points will be incremented by
 */
cudaError_t setIncrementorPoint(const secp256k1::uint256 &x, const secp256k1::uint256 &y)
{
    unsigned int xWords[8];
    unsigned int yWords[8];

    x.exportWords(xWords, 8, secp256k1::uint256::BigEndian);
    y.exportWords(yWords, 8, secp256k1::uint256::BigEndian);

    cudaError_t err = cudaMemcpyToSymbol(_INC_X, xWords, sizeof(unsigned int) * 8);
    if(err) {
        return err;
    }

    return cudaMemcpyToSymbol(_INC_Y, yWords, sizeof(unsigned int) * 8);
}



__device__ void hashPublicKey(const unsigned int *x, const unsigned int *y, unsigned int *digestOut)
{
    unsigned int hash[8];

    sha256PublicKey(x, y, hash);

    // Swap to little-endian
    for(int i = 0; i < 8; i++) {
        hash[i] = endian(hash[i]);
    }

    ripemd160sha256NoFinal(hash, digestOut);
}

__device__ void hashPublicKeyCompressed(const unsigned int *x, unsigned int yParity, unsigned int *digestOut)
{
    unsigned int hash[8];

    sha256PublicKeyCompressed(x, yParity, hash);

    // Swap to little-endian
    for(int i = 0; i < 8; i++) {
        hash[i] = endian(hash[i]);
    }

    ripemd160sha256NoFinal(hash, digestOut);
}


__device__ void setResultFound(int idx, bool compressed, unsigned int x[8], unsigned int y[8], unsigned int digest[5])
{
    CudaDeviceResult r;

    r.block = blockIdx.x;
    r.thread = threadIdx.x;
    r.idx = idx;
    r.compressed = compressed;

    for(int i = 0; i < 8; i++) {
        r.x[i] = x[i];
        r.y[i] = y[i];
    }

    doRMD160FinalRound(digest, r.digest);

    atomicListAdd(&r, sizeof(r));
}

__device__ void doIteration(int pointsPerThread, int compression)
{
    unsigned int *chain = _CHAIN[0];
    unsigned int *xPtr = ec::getXPtr();
    unsigned int *yPtr = ec::getYPtr();
    
    // 获取私钥数组和RNG状态
    unsigned int *privateKeys = _PRIVATE_KEYS[0];
    GpuRngState *rngStates = _RNG_STATES[0];
    bool useRange = _USE_RANGE;
    
    // Multiply together all (_Gx - x) and then invert
    unsigned int inverse[8] = {0,0,0,0,0,0,0,1};
    for(int i = 0; i < pointsPerThread; i++) {
        unsigned int x[8];
        
        unsigned int digest[5];
        
        readInt(xPtr, i, x);
        
        bool matchFound = false;
        
        if(compression == PointCompressionType::UNCOMPRESSED || compression == PointCompressionType::BOTH) {
            unsigned int y[8];
            readInt(yPtr, i, y);
            
            hashPublicKey(x, y, digest);
            
            if(checkHash(digest)) {
                setResultFound(i, false, x, y, digest);
                matchFound = true;
            }
        }
        
        if(compression == PointCompressionType::COMPRESSED || compression == PointCompressionType::BOTH) {
            hashPublicKeyCompressed(x, readIntLSW(yPtr, i), digest);
            
            if(checkHash(digest)) {
                unsigned int y[8];
                readInt(yPtr, i, y);
                setResultFound(i, true, x, y, digest);
                matchFound = true;
            }
        }
        
        // 如果没有找到匹配，重新生成私钥
        if(!matchFound) {
            // 计算全局私钥索引
            int globalKeyIndex = blockIdx.x * blockDim.x * pointsPerThread + threadIdx.x * pointsPerThread + i;
            
            // 检查该私钥是否已被标记为已找到（即与目标地址匹配）
            // 如果已被标记，则跳过重新生成，以避免覆盖已匹配的私钥
            if(!isKeyFound(globalKeyIndex)) {
                // 根据模式调用相应的设备函数重新生成私钥
                if(useRange) {
                    // 随机范围模式：直接调用设备函数
                    regenerateSinglePrivateKeyRangeDevice(
                        privateKeys,
                        rngStates,
                        globalKeyIndex,
                        _RANGE_START,
                        _RANGE_END
                    );
                } else {
                    // 普通随机模式：直接调用设备函数
                    regenerateSinglePrivateKeyDevice(
                        privateKeys,
                        rngStates,
                        globalKeyIndex
                    );
                }
            }
        }
        
        beginBatchAdd(_INC_X, x, chain, i, i, inverse);
    }
    
    doBatchInverse(inverse);
    
    for(int i = pointsPerThread - 1; i >= 0; i--) {
        
        unsigned int newX[8];
        unsigned int newY[8];
        
        completeBatchAdd(_INC_X, _INC_Y, xPtr, yPtr, i, i, chain, inverse, newX, newY);
        
        writeInt(xPtr, i, newX);
        writeInt(yPtr, i, newY);
    }
}

__device__ void doIterationWithDouble(int pointsPerThread, int compression)
{
    unsigned int *chain = _CHAIN[0];
    unsigned int *xPtr = ec::getXPtr();
    unsigned int *yPtr = ec::getYPtr();
    
    // 获取私钥数组和RNG状态
    unsigned int *privateKeys = _PRIVATE_KEYS[0];
    GpuRngState *rngStates = _RNG_STATES[0];
    bool useRange = _USE_RANGE;
    
    // Multiply together all (_Gx - x) and then invert
    unsigned int inverse[8] = {0,0,0,0,0,0,0,1};
    for(int i = 0; i < pointsPerThread; i++) {
        unsigned int x[8];
        
        unsigned int digest[5];
        
        readInt(xPtr, i, x);
        
        bool matchFound = false;
        
        // uncompressed
        if(compression == PointCompressionType::UNCOMPRESSED || compression == PointCompressionType::BOTH) {
            unsigned int y[8];
            readInt(yPtr, i, y);
            hashPublicKey(x, y, digest);
            
            if(checkHash(digest)) {
                setResultFound(i, false, x, y, digest);
                matchFound = true;
            }
        }
        
        // compressed
        if(compression == PointCompressionType::COMPRESSED || compression == PointCompressionType::BOTH) {
            
            hashPublicKeyCompressed(x, readIntLSW(yPtr, i), digest);
            
            if(checkHash(digest)) {
                
                unsigned int y[8];
                readInt(yPtr, i, y);
                
                setResultFound(i, true, x, y, digest);
                matchFound = true;
            }
        }
        
        // 如果没有找到匹配，重新生成私钥
        if(!matchFound) {
            // 计算全局私钥索引
            int globalKeyIndex = blockIdx.x * blockDim.x * pointsPerThread + threadIdx.x * pointsPerThread + i;
            
            // 检查该私钥是否已被标记为已找到（即与目标地址匹配）
            // 如果已被标记，则跳过重新生成，以避免覆盖已匹配的私钥
            if(!isKeyFound(globalKeyIndex)) {
                // 根据模式调用相应的设备函数重新生成私钥
                if(useRange) {
                    // 随机范围模式：直接调用设备函数
                    regenerateSinglePrivateKeyRangeDevice(
                        privateKeys,
                        rngStates,
                        globalKeyIndex,
                        _RANGE_START,
                        _RANGE_END
                    );
                } else {
                    // 普通随机模式：直接调用设备函数
                    regenerateSinglePrivateKeyDevice(
                        privateKeys,
                        rngStates,
                        globalKeyIndex
                    );
                }
            }
        }
        
        beginBatchAddWithDouble(_INC_X, _INC_Y, xPtr, chain, i, i, inverse);
    }
    
    doBatchInverse(inverse);
    
    for(int i = pointsPerThread - 1; i >= 0; i--) {
        
        unsigned int newX[8];
        unsigned int newY[8];
        
        completeBatchAddWithDouble(_INC_X, _INC_Y, xPtr, yPtr, i, i, chain, inverse, newX, newY);
        
        writeInt(xPtr, i, newX);
        writeInt(yPtr, i, newY);
    }
}

/**
* Performs a single iteration
*/
__global__ void keyFinderKernel(int points, int compression)
{
    doIteration(points, compression);
}

__global__ void keyFinderKernelWithDouble(int points, int compression)
{
    doIterationWithDouble(points, compression);
}

// 标记已找到的私钥索引
__global__ void markFoundKeys(unsigned int *foundKeyIndices, int count)
{
    // 只有索引为0的线程执行标记操作
    if(threadIdx.x == 0 && blockIdx.x == 0) {
        // 确保不超过最大容量
        int keysToMark = (count > MAX_FOUND_KEYS) ? MAX_FOUND_KEYS : count;
        
        // 复制已找到的私钥索引到设备内存
        for(int i = 0; i < keysToMark; i++) {
            d_foundKeyIndices[i] = foundKeyIndices[i];
        }
        
        // 更新已找到的私钥数量
        d_foundKeyCount = keysToMark;
    }
}