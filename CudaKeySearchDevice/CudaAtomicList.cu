#include "CudaAtomicList.h"
#include "CudaAtomicList.cuh"

#include <stdio.h>

#include <cuda.h>
#include <cuda_runtime.h>

static __constant__ void *_LIST_BUF[1];
static __constant__ unsigned int *_LIST_SIZE[1];


__device__ void atomicListAdd(void *info, unsigned int size)
{
	unsigned int count = atomicAdd(_LIST_SIZE[0], 1);

	unsigned char *ptr = (unsigned char *)(_LIST_BUF[0]) + count * size;

	memcpy(ptr, info, size);
}

static cudaError_t setListPtr(void *ptr, unsigned int *numResults)
{
	cudaError_t err = cudaMemcpyToSymbol(_LIST_BUF, &ptr, sizeof(void *));

	if(err) {
		return err;
	}

	err = cudaMemcpyToSymbol(_LIST_SIZE, &numResults, sizeof(unsigned int *));

	return err;
}


cudaError_t CudaAtomicList::init(unsigned int itemSize, unsigned int maxItems)
{
	// 检查输入参数
	if(itemSize <= 0 || maxItems <= 0) {
		return cudaErrorInvalidValue;
	}
	
	// 检查是否已经初始化
	if(_countHostPtr != NULL || _hostPtr != NULL) {
		return cudaErrorInitializationError;
	}
	
	_itemSize = itemSize;

	// The number of results found in the most recent kernel run
	_countHostPtr = NULL;
	cudaError_t err = cudaHostAlloc(&_countHostPtr, sizeof(unsigned int), cudaHostAllocMapped);
	if(err != cudaSuccess) {
		_countHostPtr = NULL;
		goto end;
	}

	// Number of items in the list
	_countDevPtr = NULL;
	err = cudaHostGetDevicePointer(&_countDevPtr, _countHostPtr, 0);
	if(err != cudaSuccess) {
		cudaFreeHost(_countHostPtr);
		_countHostPtr = NULL;
		_countDevPtr = NULL;
		goto end;
	}
	*_countHostPtr = 0;

	// Storage for results data
	_hostPtr = NULL;
	err = cudaHostAlloc(&_hostPtr, itemSize * maxItems, cudaHostAllocMapped);
	if(err != cudaSuccess) {
		cudaFreeHost(_countHostPtr);
		_countHostPtr = NULL;
		_countDevPtr = NULL;
		_hostPtr = NULL;
		goto end;
	}

	// Storage for results data (device to host pointer)
	_devPtr = NULL;
	err = cudaHostGetDevicePointer(&_devPtr, _hostPtr, 0);

	if(err != cudaSuccess) {
		cudaFreeHost(_countHostPtr);
		cudaFreeHost(_hostPtr);
		_countHostPtr = NULL;
		_countDevPtr = NULL;
		_hostPtr = NULL;
		_devPtr = NULL;
		goto end;
	}

	err = setListPtr(_devPtr, _countDevPtr);

end:
	if(err != cudaSuccess) {
		if(_countHostPtr) cudaFreeHost(_countHostPtr);
		if(_countDevPtr) cudaFree(_countDevPtr);
		if(_hostPtr) cudaFreeHost(_hostPtr);
		if(_devPtr) cudaFree(_devPtr);
		
		// 确保所有指针都设为NULL
		_countHostPtr = NULL;
		_countDevPtr = NULL;
		_hostPtr = NULL;
		_devPtr = NULL;
	}

	return err;
}

unsigned int CudaAtomicList::size()
{
	return *_countHostPtr;
}

void CudaAtomicList::clear()
{
	*_countHostPtr = 0;
}

unsigned int CudaAtomicList::read(void *ptr, unsigned int count)
{
	if(count >= *_countHostPtr) {
		count = *_countHostPtr;
	}

	memcpy(ptr, _hostPtr, count * _itemSize);

	return count;
}

void CudaAtomicList::cleanup()
{
	cudaFreeHost(_countHostPtr);

	cudaFree(_countDevPtr);

	cudaFreeHost(_hostPtr);

	cudaFree(_devPtr);
}