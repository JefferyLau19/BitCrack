@echo off
cd /d "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"
call vcvarsall.bat x64
cd /d d:\DoNotDelete\BitRangeOnlycuda\CudaKeySearchDevice
nvcc -gencode=arch=compute_35,code=sm_35 -I../cudaMath -I../secp256k1lib -I../KeyFinderLib -I../Logger -I../Util -I../cudaUtil -I../AddressUtil -I"C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v10.1/include" -c gpu_rng.cu -o gpu_rng.o
pause