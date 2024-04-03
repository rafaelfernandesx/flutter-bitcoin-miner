#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include "miner.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <chrono>

// Right rotation
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// Right shift
#define SHR(x, n) ((x) >> (n))

// Sigma0 function
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))

// Sigma1 function
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

// Sigma2 function
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))

// Sigma3 function
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// Major function
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))

// Majority function
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// SHA256 constants
const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
const uint32_t initialHash[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// SHA256 context
struct SHA256_CTX {
    std::vector<uint8_t> data;
    uint64_t bitLength;
};

// Function to initialize SHA256 context
void SHA256_Init(SHA256_CTX* ctx) {
    ctx->data.clear();
    ctx->bitLength = 0;
}

// Function to update SHA256 context with input data
void SHA256_Update(SHA256_CTX* ctx, const std::string& data) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    size_t length = data.size();
    ctx->data.insert(ctx->data.end(), ptr, ptr + length);
    ctx->bitLength += length * 8;
}

// Function to finalize SHA256 hash computation
std::string SHA256_Final(SHA256_CTX* ctx) {
    // Append '1' bit to the message
    ctx->data.push_back(0x80);

    // Append '0' bits
    while ((ctx->data.size() * 8) % 512 != 448) {
        ctx->data.push_back(0x00);
    }

    // Append original bit length of message (big endian)
    uint64_t bitLength = ctx->bitLength;
    for (int i = 7; i >= 0; --i) {
        ctx->data.push_back((bitLength >> (i * 8)) & 0xFF);
    }

    // Process the data in 512-bit blocks
    std::vector<uint32_t> words(64);
    std::vector<uint32_t> hash(initialHash, initialHash + 8);

    for (size_t i = 0; i < ctx->data.size(); i += 64) {
        // Prepare message schedule
        for (size_t t = 0; t < 16; ++t) {
            words[t] = (ctx->data[i + t * 4] << 24) | (ctx->data[i + t * 4 + 1] << 16) | (ctx->data[i + t * 4 + 2] << 8) | (ctx->data[i + t * 4 + 3]);
        }
        for (size_t t = 16; t < 64; ++t) {
            words[t] = sigma1(words[t - 2]) + words[t - 7] + sigma0(words[t - 15]) + words[t - 16];
        }

        // Initialize working variables
        uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];

        // Main loop
        for (size_t t = 0; t < 64; ++t) {
            uint32_t t1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + words[t];
            uint32_t t2 = SIGMA0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Update hash values
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    // Construct final hash as string
    std::ostringstream result;
    for (uint32_t h : hash) {
        result << std::hex << std::setw(8) << std::setfill('0') << h;
    }

    return result.str();
}

std::string hex2bin(const std::string& hex) {
    std::string bin;
    for (size_t i = 0; i < hex.length(); i += 2) {
        int byte;
        std::istringstream(hex.substr(i, 2)) >> std::hex >> byte;
        bin.push_back(static_cast<char>(byte));
    }
    return bin;
}

std::string bin2hex(const std::string& bin) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned char c : bin) {
        hex << std::setw(2) << static_cast<int>(c);
    }
    return hex.str();
}

std::string blockComputeRawHash(const std::string& header) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, header);
    std::string hash1 = hex2bin(SHA256_Final(&sha256));

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash1);
    std::string hash2 = hex2bin(SHA256_Final(&sha256));

    std::string reversedStr(hash2.rbegin(), hash2.rend());
    return bin2hex(reversedStr);
}

char * minerHeader(const char* headerHex, const char* targetHex)
{
    std::string blockHeaderHex(headerHex);
    std::string blockHeader = hex2bin(blockHeaderHex);
    std::string targetHash(targetHex);
    std::string blockHash = blockComputeRawHash(blockHeader);
    uint32_t nonce = 0;

    while (blockHash >= targetHash && nonce <= 0xffffffff) {
        nonce++;
        std::string nonceStr(reinterpret_cast<const char*>(&nonce), sizeof(nonce));
        blockHeader.replace(76, 4, nonceStr);
        blockHash = blockComputeRawHash(blockHeader);
    }
    blockHeader = bin2hex(blockHeader);
    char* headerHexResult = new char[blockHeader.length() + 1];
    std::strcpy(headerHexResult, blockHeader.c_str());

    return headerHexResult;
}

std::string concatenateStrings(const std::string& str1, const std::string& str2) {
    return str1 +"-"+ str2;
}

char * calculateHashPerSeconds()
{
    std::string blockHeaderHex ="010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d00000000";
    std::string blockHeader = hex2bin(blockHeaderHex);
    std::string targetHash ="00000000ffff0000000000000000000000000000000000000000000000000000";
    std::string blockHash = blockComputeRawHash(blockHeader);
    uint32_t nonce = 2849094635;
    int hashes_per_second = 0; // Contador de hashes por segundo

    // Contagem inicial de tempo
    auto start_time = std::chrono::steady_clock::now();

    while (blockHash >= targetHash && nonce <= 0xffffffff) {
        nonce++;
        std::string nonceStr(reinterpret_cast<const char*>(&nonce), sizeof(nonce));
        blockHeader.replace(76, 4, nonceStr);
        blockHash = blockComputeRawHash(blockHeader);
        hashes_per_second++; // Incrementa o contador de hashes por segundo
    }

    // Contagem final de tempo
    auto end_time = std::chrono::steady_clock::now();

    // Calcular o tempo decorrido em segundos
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;

    // Calcular o número de hashes por segundo
    double hashes_per_second_result = hashes_per_second / elapsed_seconds.count();
    std::string hashes_per_second_str = std::to_string(hashes_per_second_result);

    blockHeader = bin2hex(blockHeader);
    char* headerHexResult = new char[blockHeader.length() + 1];
    std::strcpy(headerHexResult, blockHeader.c_str());

    std::string concatenatedString = concatenateStrings(blockHeader, hashes_per_second_str);

    // Convertendo para char* se necessário
    char* result = new char[concatenatedString.length() + 1];
    std::strcpy(result, concatenatedString.c_str());

    return result;
}
