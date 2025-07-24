#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

// SM3 constants
constexpr uint32_t SM3_IV[] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

constexpr uint32_t SM3_T[] = {
    0x79CC4519, 0x7A879D8A
};

// Utility functions
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

class SM3 {
public:
    SM3() {
        reset();
    }

    void reset() {
        std::copy(std::begin(SM3_IV), std::end(SM3_IV), std::begin(state));
        length = 0;
        buffer.clear();
    }

    void update(const uint8_t* data, size_t len) {
        length += len;
        buffer.insert(buffer.end(), data, data + len);

        while (buffer.size() >= 64) {
            process_block(buffer.data());
            buffer.erase(buffer.begin(), buffer.begin() + 64);
        }
    }

    void finalize(uint8_t digest[32]) {
        // Padding
        uint64_t bit_length = length * 8;
        buffer.push_back(0x80);

        size_t padding_size = 64 - (buffer.size() % 64);
        if (padding_size < 8) {
            padding_size += 64;
        }

        buffer.insert(buffer.end(), padding_size - 8, 0x00);

        for (int i = 7; i >= 0; --i) {
            buffer.push_back((bit_length >> (i * 8)) & 0xFF);
        }

        // Process final blocks
        for (size_t i = 0; i < buffer.size(); i += 64) {
            process_block(buffer.data() + i);
        }

        // Output digest
        for (int i = 0; i < 8; ++i) {
            digest[i * 4 + 0] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = (state[i] >> 0) & 0xFF;
        }
    }

private:
    void process_block(const uint8_t* block) {
        uint32_t W[68];
        uint32_t W1[64];

        // Message expansion
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4 + 0] << 24) |
                   (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) |
                   (block[i * 4 + 3] << 0);
        }

        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL(W[i-3], 15)) ^ ROTL(W[i-13], 7) ^ W[i-6];
        }

        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i+4];
        }

        // Compression
        uint32_t A = state[0];
        uint32_t B = state[1];
        uint32_t C = state[2];
        uint32_t D = state[3];
        uint32_t E = state[4];
        uint32_t F = state[5];
        uint32_t G = state[6];
        uint32_t H = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(SM3_T[i < 16 ? 0 : 1], i % 32)), 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = (i < 16 ? FF0(A, B, C) : FF1(A, B, C)) + D + SS2 + W1[i];
            uint32_t TT2 = (i < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[i];

            D = C;
            C = ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }

    uint32_t state[8];
    uint64_t length;
    std::vector<uint8_t> buffer;
};

class HMAC_SM3 {
public:
    HMAC_SM3(const uint8_t* key, size_t key_len) {
        // Key processing
        uint8_t processed_key[64] = {0};

        if (key_len > 64) {
            SM3 sm3;
            sm3.update(key, key_len);
            sm3.finalize(processed_key);
        } else {
            std::copy(key, key + key_len, processed_key);
        }

        // Create inner and outer padding
        for (int i = 0; i < 64; ++i) {
            ipad[i] = processed_key[i] ^ 0x36;
            opad[i] = processed_key[i] ^ 0x5C;
        }
    }

    void compute(const uint8_t* data, size_t data_len, uint8_t digest[32]) {
        SM3 sm3;

        // Inner hash
        sm3.update(ipad, 64);
        sm3.update(data, data_len);
        uint8_t inner_hash[32];
        sm3.finalize(inner_hash);

        // Outer hash
        sm3.reset();
        sm3.update(opad, 64);
        sm3.update(inner_hash, 32);
        sm3.finalize(digest);
    }

private:
    uint8_t ipad[64];
    uint8_t opad[64];
};

// Helper function to convert string to hex
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

int main() {
    // Example usage
    std::string key = "secretKey";
    std::string key_long = "secretKey_secretKey_secretKey_secretKey_secretKey_secretKey_secretKey";
    std::string message = "Hello, HMAC-SM3!";
    //sm3 whith key "secretKey_secretKey_secretKey_secretKey_secretKey_secretKey_secretKey"
    //--> da6bb08ddfb04dce6ecd2f36290d6c5c7b0346ae32191327cc24300c39e90ffc
    //sm3 whith key "secretKey"
    //--> 2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df

    // Compute HMAC-SM3
    HMAC_SM3 hmac(reinterpret_cast<const uint8_t*>(key.data()), key.size());
    uint8_t digest[32];
    hmac.compute(reinterpret_cast<const uint8_t*>(message.data()), message.size(), digest);

    // Print result
    std::cout << "HMAC-SM3 Short Key : " << bytes_to_hex(digest, 32) << std::endl;
    //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df     --online
    //2c2d7be4307a1a030c018f9ff34be0180369d209ca2965293150588c9669b7df     --cpp

    //Long Key Test
    // Compute HMAC-SM3
    HMAC_SM3 hmac1(reinterpret_cast<const uint8_t*>(key_long.data()), key_long.size());
    uint8_t digest1[32];
    hmac1.compute(reinterpret_cast<const uint8_t*>(message.data()), message.size(), digest1);
    std::cout << "HMAC-SM3 Long  Key : " << bytes_to_hex(digest1, 32) << std::endl;
    //da6bb08ddfb04dce6ecd2f36290d6c5c7b0346ae32191327cc24300c39e90ffc     --online
    //da6bb08ddfb04dce6ecd2f36290d6c5c7b0346ae32191327cc24300c39e90ffc     --cpp

    return 0;
}