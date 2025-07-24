#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

// 8字节SM3常量
constexpr uint32_t SM3_IV[] = {
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E
};

constexpr uint32_t SM3_T[] = {
    0x79CC4519,
    0x7A879D8A
};

//工具函数
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
    HMAC_SM3(const uint8_t* key, //密钥
             size_t key_len)     //密钥长度
    {
        //目标密钥
        uint8_t processed_key[64] = {0};

        //处理密钥
        if (key_len > 64) {
            //使用SM3哈希算法生成新密钥
            SM3 sm3;
            sm3.update(key, key_len);//根据密钥生成32字节SM3哈希密钥
            sm3.finalize(processed_key);//复制生成的32字节SM3哈希密钥到目标密钥中
        } else {
            //复制原始密钥到目标密钥中
            std::copy(key, //源范围的起始位置
                      key + key_len,//源范围的结束位置
                      processed_key);//目标
        }

        //初始化内部及外部填充键并与密钥进行位异域运算
        for (int i = 0; i < 64; ++i) {
            ipad[i] = processed_key[i] ^ 0x36;
            opad[i] = processed_key[i] ^ 0x5C;
        }
    }

    //计算SM3哈希
    void compute(const uint8_t* data, size_t data_len, uint8_t digest[32]) {
        SM3 sm3;
        //使用内部填充键与数据生成内部哈希
        sm3.update(ipad, 64);
        sm3.update(data, data_len);
        uint8_t inner_hash[32];
        sm3.finalize(inner_hash);

        //使用外部填充键与生成的内部哈希 生成最终的外部哈希也就是HAMC SM3输出值
        sm3.reset();
        sm3.update(opad, 64);
        sm3.update(inner_hash, 32);
        sm3.finalize(digest);
    }

private:
    uint8_t ipad[64]; //内填充键
    uint8_t opad[64]; //外填充键
};

//转换字符串为十六进制并返回标准字符串
std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;//字符串输出对象
    oss << std::hex << std::setfill('0');//设置填充字符0
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);//设置填充宽度为2，并将字符写入字符串中
    }
    return oss.str();//返回所有写入的字符
}

int main() {

    std::string key = "secretKey";
    std::string key_long = "secretKey_secretKey_secretKey_secretKey_secretKey_secretKey_secretKey";
    std::string message = "Hello, HMAC-SM3!";
    std::cout<<"===>原始短密钥:"<<key<<std::endl<<"===>原始长密钥:"<<key_long<<std::endl<<"===>原始消息:"<<message<<std::endl;
    HMAC_SM3 hmac(reinterpret_cast<const uint8_t*>(key.data()), key.size());
    uint8_t digest[32];
    hmac.compute(reinterpret_cast<const uint8_t*>(message.data()), message.size(), digest);
    std::cout <<"消息:-> \""<<message<< "\" 使用HmacSm3短密钥(密钥小于64字节)加密结果: " << bytes_to_hex(digest, 32) << std::endl;
    HMAC_SM3 hmac1(reinterpret_cast<const uint8_t*>(key_long.data()), key_long.size());
    uint8_t digest1[32];
    hmac1.compute(reinterpret_cast<const uint8_t*>(message.data()), message.size(), digest1);
    std::cout <<"消息:-> \""<<message<< "\" 使用HmacSm3长密钥(密钥大于64字节)加密结果: " << bytes_to_hex(digest1, 32) << std::endl;
    return 0;
}