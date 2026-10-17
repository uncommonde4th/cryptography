#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "cipher_context.hpp"
#include "deal.hpp"
#include "des.hpp"

namespace {

using bytes = std::vector<std::uint8_t>;
using namespace lab1;

struct named_mode {
  const char* name;
  cipher_mode mode;
};
struct named_padding {
  const char* id;
  const char* name;
  padding_mode padding;
};

struct algorithm {
  const char* id;
  const char* name;
  std::size_t key_size;
  std::size_t block_size;
  std::function<std::unique_ptr<i_block_cipher>()> create;
};

constexpr std::array<named_mode, 7> all_modes = {
    {{"ECB", cipher_mode::ecb},
     {"CBC", cipher_mode::cbc},
     {"PCBC", cipher_mode::pcbc},
     {"CFB", cipher_mode::cfb},
     {"OFB", cipher_mode::ofb},
     {"CTR", cipher_mode::ctr},
     {"RandomDelta", cipher_mode::random_delta}}};

constexpr std::array<named_padding, 4> all_paddings = {
    {{"zeros", "Zeros", padding_mode::zeros},
     {"x923", "ANSI X.923", padding_mode::ansi_x923},
     {"pkcs7", "PKCS7", padding_mode::pkcs7},
     {"iso10126", "ISO 10126", padding_mode::iso_10126}}};

const std::array<algorithm, 4> all_algorithms = {{
    {"des", "DES", 8, 8,
     []() -> std::unique_ptr<i_block_cipher> {
       return std::make_unique<des>();
     }},
    {"deal128", "DEAL-128", 16, 16,
     []() -> std::unique_ptr<i_block_cipher> {
       return std::make_unique<deal>();
     }},
    {"deal192", "DEAL-192", 24, 16,
     []() -> std::unique_ptr<i_block_cipher> {
       return std::make_unique<deal>();
     }},
    {"deal256", "DEAL-256", 32, 16,
     []() -> std::unique_ptr<i_block_cipher> {
       return std::make_unique<deal>();
     }},
}};

bytes random_bytes(std::mt19937_64& rng, std::size_t count) {
  bytes result(count);
  for (auto& b : result) {
    b = static_cast<std::uint8_t>(rng());
  }
  return result;
}

bytes read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return bytes(std::istreambuf_iterator<char>(in),
               std::istreambuf_iterator<char>());
}

bool files_equal(const std::filesystem::path& a,
                 const std::filesystem::path& b) {
  std::ifstream fa(a, std::ios::binary);
  std::ifstream fb(b, std::ios::binary);
  if (!fa || !fb) {
    return false;
  }
  std::array<char, 4096> buf_a{};
  std::array<char, 4096> buf_b{};
  while (true) {
    fa.read(buf_a.data(), buf_a.size());
    fb.read(buf_b.data(), buf_b.size());
    const auto got_a = fa.gcount();
    const auto got_b = fb.gcount();
    if (got_a != got_b ||
        !std::equal(buf_a.begin(), buf_a.begin() + got_a, buf_b.begin())) {
      return false;
    }
    if (got_a == 0) {
      return true;
    }
  }
}

std::vector<named_padding> select_paddings(const std::string& filter,
                                           bool for_files) {
  std::string wanted = filter;
  if (wanted.empty()) {
    wanted = for_files ? "pkcs7" : "all";
  }
  std::vector<named_padding> result;
  for (const auto& pad : all_paddings) {
    if (wanted == "all" || wanted == pad.id) {
      result.push_back(pad);
    }
  }
  return result;
}

std::unique_ptr<cipher_context> make_context(const algorithm& algo,
                                             const bytes& key, cipher_mode mode,
                                             padding_mode padding,
                                             const bytes& iv) {
  // Последний аргумент - дельта для Random Delta (остальные режимы его игнорируют).
  return std::make_unique<cipher_context>(
      algo.create(), key, mode, padding, iv,
      std::vector<std::uint64_t>{0x9E3779B97F4A7C15ull});
}

// Эталонный вектор DES: ключ 133457799BBCDFF1, открытый текст 0123456789ABCDEF.
bool des_known_answer_test() {
  const bytes key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
  const bytes plain = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  const bytes expected = {0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05};

  des cipher;
  cipher.set_key(key);
  const bytes encrypted = cipher.encrypt_block(plain);
  const bytes decrypted = cipher.decrypt_block(encrypted);

  std::printf("Эталонный вектор DES: шифрование %s, дешифрование %s\n",
              encrypted == expected ? "OK" : "FAIL",
              decrypted == plain ? "OK" : "FAIL");
  return encrypted == expected && decrypted == plain;
}

// Один блок туда и обратно, шифртекст не должен совпадать с открытым текстом.
bool block_roundtrip_test(const algorithm& algo, std::mt19937_64& rng) {
  const auto cipher = algo.create();
  cipher->set_key(random_bytes(rng, algo.key_size));
  const bytes block = random_bytes(rng, algo.block_size);
  const bytes encrypted = cipher->encrypt_block(block);
  const bool ok =
      cipher->decrypt_block(encrypted) == block && encrypted != block;
  std::printf("  один блок туда и обратно: %s\n", ok ? "OK" : "FAIL");
  return ok;
}

bool random_data_test(const algorithm& algo, std::mt19937_64& rng,
                      const std::vector<named_padding>& paddings) {
  const std::array<std::size_t, 9> sizes = {0, 1, 7, 8, 9, 15, 16, 1000, 10003};
  std::size_t passed = 0;
  std::size_t total = 0;

  for (std::size_t size : sizes) {
    for (const auto& pad : paddings) {
      for (const auto& mode : all_modes) {
        bytes data = random_bytes(rng, size);
        // Набивка нулями не отличает нули данных от набивки,
        /*if (pad.padding == padding_mode::zeros && !data.empty() &&
            data.back() == 0) {
          data.back() = 1;
        }*/
        const bytes key = random_bytes(rng, algo.key_size);
        const bytes iv = random_bytes(rng, algo.block_size);

        bytes encrypted;
        bytes decrypted;
        bool ok = false;
        try {
          auto ctx = make_context(algo, key, mode.mode, pad.padding, iv);
          ctx->encrypt(data, encrypted).get();
          ctx->decrypt(encrypted, decrypted).get();
          ok = decrypted == data;
        } catch (const std::exception& e) {
          std::printf("  исключение: %s\n", e.what());
        }

        ++total;
        if (ok) {
          ++passed;
        } else {
          std::printf("  FAIL: размер %zu, набивка %s, режим %s\n", size,
                      pad.name, mode.name);
          return false;
        }
      }
    }
  }
  std::printf("  случайные данные: %zu из %zu комбинаций прошли\n", passed,
              total);
  return passed == total;
}

bool streaming_consistency_test(const algorithm& algo, std::mt19937_64& rng) {
  const std::array<std::size_t, 6> sizes = {0, 1, 4095, 4096, 4097, 8193};
  const auto tmp = std::filesystem::temp_directory_path();
  const auto in_path = tmp / "lab1_stream.in";
  const auto enc_path = tmp / "lab1_stream.enc";
  const auto dec_path = tmp / "lab1_stream.dec";
  bool all_ok = true;

  for (std::size_t size : sizes) {
    const bytes data = random_bytes(rng, size);
    {
      std::ofstream out(in_path, std::ios::binary | std::ios::trunc);
      out.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
    for (const auto& mode : all_modes) {
      const bytes key = random_bytes(rng, algo.key_size);
      const bytes iv = random_bytes(rng, algo.block_size);
      bool ok = false;
      try {
        auto ctx = make_context(algo, key, mode.mode, padding_mode::pkcs7, iv);
        bytes expected;
        ctx->encrypt(data, expected).get();
        ctx->encrypt(in_path, enc_path).get();
        ctx->decrypt(enc_path, dec_path).get();
        ok = read_all(enc_path) == expected && files_equal(in_path, dec_path);
      } catch (const std::exception& e) {
        std::printf("  исключение: %s\n", e.what());
      }
      if (!ok) {
        std::printf("  FAIL (потоковая обработка): размер %zu, режим %s\n",
                    size, mode.name);
        all_ok = false;
      }
    }
  }

  std::error_code ignored;
  /*std::filesystem::remove(in_path, ignored);
  std::filesystem::remove(enc_path, ignored);
  std::filesystem::remove(dec_path, ignored);*/
  std::printf("  потоковая обработка (границы порций): %s\n",
              all_ok ? "OK" : "FAIL");
  return all_ok;
}

bool file_test(const algorithm& algo, const std::filesystem::path& path,
               const named_padding& pad, std::mt19937_64& rng) {
  const bytes key = random_bytes(rng, algo.key_size);
  const bytes iv = random_bytes(rng, algo.block_size);
  const auto tmp = std::filesystem::temp_directory_path();
  const auto encrypted_path = tmp / "lab1_demo.enc";
  const auto decrypted_path = tmp / "lab1_demo.dec";

  std::printf("  файл %s (%llu байт), набивка %s\n", path.string().c_str(),
              static_cast<unsigned long long>(std::filesystem::file_size(path)),
              pad.name);
  bool all_ok = true;
  for (const auto& mode : all_modes) {
    bool ok = false;
    double seconds = 0;
    std::size_t encrypt_threads = 0;
    std::size_t decrypt_threads = 0;
    try {
      auto ctx = make_context(algo, key, mode.mode, pad.padding, iv);
      const auto start = std::chrono::steady_clock::now();
      ctx->encrypt(path, encrypted_path).get();
      encrypt_threads = ctx->last_encrypt_threads();
      ctx->decrypt(encrypted_path, decrypted_path).get();
      decrypt_threads = ctx->last_decrypt_threads();
      seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                              start)
                    .count();
      ok = files_equal(path, decrypted_path);
    } catch (const std::exception& e) {
      std::printf("    исключение: %s\n", e.what());
    }
    std::printf(
        "    %-12s %s  (%.3f с)  потоков: шифрование %zu, дешифрование %zu\n",
        mode.name, ok ? "OK" : "FAIL", seconds, encrypt_threads,
        decrypt_threads);
    all_ok = all_ok && ok;
  }

  std::error_code ignored;
  std::filesystem::remove(encrypted_path, ignored);
  std::filesystem::remove(decrypted_path, ignored);
  return all_ok;
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    std::string algo_filter;
    std::string padding_filter;
    std::vector<std::filesystem::path> files;
    for (int i = 1; i < argc; ++i) {
      const std::string arg = argv[i];
      if (arg.rfind("--algo=", 0) == 0) {
        algo_filter = arg.substr(7);
      } else if (arg.rfind("--padding=", 0) == 0) {
        padding_filter = arg.substr(10);
      } else {
        files.emplace_back(arg);
      }
    }

    const auto test_paddings = select_paddings(padding_filter, false);
    const auto file_paddings = select_paddings(padding_filter, true);
    if (test_paddings.empty()) {
      std::printf(
          "Неизвестная набивка: %s (доступны: zeros, x923, pkcs7, iso10126, "
          "all)\n",
          padding_filter.c_str());
      return 2;
    }

    std::mt19937_64 rng{std::random_device{}()};
    bool ok = des_known_answer_test();
    bool any_selected = false;
    std::printf("Доступно аппаратных потоков: %u\n",
                std::thread::hardware_concurrency());

    for (const auto& algo : all_algorithms) {
      if (!algo_filter.empty() && algo_filter != algo.id) {
        continue;
      }
      any_selected = true;
      std::printf("\n=== %s ===\n", algo.name);
      ok = block_roundtrip_test(algo, rng) && ok;
      ok = random_data_test(algo, rng, test_paddings) && ok;
      ok = streaming_consistency_test(algo, rng) && ok;
      for (const auto& file : files) {
        for (const auto& pad : file_paddings) {
          ok = file_test(algo, file, pad, rng) && ok;
        }
      }
    }

    if (!any_selected) {
      std::printf(
          "Неизвестный алгоритм: %s (доступны: des, deal128, deal192, "
          "deal256)\n",
          algo_filter.c_str());
      return 2;
    }

    std::printf("\n%s\n", ok ? "Все проверки пройдены" : "Есть ошибки");
    return ok ? 0 : 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "Ошибка: %s\n", e.what());
    return 2;
  }
}