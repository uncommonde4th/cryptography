#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
#include <span>
#include <vector>

#include "i_block_cipher.hpp"

namespace lab1 {

enum class cipher_mode { ecb, cbc, pcbc, cfb, ofb, ctr, random_delta };

enum class padding_mode { zeros, ansi_x923, pkcs7, iso_10126 };

// Класс, репрезентирующий контекст выполнения симметричного криптографического
// алгоритма, предоставляющий объектный функционал по выполнению операций
// шифрования и дешифрования заданным ключом симметричного алгоритма с
// поддержкой одного из режимов шифрования.
class cipher_context {
 public:
  cipher_context(std::unique_ptr<i_block_cipher> cipher,
                 std::span<const std::uint8_t> key, cipher_mode mode,
                 padding_mode padding,
                 std::optional<std::vector<std::uint8_t>> iv = std::nullopt,
                 std::vector<std::uint64_t> extra_params = {});
  cipher_context(const cipher_context&) = delete;
  cipher_context& operator=(const cipher_context&) = delete;
  cipher_context(cipher_context&&) = delete;
  cipher_context& operator=(cipher_context&&) = delete;

  [[nodiscard]] std::future<void> encrypt(std::span<const std::uint8_t> data,
                                          std::vector<std::uint8_t>& result);
  [[nodiscard]] std::future<void> decrypt(std::span<const std::uint8_t> data,
                                          std::vector<std::uint8_t>& result);

  [[nodiscard]] std::future<void> encrypt(const std::filesystem::path& input,
                                          const std::filesystem::path& output);
  [[nodiscard]] std::future<void> decrypt(const std::filesystem::path& input,
                                          const std::filesystem::path& output);

  /// Сколько потоков считало блоки в последней завершённой операции
  /// (1 - последовательное вычисление). Читать после future::get().
  [[nodiscard]] std::size_t last_encrypt_threads() const noexcept {
    return encrypt_threads_.load();
  }
  [[nodiscard]] std::size_t last_decrypt_threads() const noexcept {
    return decrypt_threads_.load();
  }

 private:
  using bytes = std::vector<std::uint8_t>;

  bytes encrypt_sync(std::span<const std::uint8_t> data) const;
  bytes decrypt_sync(std::span<const std::uint8_t> data) const;

  bytes encrypt_blocks(const bytes& plain, std::size_t& threads) const;
  bytes decrypt_blocks(const bytes& cipher_text, std::size_t& threads) const;
  bytes stream_blocks(const bytes& in, std::size_t& threads) const;

  std::unique_ptr<i_block_cipher> cipher_;
  cipher_mode mode_;
  padding_mode padding_;
  std::size_t block_size_ = 0;
  bytes iv_;
  std::uint64_t delta_ = 0;
  mutable std::atomic<std::size_t> encrypt_threads_{1};
  mutable std::atomic<std::size_t> decrypt_threads_{1};
};
}  // namespace lab1