#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

#include "feistel_network.hpp"
#include "i_block_cipher.hpp"
#include "i_key_expander.hpp"
#include "i_round_transform.hpp"

namespace lab1 {

// Расширение ключа DEAL: ключ 16, 24 или 32 байта -> 6 или 8 раундовых ключей по 8 байт.
class deal_key_expander final : public i_key_expander {
 public:
  [[nodiscard]] std::vector<std::vector<std::uint8_t>> expand_key(
      std::span<const std::uint8_t> key) const override;
};

// Адаптер: использует блочный шифр (DES) в качестве раундовой функции F.
// F(блок, раундовый_ключ) = шифрование блока на раундовом ключе.
class des_round_adapter final : public i_round_transform {
 public:
  using cipher_factory = std::function<std::unique_ptr<i_block_cipher>()>;

  explicit des_round_adapter(cipher_factory factory);

  [[nodiscard]] std::vector<std::uint8_t> transform(
      std::span<const std::uint8_t> block,
      std::span<const std::uint8_t> round_key) const override;

 private:
  cipher_factory factory_;
};

// Cеть Фейстеля с блоком 16 байт и DES в качестве раундовой функции.
class deal final : public i_block_cipher {
 public:
  deal();

  void set_key(std::span<const std::uint8_t> key) override;
  [[nodiscard]] std::size_t block_size() const override;
  [[nodiscard]] std::vector<std::uint8_t> encrypt_block(
      std::span<const std::uint8_t> block) const override;
  [[nodiscard]] std::vector<std::uint8_t> decrypt_block(
      std::span<const std::uint8_t> block) const override;

 private:
  feistel_network feistel_;
};

}  // namespace lab1