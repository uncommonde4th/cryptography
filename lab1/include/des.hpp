#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "feistel_network.hpp"
#include "i_block_cipher.hpp"
#include "i_key_expander.hpp"
#include "i_round_transform.hpp"

namespace lab1 {

class des_key_expander final : public i_key_expander {
 public:
  [[nodiscard]] std::vector<std::vector<uint8_t>> expand_key(
      std::span<const std::uint8_t> key) const override;
};

class des_round_transform final : public i_round_transform {
 public:
  [[nodiscard]] std::vector<std::uint8_t> transform(
      std::span<const std::uint8_t> block,
      std::span<const std::uint8_t> round_key) const override;
};

class des final : public i_block_cipher {
 public:
  des();

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