#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

#include "i_block_cipher.hpp"
#include "i_key_expander.hpp"
#include "i_round_transform.hpp"

namespace lab1 {

class feistel_network : public i_block_cipher {
 public:
  feistel_network(std::unique_ptr<i_key_expander> key_expander,
                  std::unique_ptr<i_round_transform> round_transform,
                  std::size_t block_size);
  void set_key(std::span<const std::uint8_t> key) override;
  [[nodiscard]] std::size_t block_size() const override;
  [[nodiscard]] std::vector<std::uint8_t> encrypt_block(
      std::span<const std::uint8_t> block) const override;
  [[nodiscard]] std::vector<std::uint8_t> decrypt_block(
      std::span<const std::uint8_t> block) const override;

 private:
  [[nodiscard]] std::vector<std::uint8_t> run(
      std::span<const std::uint8_t> block, bool reverse_keys) const;
  std::unique_ptr<i_key_expander> key_expander_;
  std::unique_ptr<i_round_transform> round_transform_;
  std::size_t block_size_;
  std::vector<std::vector<std::uint8_t>> round_keys_;
};
}  // namespace lab1