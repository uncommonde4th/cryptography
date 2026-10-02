#include "des.hpp"
#include <cstddef>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

#include "bit_utils.hpp"
#include "des_tables.hpp"
#include "feistel_network.hpp"

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;

std::vector<std::size_t> rotation_table(std::size_t shift) {
  std::vector<std::size_t> table(56);
  for (std::size_t i = 0; i < 28; ++i) {
    table[i] = (i + shift) % 28 + 1;
    table[28 + i] = 28 + (i + shift) % 28 + 1;
  }
  return table;
}

}  // namespace

std::vector<bytes> des_key_expander::expand_key(
    std::span<const std::uint8_t> key) const {
  if (key.size() != 8) {
    throw std::invalid_argument("DES key must be 8 bytes");
  }

  bytes state = permute(key, des_tables::pc1, bit_order::msb_first, 1);

  const std::vector<std::size_t> rotate_by_1 = rotation_table(1);
  const std::vector<std::size_t> rotate_by_2 = rotation_table(2);

  std::vector<bytes> round_keys;
  round_keys.reserve(16);
  for (std::size_t round = 0; round < 16; ++round) {
    const auto& rotation =
        des_tables::shifts[round] == 1 ? rotate_by_1 : rotate_by_2;
    state = permute(state, rotation, bit_order::msb_first, 1);
    round_keys.push_back(
        permute(state, des_tables::pc2, bit_order::msb_first, 1));
  }
  return round_keys;
}

bytes des_round_transform::transform(
    std::span<const std::uint8_t> block,
    std::span<const std::uint8_t> round_key) const {
  if (block.size() != 4 || round_key.size() != 6) {
    throw std::invalid_argument(
        "DES round function: expected 4-byte block and 6-byte key");
  }

  bytes expanded =
      permute(block, des_tables::expansion, bit_order::msb_first, 1);
  for (std::size_t i = 0; i < expanded.size(); ++i) {
    expanded[i] = static_cast<std::uint8_t>(expanded[i] ^ round_key[i]);
  }

  bytes substituted(4, 0);
  for (std::size_t group = 0; group < 8; ++group) {
    const std::size_t base = group * 6;
    const auto bit = [&](std::size_t j) -> unsigned {
      return get_bit(expanded, base + j, bit_order::msb_first) ? 1u : 0u;
    };
    const unsigned row = (bit(0) << 1) | bit(5);
    const unsigned col = (bit(1) << 3) | (bit(2) << 2) | (bit(3) << 1) | bit(4);
    const unsigned value = des_tables::s_boxes[group][row * 16 + col];

    for (std::size_t j = 0; j < 4; ++j) {
      set_bit(substituted, group * 4 + j, ((value >> (3 - j)) & 1u) != 0,
              bit_order::msb_first);
    }
  }
  return permute(substituted, des_tables::p_permutation, bit_order::msb_first,
                 1);
}

des::des()
    : feistel_(std::make_unique<des_key_expander>(),
               std::make_unique<des_round_transform>(), 8) {}

void des::set_key(std::span<const std::uint8_t> key) {
  feistel_.set_key(key);
}

std::size_t des::block_size() const {
  return 8;
}

bytes des::encrypt_block(std::span<const std::uint8_t> block) const {
  if (block.size() != 8) {
    throw std::invalid_argument("DES block must be 8 bytes");
  }
  const bytes permuted =
      permute(block, des_tables::ip, bit_order::msb_first, 1);
  const bytes mixed = feistel_.encrypt_block(permuted);
  return permute(mixed, des_tables::fp, bit_order::msb_first, 1);
}

bytes des::decrypt_block(std::span<const std::uint8_t> block) const {
  if (block.size() != 8) {
    throw std::invalid_argument("DES block must be 8 bytes");
  }
  const bytes permuted =
      permute(block, des_tables::ip, bit_order::msb_first, 1);
  const bytes mixed = feistel_.decrypt_block(permuted);
  return permute(mixed, des_tables::fp, bit_order::msb_first, 1);
}

}  // namespace lab1