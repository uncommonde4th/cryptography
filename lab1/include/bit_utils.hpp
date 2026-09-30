#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lab1 {

enum class bit_order { lsb_first, msb_first };

std::vector<std::uint8_t> permute(std::span<const std::uint8_t> value,
                                  std::span<const std::size_t> p_block, bit_order order,
                                  std::size_t base_index);

bool get_bit(std::span<const std::uint8_t> data, std::size_t k, bit_order order);

void set_bit(std::span<std::uint8_t> data, std::size_t k, bool bit, bit_order order);

} // namespace lab1