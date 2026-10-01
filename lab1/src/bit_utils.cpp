#include "bit_utils.hpp"

#include <cstddef>
#include <stdexcept>

namespace lab1 {

// Переводит позицию бита во всем массиве в позицию внутри его байта.
static std::size_t shift_in_byte(std::size_t k, bit_order order) {
  const std::size_t pos = k % 8;
  return order == bit_order::lsb_first ? pos : 7 - pos;
}

bool get_bit(std::span<const std::uint8_t> data, std::size_t k,
             bit_order order) {
  if (k >= data.size() * 8) {
    throw std::out_of_range("get_bit: bit index is out of range");
  }
  const std::uint8_t byte = data[k / 8];
  return ((byte >> shift_in_byte(k, order)) & 1u) != 0;
}

void set_bit(std::span<std::uint8_t> data, std::size_t k, bool bit,
             bit_order order) {
  if (k >= data.size() * 8) {
    throw std::out_of_range("set_bit: bit index is out of range");
  }
  const auto mask = static_cast<std::uint8_t>(1u << shift_in_byte(k, order));
  std::uint8_t& byte = data[k / 8];
  if (bit) {
    byte = static_cast<std::uint8_t>(byte | mask);
  } else {
    byte = static_cast<std::uint8_t>(byte & ~mask);
  }
}

// Переставляет биты по P-блоку. Размер результата зависит от размера P-блока.
std::vector<std::uint8_t> permute(std::span<const std::uint8_t> value,
                                  std::span<const std::size_t> p_block,
                                  bit_order order, std::size_t base_index) {
  if (base_index > 1) {
    throw std::invalid_argument("permute: base index must be 0 or 1");
  }

  std::vector<std::uint8_t> result((p_block.size() + 7) / 8, 0);

  for (std::size_t i = 0; i < p_block.size(); ++i) {
    if (p_block[i] < base_index) {
      throw std::out_of_range("permute: p_block entry is below base_index");
    }
    const std::size_t source = p_block[i] - base_index;
    set_bit(result, i, get_bit(value, source, order), order);
  }
  return result;
}

}  // namespace lab1