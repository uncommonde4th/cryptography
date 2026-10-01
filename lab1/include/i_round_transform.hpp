#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace lab1 {

// Интерфейс, предоставляющий описание функционала по выполнению шифрующего
// преобразования.
class i_round_transform {
 public:
  virtual ~i_round_transform() = default;

  [[nodiscard]] virtual std::vector<std::uint8_t> transform(
      std::span<const std::uint8_t> block,
      std::span<const std::uint8_t> round_key) const = 0;
};
}  // namespace lab1