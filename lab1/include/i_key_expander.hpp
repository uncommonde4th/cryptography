#pragma once
#include <cstdint>
#include <span>
#include <vector>

namespace lab1 {

// Интерфейс, предоставляющий описание функционала для процедуры расширения
// ключа (генерации раундовых ключей).
class i_key_expander {
 public:
  virtual ~i_key_expander() = default;

  [[nodiscard]] virtual std::vector<std::vector<std::uint8_t>> expand_key(
      std::span<const std::uint8_t> key) const = 0;
};
}  // namespace lab1