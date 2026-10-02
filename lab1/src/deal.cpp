#include "deal.hpp"

#include <stdexcept>
#include <utility>

#include "des.hpp"

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;

// Фиксированный ключ DES, на котором строится расширение ключа DEAL.
constexpr std::uint8_t fixed_des_key[8] = {0x01, 0x23, 0x45, 0x67,
                                           0x89, 0xAB, 0xCD, 0xEF};

// Константа s_j: 64-битное значение, в котором установлен один бит
// с номером j.
bytes round_constant(std::size_t j) {
  bytes constant(8, 0);
  const std::size_t bit = j - 1;
  constant[bit / 8] = static_cast<std::uint8_t>(0x80u >> (bit % 8));
  return constant;
}

void xor_into(bytes& target, std::span<const std::uint8_t> other) {
  for (std::size_t i = 0; i < target.size(); ++i) {
    target[i] = static_cast<std::uint8_t>(target[i] ^ other[i]);
  }
}

}  // namespace

std::vector<bytes> deal_key_expander::expand_key(
    std::span<const std::uint8_t> key) const {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw std::invalid_argument("DEAL key must be 16, 24 or 32 bytes");
  }

  const std::size_t parts = key.size() / 8;  // k: число 64-битных частей ключа
  const std::size_t rounds =
      parts == 4 ? 8 : 6;  // 6 раундов для 128/192, 8 для 256

  des cipher;
  cipher.set_key(fixed_des_key);

  // RK_1 = E(K_1)
  // RK_i = E(K_i xor RK_(i-1))                      при 1 < i <= k
  // RK_i = E(K_((i-1) mod k + 1) xor s_(i-k) xor RK_(i-1))   при i > k
  std::vector<bytes> round_keys;
  round_keys.reserve(rounds);
  for (std::size_t i = 1; i <= rounds; ++i) {
    const std::size_t part = (i - 1) % parts;
    bytes input(key.begin() + static_cast<std::ptrdiff_t>(part * 8),
                key.begin() + static_cast<std::ptrdiff_t>(part * 8 + 8));
    if (i > 1) {
      xor_into(input, round_keys.back());
    }
    if (i > parts) {
      xor_into(input, round_constant(i - parts));
    }
    round_keys.push_back(cipher.encrypt_block(input));
  }
  return round_keys;
}

des_round_adapter::des_round_adapter(cipher_factory factory)
    : factory_(std::move(factory)) {
  if (!factory_) {
    throw std::invalid_argument("des_round_adapter: factory is empty");
  }
}

bytes des_round_adapter::transform(
    std::span<const std::uint8_t> block,
    std::span<const std::uint8_t> round_key) const {
  if (block.size() != 8 || round_key.size() != 8) {
    throw std::invalid_argument(
        "des_round_adapter: block and round key must be 8 bytes");
  }
  const auto cipher = factory_();
  cipher->set_key(round_key);
  return cipher->encrypt_block(block);
}

deal::deal()
    : feistel_(std::make_unique<deal_key_expander>(),
               std::make_unique<des_round_adapter>(
                   []() -> std::unique_ptr<i_block_cipher> {
                     return std::make_unique<des>();
                   }),
               16) {}

void deal::set_key(std::span<const std::uint8_t> key) {
  feistel_.set_key(key);
}

std::size_t deal::block_size() const {
  return 16;
}

bytes deal::encrypt_block(std::span<const std::uint8_t> block) const {
  return feistel_.encrypt_block(block);
}

bytes deal::decrypt_block(std::span<const std::uint8_t> block) const {
  return feistel_.decrypt_block(block);
}

}  // namespace lab1