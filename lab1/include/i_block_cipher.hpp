#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace lab1 {

class i_block_cipher {
public:
    virtual ~i_block_cipher() = default;

    virtual void set_key(std::span<const std::uint8_t> key) = 0;

    [[nodiscard]] virtual std::size_t block_size() const = 0;

    [[nodiscard]] virtual std::vector<std::uint8_t>
    encrypt_block(std::span<const std::uint8_t> block) const = 0;

    [[nodiscard]] virtual std::vector<std::uint8_t>
    decrypt_block(std::span<const std::uint8_t> block) const = 0;
};
} // namespace lab1