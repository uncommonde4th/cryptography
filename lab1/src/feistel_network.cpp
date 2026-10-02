#include "feistel_network.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>
#include "i_key_expander.hpp"
#include "i_round_transform.hpp"

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;

bytes xor_bytes(const bytes& a, const bytes& b) {
  bytes result(a.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    result[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
  }
  return result;
}
}  // namespace

feistel_network::feistel_network(
    std::unique_ptr<i_key_expander> key_expander,
    std::unique_ptr<i_round_transform> round_transform, std::size_t block_size)
    : key_expander_(std::move(key_expander)),
      round_transform_(std::move(round_transform)),
      block_size_(block_size) {
  if (!key_expander_ || !round_transform_) {
    throw std::invalid_argument("feistel_network: null dependency");
  }
  if (block_size_ == 0 || block_size_ % 2 != 0) {
    throw std::invalid_argument(
        "feistel_network: block size must be even and non-zero");
  }
}

void feistel_network::set_key(std::span<const std::uint8_t> key) {
  auto keys = key_expander_->expand_key(key);
  if (keys.empty()) {
    throw std::logic_error(
        "feistel_network: key expander returned no round keys");
  }
  round_keys_ = std::move(keys);
}

std::size_t feistel_network::block_size() const {
  return block_size_;
}

std::vector<std::uint8_t> feistel_network::encrypt_block(
    std::span<const std::uint8_t> block) const {
  return run(block, false);
}

std::vector<std::uint8_t> feistel_network::decrypt_block(
    std::span<const std::uint8_t> block) const {
  return run(block, true);
}

std::vector<std::uint8_t> feistel_network::run(
    std::span<const std::uint8_t> block, bool reverse_keys) const {
  if (round_keys_.empty()) {
    throw std::logic_error("feistel_network: jey is not set");
  }
  if (block.size() != block_size_) {
    throw std::invalid_argument("feistel_network: wrong block size");
  }

  const std::size_t half = block_size_ / 2;
  const auto left_view = block.first(half);
  const auto right_view = block.last(half);
  bytes left(left_view.begin(), left_view.end());
  bytes right(right_view.begin(), right_view.end());

  const std::size_t rounds = round_keys_.size();
  for (std::size_t r = 0; r < rounds; ++r) {
    const bytes& key =
        reverse_keys ? round_keys_[rounds - 1 - r] : round_keys_[r];
    bytes next_right = xor_bytes(left, round_transform_->transform(right, key));
    left = std::move(right);
    right = std::move(next_right);
  }

  bytes result;
  result.reserve(block_size_);
  result.insert(result.end(), right.begin(), right.end());
  result.insert(result.end(), left.begin(), left.end());
  return result;
}

}  // namespace lab1