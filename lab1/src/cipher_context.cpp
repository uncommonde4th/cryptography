#include "cipher_context.hpp"

#include <algorithm>
#include <cstddef>
#include <random>
#include <stdexcept>
#include <thread>

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;
using bytes_view = std::span<const std::uint8_t>;

constexpr std::size_t parallel_threshold = 256;

//
template <typename F>
void parallel_for(std::size_t count, F&& fn) {
  if (count < parallel_threshold) {
    fn(std::size_t{0}, count);
    return;
  }
  const std::size_t workers = std::max<std::size_t>(
      1, std::min<std::size_t>(std::thread::hardware_concurrency(), count));
  const std::size_t chunk = (count + workers - 1) / workers;

  std::vector<std::future<void>> tasks;
  for (std::size_t w = 0; w < workers; ++w) {
    const std::size_t begin = w * chunk;
    const std::size_t end = std::min(count, begin + chunk);
    if (begin >= end) {
      break;
    }
    tasks.push_back(
        std::async(std::launch::async, [&fn, begin, end] { fn(begin, end); }));
  }
  for (auto& task : tasks) {
    task.get();
  }
}

bytes xor_bytes(bytes_view a, bytes_view b) {
  bytes result(a.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    result[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
  }
  return result;
}

}  // namespace

}  // namespace lab1