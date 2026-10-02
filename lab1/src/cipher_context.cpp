#include "cipher_context.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <future>
#include <ios>
#include <memory>
#include <random>
#include <span>
#include <stdexcept>
#include <thread>

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;
using bytes_view = std::span<const std::uint8_t>;

constexpr std::size_t parallel_threshold = 256;

// Шаблон для параллельного выполнения лямбда-функций.
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

bytes_view block_view(const bytes& data, std::size_t i, std::size_t bs) {
  return bytes_view(data.data() + i * bs, bs);
}

void store_block(bytes& out, std::size_t i, std::size_t bs,
                 const bytes& block) {
  std::copy(block.begin(), block.end(), out.data() + i * bs);
}

bytes make_counter(bytes_view iv, std::uint64_t offset) {
  bytes counter(iv.begin(), iv.end());
  unsigned int carry = 0;
  for (std::size_t i = 0; i < counter.size(); ++i) {
    const std::size_t pos = counter.size() - 1 - i;
    const unsigned int add =
        i < 8 ? static_cast<unsigned int>((offset >> (8 * i)) & 0xFFu) : 0u;
    const unsigned int sum = counter[pos] + add + carry;
    counter[pos] = static_cast<std::uint8_t>(sum & 0xFFu);
    carry = sum >> 8;
  }
  return counter;
}

bytes pad(bytes_view data, std::size_t bs, padding_mode mode) {
  bytes result(data.begin(), data.end());
  const std::size_t rest = data.size() % bs;

  if (mode == padding_mode::zeros) {
    if (rest != 0) {
      result.resize(data.size() + (bs - rest), 0);
    }
    return result;
  }
  const std::size_t count = bs - rest;
  switch (mode) {
    case padding_mode::ansi_x923m:
      result.insert(result.end(), count - 1, std::uint8_t{0});
      break;
    case padding_mode::pkcs7:
      result.insert(result.end(), count - 1, static_cast<std::uint8_t>(count));
      break;
    case padding_mode::iso_10126: {
      std::random_device rd;
      for (std::size_t i = 0; i + 1 < count; ++i) {
        result.push_back(static_cast<std::uint8_t>(rd()));
      }
      break;
    }
    default:
      break;
  }
  result.push_back(static_cast<std::uint8_t>(count));
  return result;
}

bytes unpad(bytes data, std::size_t bs, padding_mode mode) {
  if (mode == padding_mode::zeros) {
    while (!data.empty() && data.back() == 0) {
      data.pop_back();
    }
    return data;
  }

  if (data.empty()) {
    throw std::runtime_error("unpad: empty data");
  }
  const std::size_t count = data.back();
  if (count == 0 || count > bs || count > data.size()) {
    throw std::runtime_error("unpad: invalid padding");
  }
  const std::size_t start = data.size() - count;

  if (mode == padding_mode::pkcs7) {
    for (std::size_t i = start; i < data.size(); ++i) {
      if (data[i] != count) {
        throw std::runtime_error("unpad: invalid PKCS7 padding");
      }
    }
  }
  data.resize(start);
  return data;
}

bytes read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot open input file: " + path.string());
  }
  const auto size =
      static_cast<std::streamsize>(std::filesystem::file_size(path));
  bytes data(static_cast<std::size_t>(size));
  in.read(reinterpret_cast<char*>(data.data()), size);
  if (in.gcount() != size) {
    throw std::runtime_error("cannot read input file: " + path.string());
  }
  return data;
}

void write_file(const std::filesystem::path& path, const bytes& data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("cannot open output file: " + path.string());
  }
  out.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
  if (!out) {
    throw std::runtime_error("cannot write output file: " + path.string());
  }
}

}  // namespace

cipher_context::cipher_context(std::unique_ptr<i_block_cipher> cipher,
                               std::span<const std::uint8_t> key,
                               cipher_mode mode, padding_mode padding,
                               std::optional<bytes> iv,
                               std::vector<std::uint64_t> extra_params)
    : cipher_(std::move(cipher)), mode_(mode), padding_(padding) {
  if (!cipher_) {
    throw std::invalid_argument("cipher_context: cipher is null");
  }
  cipher_->set_key(key);

  block_size_ = cipher_->block_size();
  if (block_size_ == 0 || block_size_ > 255) {
    throw std::invalid_argument("cipher_context: unsupported block size");
  }

  if (mode_ != cipher_mode::ecb) {
    if (!iv || iv->size() != block_size_) {
      throw std::invalid_argument(
          "cipher_context: IV of block size is required");
    }
    iv_ = std::move(*iv);
  }
  if (mode == cipher_mode::random_delta) {
    if (extra_params.empty()) {
      throw std::invalid_argument(
          "cipher_context: random_delta requires delta");
    }
    delta_ = extra_params.front();
  }
}

cipher_context::bytes cipher_context::encrypt_sync(bytes_view data) const {
  return encrypt_blocks(pad(data, block_size_, padding_));
}

cipher_context::bytes cipher_context::decrypt_sync(bytes_view data) const {
  if (data.size() % block_size_ != 0) {
    throw std::invalid_argument(
        "decrypt: data size is not a multiple of block size");
  }
  const bytes plain = decrypt_blocks(bytes(data.begin(), data.end()));
  return unpad(plain, block_size_, padding_);
}

cipher_context::bytes cipher_context::stream_blocks(const bytes& in) const {
  const std::size_t bs = block_size_;
  const std::size_t n = in.size() / bs;
  bytes out(in.size());

  if (mode_ == cipher_mode::ofb) {
    bytes state = iv_;
    for (std::size_t i = 0; i < n; ++i) {
      state = cipher_->encrypt_block(state);
      store_block(out, i, bs, xor_bytes(block_view(in, i, bs), state));
    }
  } else {
    parallel_for(n, [&](std::size_t begin, std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        const bytes gamma = cipher_->encrypt_block(make_counter(iv_, i));
        store_block(out, i, bs, xor_bytes(block_view(in, i, bs), gamma));
      }
    });
  }
  return out;
}

cipher_context::bytes cipher_context::encrypt_blocks(const bytes& plain) const {
  const std::size_t bs = block_size_;
  const std::size_t n = plain.size() / bs;
  bytes out(plain.size());

  switch (mode_) {
    case cipher_mode::ecb: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          store_block(out, i, bs,
                      cipher_->encrypt_block(block_view(plain, i, bs)));
        }
      });
      break;
    }
    case cipher_mode::cbc: {
      bytes prev = iv_;
      for (std::size_t i = 0; i < n; ++i) {
        bytes c =
            cipher_->encrypt_block(xor_bytes(block_view(plain, i, bs), prev));
        store_block(out, i, bs, c);
        prev = std::move(c);
      }
      break;
    }
    case cipher_mode::pcbc: {
      bytes feedback = iv_;
      for (std::size_t i = 0; i < n; ++i) {
        const bytes c = cipher_->encrypt_block(
            xor_bytes(block_view(plain, i, bs), feedback));
        store_block(out, i, bs, c);
        feedback = xor_bytes(block_view(plain, i, bs), c);
      }
      break;
    }

    case cipher_mode::cfb: {
      bytes prev = iv_;
      for (std::size_t i = 0; i < n; ++i) {
        bytes c =
            xor_bytes(block_view(plain, i, bs), cipher_->encrypt_block(prev));
        store_block(out, i, bs, c);
        prev = std::move(c);
      }
      break;
    }

    case cipher_mode::ofb:
    case cipher_mode::ctr:
      return stream_blocks(plain);

    case cipher_mode::random_delta: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes value =
              make_counter(iv_, static_cast<std::uint64_t>(i) * delta_);
          store_block(out, i, bs,
                      cipher_->encrypt_block(
                          xor_bytes(block_view(plain, i, bs), value)));
        }
      });
      break;
    }
  }
  return out;
}

cipher_context::bytes cipher_context::decrypt_blocks(
    const bytes& cipher_text) const {
  const std::size_t bs = block_size_;
  const std::size_t n = cipher_text.size() / bs;
  bytes out(cipher_text.size());

  switch (mode_) {
    case cipher_mode::ecb: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          store_block(out, i, bs,
                      cipher_->decrypt_block(block_view(cipher_text, i, bs)));
        }
      });
      break;
    }

    case cipher_mode::cbc: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes_view prev =
              i == 0 ? bytes_view(iv_) : block_view(cipher_text, i - 1, bs);
          store_block(
              out, i, bs,
              xor_bytes(cipher_->decrypt_block(block_view(cipher_text, i, bs)),
                        prev));
        }
      });
      break;
    }

    case cipher_mode::pcbc: {
      bytes feedback = iv_;
      for (std::size_t i = 0; i < n; ++i) {
        const bytes p = xor_bytes(
            cipher_->decrypt_block(block_view(cipher_text, i, bs)), feedback);
        store_block(out, i, bs, p);
        feedback = xor_bytes(p, block_view(cipher_text, i, bs));
      }
      break;
    }

    case cipher_mode::cfb: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes_view prev =
              i == 0 ? bytes_view(iv_) : block_view(cipher_text, i - 1, bs);
          store_block(out, i, bs,
                      xor_bytes(block_view(cipher_text, i, bs),
                                cipher_->encrypt_block(prev)));
        }
      });
      break;
    }

    case cipher_mode::ofb:
    case cipher_mode::ctr:
      return stream_blocks(cipher_text);

    case cipher_mode::random_delta: {
      parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes value =
              make_counter(iv_, static_cast<std::uint64_t>(i) * delta_);
          store_block(
              out, i, bs,
              xor_bytes(cipher_->decrypt_block(block_view(cipher_text, i, bs)),
                        value));
        }
      });
      break;
    }
  }
  return out;
}

std::future<void> cipher_context::encrypt(std::span<const std::uint8_t> data,
                                          bytes& result) {
  return std::async(std::launch::async,
                    [this, input = bytes(data.begin(), data.end()), &result] {
                      result = encrypt_sync(input);
                    });
}

std::future<void> cipher_context::decrypt(std::span<const std::uint8_t> data,
                                          bytes& result) {
  return std::async(std::launch::async,
                    [this, input = bytes(data.begin(), data.end()), &result] {
                      result = decrypt_sync(input);
                    });
}

std::future<void> cipher_context::encrypt(const std::filesystem::path& input,
                                          const std::filesystem::path& output) {
  return std::async(std::launch::async, [this, input, output] {
    write_file(output, encrypt_sync(read_file(input)));
  });
}

std::future<void> cipher_context::decrypt(const std::filesystem::path& input,
                                          const std::filesystem::path& output) {
  return std::async(std::launch::async, [this, input, output] {
    write_file(output, decrypt_sync(read_file(input)));
  });
}

}  // namespace lab1