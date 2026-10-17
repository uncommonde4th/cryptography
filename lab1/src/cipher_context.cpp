#include "cipher_context.hpp"

#include <algorithm>
#include <fstream>
#include <random>
#include <stdexcept>
#include <thread>

namespace lab1 {

namespace {

using bytes = std::vector<std::uint8_t>;
using bytes_view = std::span<const std::uint8_t>;

constexpr std::size_t parallel_threshold =
    256;  // меньше блоков - считаем в одном потоке
constexpr std::size_t file_buffer_size =
    4096;  // размер порции при работе с файлами

template <typename F>
std::size_t parallel_for(std::size_t count, F&& fn) {
  if (count < parallel_threshold) {
    fn(std::size_t{0}, count);
    return 1;
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
  return tasks.size();
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

/// iv + offset (big-endian, по модулю 2^(8 * размер iv)).
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

  const std::size_t count =
      bs - rest;  // от 1 до bs; если данные кратны bs, добавляется целый блок
  switch (mode) {
    case padding_mode::ansi_x923:
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
  } else if (mode == padding_mode::ansi_x923) {
    for (std::size_t i = start; i + 1 < data.size(); ++i) {
      if (data[i] != 0) {
        throw std::runtime_error("unpad: invalid ANSI X.923 padding");
      }
    }
  }
  // ISO 10126: случайные байты не проверяются, важен только последний.

  data.resize(start);
  return data;
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

  if (mode_ == cipher_mode::random_delta) {
    if (extra_params.empty()) {
      throw std::invalid_argument(
          "cipher_context: random_delta requires delta");
    }
    delta_ = extra_params.front();
  }
}

cipher_context::stream_state cipher_context::initial_state() const {
  stream_state state;
  state.prev = iv_;  // для ECB пусто
  return state;
}

cipher_context::bytes cipher_context::encrypt_sync(bytes_view data) const {
  stream_state state = initial_state();
  std::size_t threads = 1;
  bytes result =
      encrypt_blocks(pad(data, block_size_, padding_), state, threads);
  encrypt_threads_ = threads;
  return result;
}

cipher_context::bytes cipher_context::decrypt_sync(bytes_view data) const {
  if (data.size() % block_size_ != 0) {
    throw std::invalid_argument(
        "decrypt: data size is not a multiple of block size");
  }
  stream_state state = initial_state();
  std::size_t threads = 1;
  bytes plain = decrypt_blocks(bytes(data.begin(), data.end()), state, threads);
  decrypt_threads_ = threads;
  return unpad(std::move(plain), block_size_, padding_);
}

void cipher_context::process_file(const std::filesystem::path& input,
                                  const std::filesystem::path& output,
                                  bool encrypting) const {
  if (std::filesystem::exists(output) && std::filesystem::exists(input) &&
      std::filesystem::equivalent(input, output)) {
    throw std::invalid_argument("input and output files must be different");
  }

  std::ifstream in(input, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot open input file: " + input.string());
  }
  std::ofstream out(output, std::ios::binary | std::ios::trunc);
  if (!out) {
    throw std::runtime_error("cannot open output file: " + output.string());
  }

  // Размер порции кратен размеру блока (4096 для блоков 8 и 16 байт).
  const std::size_t chunk_size =
      std::max(block_size_, (file_buffer_size / block_size_) * block_size_);
  bytes buffer(chunk_size);
  stream_state state = initial_state();
  std::size_t max_threads = 1;

  while (true) {
    in.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(chunk_size));
    const auto got = static_cast<std::size_t>(in.gcount());
    const bool last = in.peek() == std::ifstream::traits_type::eof();

    const bytes_view chunk(buffer.data(), got);
    std::size_t threads = 1;
    bytes result;
    if (encrypting) {
      // Набивка добавляется только к последней порции.
      const bytes plain = last ? pad(chunk, block_size_, padding_)
                               : bytes(chunk.begin(), chunk.end());
      result = encrypt_blocks(plain, state, threads);
    } else {
      if (got % block_size_ != 0) {
        throw std::invalid_argument(
            "decrypt: file size is not a multiple of block size");
      }
      result =
          decrypt_blocks(bytes(chunk.begin(), chunk.end()), state, threads);
      if (last) {
        result = unpad(std::move(result), block_size_, padding_);
      }
    }

    out.write(reinterpret_cast<const char*>(result.data()),
              static_cast<std::streamsize>(result.size()));
    max_threads = std::max(max_threads, threads);

    if (last) {
      break;
    }
  }

  if (in.bad()) {
    throw std::runtime_error("cannot read input file: " + input.string());
  }
  out.flush();
  if (!out) {
    throw std::runtime_error("cannot write output file: " + output.string());
  }
  (encrypting ? encrypt_threads_ : decrypt_threads_) = max_threads;
}

cipher_context::bytes cipher_context::stream_blocks(
    const bytes& in, stream_state& state, std::size_t& threads) const {
  const std::size_t bs = block_size_;
  const std::size_t n = in.size() / bs;
  bytes out(in.size());

  if (mode_ == cipher_mode::ofb) {
    threads = 1;
    bytes gamma = state.prev;
    for (std::size_t i = 0; i < n; ++i) {
      gamma = cipher_->encrypt_block(gamma);
      store_block(out, i, bs, xor_bytes(block_view(in, i, bs), gamma));
    }
    state.prev = std::move(gamma);
  } else {
    // CTR - частный случай Random Delta при delta = 1:
    // C_i = P_i xor E(IV + i * step). Блоки независимы.
    const std::uint64_t step = mode_ == cipher_mode::random_delta ? delta_ : 1;
    const std::uint64_t base = state.block_index;
    threads = parallel_for(n, [&](std::size_t begin, std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        const bytes counter =
            make_counter(iv_, (base + static_cast<std::uint64_t>(i)) * step);
        const bytes gamma = cipher_->encrypt_block(counter);
        store_block(out, i, bs, xor_bytes(block_view(in, i, bs), gamma));
      }
    });
    state.block_index += n;
  }
  return out;
}

cipher_context::bytes cipher_context::encrypt_blocks(
    const bytes& plain, stream_state& state, std::size_t& threads) const {
  const std::size_t bs = block_size_;
  const std::size_t n = plain.size() / bs;
  bytes out(plain.size());
  threads = 1;

  switch (mode_) {
    case cipher_mode::ecb:
      threads = parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          store_block(out, i, bs,
                      cipher_->encrypt_block(block_view(plain, i, bs)));
        }
      });
      break;

    case cipher_mode::cbc: {  // C_i = E(P_i xor C_(i-1)), C_0 = IV
      bytes prev = state.prev;
      for (std::size_t i = 0; i < n; ++i) {
        bytes c =
            cipher_->encrypt_block(xor_bytes(block_view(plain, i, bs), prev));
        store_block(out, i, bs, c);
        prev = std::move(c);
      }
      state.prev = std::move(prev);
      break;
    }

    case cipher_mode::
        pcbc: {  // C_i = E(P_i xor F_(i-1)), F_i = P_i xor C_i, F_0 = IV
      bytes feedback = state.prev;
      for (std::size_t i = 0; i < n; ++i) {
        const bytes c = cipher_->encrypt_block(
            xor_bytes(block_view(plain, i, bs), feedback));
        store_block(out, i, bs, c);
        feedback = xor_bytes(block_view(plain, i, bs), c);
      }
      state.prev = std::move(feedback);
      break;
    }

    case cipher_mode::cfb: {  // C_i = P_i xor E(C_(i-1)), C_0 = IV
      bytes prev = state.prev;
      for (std::size_t i = 0; i < n; ++i) {
        bytes c =
            xor_bytes(block_view(plain, i, bs), cipher_->encrypt_block(prev));
        store_block(out, i, bs, c);
        prev = std::move(c);
      }
      state.prev = std::move(prev);
      break;
    }

    case cipher_mode::ofb:
    case cipher_mode::ctr:
    case cipher_mode::random_delta:
      return stream_blocks(plain, state, threads);
  }
  return out;
}

cipher_context::bytes cipher_context::decrypt_blocks(
    const bytes& cipher_text, stream_state& state, std::size_t& threads) const {
  const std::size_t bs = block_size_;
  const std::size_t n = cipher_text.size() / bs;
  bytes out(cipher_text.size());
  threads = 1;

  switch (mode_) {
    case cipher_mode::ecb:
      threads = parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          store_block(out, i, bs,
                      cipher_->decrypt_block(block_view(cipher_text, i, bs)));
        }
      });
      break;

    case cipher_mode::cbc:  // P_i = D(C_i) xor C_(i-1); блоки независимы
      threads = parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes_view prev = i == 0 ? bytes_view(state.prev)
                                         : block_view(cipher_text, i - 1, bs);
          store_block(
              out, i, bs,
              xor_bytes(cipher_->decrypt_block(block_view(cipher_text, i, bs)),
                        prev));
        }
      });
      if (n > 0) {
        const bytes_view last = block_view(cipher_text, n - 1, bs);
        state.prev.assign(last.begin(), last.end());
      }
      break;

    case cipher_mode::pcbc: {  // P_i = D(C_i) xor F_(i-1), F_i = P_i xor C_i
      bytes feedback = state.prev;
      for (std::size_t i = 0; i < n; ++i) {
        const bytes p = xor_bytes(
            cipher_->decrypt_block(block_view(cipher_text, i, bs)), feedback);
        store_block(out, i, bs, p);
        feedback = xor_bytes(p, block_view(cipher_text, i, bs));
      }
      state.prev = std::move(feedback);
      break;
    }

    case cipher_mode::cfb:  // P_i = C_i xor E(C_(i-1)); блоки независимы
      threads = parallel_for(n, [&](std::size_t begin, std::size_t end) {
        for (std::size_t i = begin; i < end; ++i) {
          const bytes_view prev = i == 0 ? bytes_view(state.prev)
                                         : block_view(cipher_text, i - 1, bs);
          store_block(out, i, bs,
                      xor_bytes(block_view(cipher_text, i, bs),
                                cipher_->encrypt_block(prev)));
        }
      });
      if (n > 0) {
        const bytes_view last = block_view(cipher_text, n - 1, bs);
        state.prev.assign(last.begin(), last.end());
      }
      break;

    case cipher_mode::ofb:
    case cipher_mode::ctr:
    case cipher_mode::random_delta:
      return stream_blocks(cipher_text, state, threads);
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
    process_file(input, output, true);
  });
}

std::future<void> cipher_context::decrypt(const std::filesystem::path& input,
                                          const std::filesystem::path& output) {
  return std::async(std::launch::async, [this, input, output] {
    process_file(input, output, false);
  });
}

}  // namespace lab1