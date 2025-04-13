#ifndef ANP_METRICS_H_
#define ANP_METRICS_H_

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <ctime>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/histogram.hpp>

using boost::property_tree::ptree;

enum anp_log_level_e {
    LOG_NONE    = 0,
    LOG_ERROR   = 1,
    LOG_INFO    = 2,
    LOG_DEBUG   = 3,
    LOG_VERBOSE = 4
};

class anp_logger {
public:
    static anp_log_level_e log_level;
};

#define LOG(level, fmt, ...) \
    do { \
        if (level <= anp_logger::log_level && LOG_NONE != anp_logger::log_level) { \
            printf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define ANP_LOG_ERROR(fmt, ...)   LOG(LOG_ERROR, "[ERROR] " fmt, ##__VA_ARGS__)
#define ANP_LOG_INFO(fmt, ...)    LOG(LOG_INFO, "[INFO] " fmt, ##__VA_ARGS__)
#define ANP_LOG_DEBUG(fmt, ...)   LOG(LOG_DEBUG, "[DEBUG] " fmt, ##__VA_ARGS__)
#define ANP_LOG_VERBOSE(fmt, ...) LOG(LOG_VERBOSE, "[VERBOSE] " fmt, ##__VA_ARGS__)

template <typename T>
struct bucket_s {
    T min;
    T max;
    size_t count;

    bucket_s(const T& min, const T& max) : min(min), max(max), count(0) {}
    bucket_s() : count(0) {}

    bool contains(const T& value) const {
        return value >= min && value < max;
    }
};

template <typename T>
struct metric_config_s : public std::vector<bucket_s<T>> {
    void reset_counts() {
        for (auto& bucket : *this) {
            bucket.count = 0;
        }
    }

    void print() {
        ANP_LOG_VERBOSE("Histogram Buckets:");
        for (auto& bucket : *this) {
            ANP_LOG_VERBOSE("Bucket [%lu-%lu], Count: %lu", bucket.min, bucket.max, bucket.count);
        }
    }
};

struct histogram_config_s {
    metric_config_s<uint64_t> completion_metrics;
};

template <typename T>
class buffer_s {
public:
    buffer_s(size_t size) : size_(size),
        buffer_(size),
        count_(0),
        write_index_(0),
        rollover_count_(0) {
   }

    // push an element into the buffer (overwrites the oldest if full)
    void push(const T& value) {
        buffer_[write_index_] = value;
        write_index_ = (write_index_ + 1) % size_;
        if (count_ == size_) {
            rollover_count_++;
        } else {
            count_++;
        }
    }

    std::vector<T> get_values() const {
        return std::vector<T>(buffer_.begin(), buffer_.begin() + count_);
    }

    void process_ring_buffer(std::vector<bucket_s<T>>& buckets) {
        ANP_LOG_VERBOSE("write-index: %lu, count: %lu, size: %lu, rollover: %lu",
                        write_index_, count_, size_, rollover_count_);
        for (size_t i = 0; i < count_; ++i) {
            T entry = buffer_[i];
            int bucket_index = find_bucket_index(buckets, entry);
            buckets[bucket_index].count++;
        }
    }

    // function to find the appropriate bucket index for a given value
    int find_bucket_index(const std::vector<bucket_s<T>>& buckets, const T& value) {
        for (size_t i = 0; i < buckets.size(); ++i) {
             if (buckets[i].contains(value)) {
                return i;
            }
        }
        // handle cases where value is outside the defined buckets (e.g., last bucket is inclusive)
        return buckets.size() - 1;
    }

    void generate_histogram(std::vector<bucket_s<T>>& buckets) {
        std::vector<T> data = get_values();
        if (data.empty()) {
            ANP_LOG_VERBOSE("No data to process");
            return;
        }

        T min_val = *std::min_element(data.begin(), data.end());
        T max_val = *std::max_element(data.begin(), data.end());
        ANP_LOG_VERBOSE("num_entries %lu, min %lu, max %lu", data.size(), min_val, max_val);

        int num_buckets = std::ceil(std::sqrt(data.size()));
        ANP_LOG_VERBOSE("num_buckets %d", num_buckets);

        if (num_buckets <= 0) {
            ANP_LOG_ERROR("Histogram num_buckets(%d) must be > 0", num_buckets);
            return;
        }
        if (min_val >= max_val) {
            ANP_LOG_ERROR("Invalid range: min (%lu) must be < max (%lu)", min_val, max_val);
            return;
        }

        // create histogram with uniform buckets from min to max of data
        auto h = boost::histogram::make_histogram(
                     boost::histogram::axis::regular<double>(num_buckets, (double)min_val, (double)max_val+1));

        // fill histogram with data
        for (auto value : data) {
            h(value);
        }

        // populate histogram
        ANP_LOG_VERBOSE("Histogram:");
        for (auto&& bin : boost::histogram::indexed(h)) {
            ANP_LOG_VERBOSE("[%lu-%lu]: %lu counts", static_cast<T>(bin.bin(0).lower()),
                            static_cast<T>(bin.bin(0).upper()), static_cast<T>(*bin));
            bucket_s<T> entry;
            entry.min = static_cast<T>(bin.bin(0).lower());
            entry.max = static_cast<T>(bin.bin(0).upper());
            entry.count = static_cast<size_t>(*bin);
            buckets.push_back(entry);
        }
    }

private:
    size_t size_;
    size_t count_;
    size_t write_index_;
    size_t rollover_count_;
    std::vector<T> buffer_;
};

class time_histogram_s {
public:
    time_histogram_s(int max_buckets, uint32_t bucket_sz_log2)
        : max_buckets(max_buckets),
          bucket_sz_log2(bucket_sz_log2) {}

    void log_time(const uint64_t& time) {
        // round to nearest bucket
        // for entries falling beyond max_buckets, add entry in last bucket
        uint64_t bucket_index = (uint64_t) time >> bucket_sz_log2;
        bucket_index = (bucket_index < max_buckets) ?
                            bucket_index : (max_buckets - 1);
        buckets[bucket_index]++;
    }

    void print_histogram() {
        ANP_LOG_VERBOSE("Histogram:");
        for (const auto& entry : buckets) {
            ANP_LOG_VERBOSE("[%lu-%lu]: %lu counts",
                            entry.first << bucket_sz_log2,
                            (((entry.first + 1) << bucket_sz_log2) - 1),
                            entry.second);
        }
    }

public:
    uint32_t bucket_sz_log2;
    int max_buckets;
    std::unordered_map<uint64_t, size_t> buckets;
};

#endif
