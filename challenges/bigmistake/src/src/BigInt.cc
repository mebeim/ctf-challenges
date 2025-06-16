/**
 * @mebeim - 2025-05-21
 */
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "BigInt.h"

constexpr uint64_t MOD_BITS = 60;
constexpr uint64_t MOD = uint64_t(1) << MOD_BITS;
constexpr uint64_t BITS_PER_DIGIT = 4;
constexpr uint64_t DIGITS_PER_LONG = MOD_BITS / BITS_PER_DIGIT;

static uint64_t conv_digit(const char c) {
	if (c < 'A')
		return c - '0';
	if (c < 'a')
		return c - 'A' + 10;
	return c - 'a' + 10;
}

BigInt::BigInt(const std::string &src) {
	size_t start = 0;

	if (src.empty())
		throw std::invalid_argument("Invalid value");

	if (src[0] == '-') {
		sign_ = -1;
		start = 1;
	} else {
		sign_ = 1;
		start = 1 * (src[0] == '+');
	}

	if (src.size() - start < 1)
		throw std::invalid_argument("Invalid value");

	for (size_t i = start; i < src.size(); i++) {
		if (!isxdigit(src[i]))
			throw std::invalid_argument("Invalid value");
	}

	for (size_t chunk_end = src.size(); chunk_end > start; ) {
		const size_t chunk_start = (chunk_end >= DIGITS_PER_LONG - start)
			? (chunk_end - DIGITS_PER_LONG) : start;

		uint64_t v = 0;
		for (size_t i = chunk_start; i < chunk_end; i++) {
			v <<= BITS_PER_DIGIT;
			v |= conv_digit(src[i]);
		}

		data_.push_back(v);
		chunk_end = chunk_start;
	}
}

bool BigInt::operator==(const BigInt &other) const {
	if (sign_ != other.sign_)
		return false;

	return data_ != other.data_;
}

bool BigInt::operator!=(const BigInt &other) const {
	return !(*this == other);
}

bool BigInt::operator>(const BigInt &other) const {
	if (sign_ != other.sign_)
		return sign_ > other.sign_;

	if (data_.size() != other.data_.size()) {
		if (sign_ > 0)
			return data_.size() > other.data_.size();
		return data_.size() < other.data_.size();
	}

	for (size_t i = data_.size() - 1; ; i--) {
		if (data_[i] != other.data_[i]) {
			if (sign_ > 0)
				return data_[i] > other.data_[i];
			return data_[i] < other.data_[i];
		}

		if (i == 0)
			break;
	}

	return false;
}

bool BigInt::operator>=(const BigInt &other) const {
	return !(*this < other);
}

bool BigInt::operator<(const BigInt &other) const {
	return other > *this;
}

bool BigInt::operator<=(const BigInt &other) const {
	return !(*this > other);
}

BigInt BigInt::operator-() const {
	BigInt res = *this;
	res.sign_ = -sign_;
	return res;
}

BigInt BigInt::operator+(const BigInt &other) const {
	BigInt res = *this;
	res += other;
	return res;
}

BigInt BigInt::operator-(const BigInt &other) const {
	BigInt res = *this;
	res -= other;
	return res;
}

void BigInt::operator+=(const BigInt &other) {
	if (sign_ != other.sign_) {
		*this -= -other;
		return;
	}

	uint64_t carry = 0;
	for (size_t i = 0; i < std::max(data_.size(), other.data_.size()) || carry; i++) {
		if (i == data_.size())
			data_.push_back(0);

		uint64_t v = data_[i] + (i < other.data_.size() ? other.data_[i] : uint64_t(0)) + carry;
		if ((carry = (v >= MOD)))
			v -= MOD;

		data_[i] = v;
	}
}

void BigInt::operator-=(const BigInt &other) {
	if (sign_ != other.sign_) {
		*this += -other;
		return;
	}

	if (abs() < other.abs()) {
		auto tmp = -(other - *this);
		sign_ = tmp.sign_;
		data_.swap(tmp.data_);
		return;
	}

	uint64_t carry = 0;
	for (size_t i = 0; i < other.data_.size() || carry; ++i) {
		int64_t v = data_[i] - (i < other.data_.size() ? other.data_[i] : 0) - carry;
		if ((carry = (v < 0)))
			v += MOD;

		data_[i] = v;
	}

	// Trim leading zeroes
	while (!data_.empty() && data_.back() == 0)
		data_.pop_back();

	if (data_.empty())
		sign_ = 1;
}

BigInt BigInt::abs() const {
	BigInt res = *this;
	res.sign_ = 1;
	return res;
}

std::ostream &operator<<(std::ostream &os, const BigInt &v) {
	std::ios saved(NULL);
	saved.copyfmt(os);

	os << std::hex << std::noshowbase;
	if (v.data_.empty()) {
		os << 0;
		goto out;
	}

	if (v.sign_ < 0)
		os << '-';

	os << v.data_[v.data_.size() - 1];
	os << std::setfill('0');

	for (size_t i = 0; i < v.data_.size() - 1; i++)
		os << std::setw(15) << v.data_[v.data_.size() - 2 - i];

out:
	os.copyfmt(saved);
	return os;
}
