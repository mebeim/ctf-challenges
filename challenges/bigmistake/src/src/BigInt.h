/**
 * @mebeim - 2025-05-21
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

class BigInt {
	int sign_;
	std::vector<uint64_t> data_;

public:
	BigInt() : sign_(1) {};
	BigInt(const std::string &src);

	bool operator==(const BigInt &other) const;
	bool operator!=(const BigInt &other) const;
	bool operator>(const BigInt &other) const;
	bool operator>=(const BigInt &other) const;
	bool operator<(const BigInt &other) const;
	bool operator<=(const BigInt &other) const;
	BigInt operator+(const BigInt &other) const;
	BigInt operator-(const BigInt &other) const;
	void operator+=(const BigInt &other);
	void operator-=(const BigInt &other);
	BigInt operator-() const;

	BigInt abs() const;

	friend std::ostream &operator<<(std::ostream &os, const BigInt &v);
};
