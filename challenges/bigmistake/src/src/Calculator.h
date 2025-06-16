/**
 * @mebeim - 2025-05-21
 */
#pragma once

#include <deque>
#include <string>
#include <unordered_map>

#include "BigInt.h"

class Calculator {
	std::unordered_map<std::string,BigInt *> vars_;

	bool eval_one(const std::string &v, BigInt *&out) const;
	BigInt *eval_expr(const std::deque<std::string> &expr) const;
	void eval_assign(std::deque<std::string> &stmt);
public:
	BigInt *eval(const std::string &stmt);
};
