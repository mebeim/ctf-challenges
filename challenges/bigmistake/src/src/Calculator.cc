/**
 * @mebeim - 2025-05-21
 */
#include <deque>
#include <iostream>
#include <stdexcept>
#include <string>

#include "Calculator.h"

static std::deque<std::string> str_split(const std::string &s) {
	std::deque<std::string> res;
	size_t start = 0;
	size_t end = 0;

	while ((end = s.find(' ', start)) != std::string::npos) {
		if (start == end) {
			start++;
			continue;
		}

		res.push_back(s.substr(start, end - start));
		start = end + 1;
	}

	if (start != s.size())
		res.push_back(s.substr(start));

	return res;
}

bool Calculator::eval_one(const std::string &v, BigInt *&out) const {
	const auto it = vars_.find(v);
	if (it != vars_.end()) {
		out = it->second;
		return true;
	}

	out = new BigInt(v);
	return false;
}

BigInt *Calculator::eval_expr(const std::deque<std::string> &expr) const {
	BigInt *res = nullptr;
	BigInt *first;

	/* BUG: here we can either get a pointer to a temporary value created by
	 * eval_one() (if the name is not found in our vars_), or a pointer to an
	 * existing BigInt, which is directly returned to the caller without
	 * performing a copy. The caller has no information to discern between the
	 * two cases and will always free returned objects treating them as
	 * temporaries, leaving us with a stale pointer in vars_, leading to UAF if
	 * used later.
	 */
	eval_one(expr[0], first);
	if (expr.size() == 1)
		return first;

	res = new BigInt(*first);

	for (size_t i = 2; i < expr.size(); i += 2) {
		const auto op = expr[i - 1];
		BigInt *v;

		const bool found = eval_one(expr[i], v);

		if (op == "+")
			*res = *res + *v;
		else if (op == "-")
			*res = *res - *v;

		if (!found)
			delete v;
	}

	return res;
}

void Calculator::eval_assign(std::deque<std::string> &stmt) {
	const auto name = stmt[0];
	const auto op = stmt[1];

	stmt.pop_front();
	stmt.pop_front();

	const auto rhs = eval_expr(stmt);
	auto &lhs = vars_[name];
	if (lhs == nullptr)
		lhs = new BigInt();

	if (op == "=")
		*lhs = *rhs;
	else if (op == "+=")
		*lhs += *rhs;
	else
		*lhs -= *rhs;
}

BigInt *Calculator::eval(const std::string &stmt) {
	BigInt *res = nullptr;

	std::deque<std::string> q = str_split(stmt);
	if (q.empty())
		goto out;

	if (q.size() % 2 == 0)
		throw std::invalid_argument("Invalid statement");

	if (q.size() >= 3) {
		const auto op = q[1];

		if (op == "=" || op == "+=" || op == "-=") {
			eval_assign(q);
			goto out;
		}
	}

	res = eval_expr(q);
out:
	return res;
}
