/**
 * @mebeim - 2025-05-21
 */
#include <iostream>
#include <string>

#include "BigInt.h"
#include "Calculator.h"

int main(void) {
	std::string line;
	Calculator calc;
	const BigInt *res;

	std::cout << std::unitbuf;

	while (1) {
		std::cout << "> ";
		if (!std::getline(std::cin, line))
			break;

		try {
			res = calc.eval(line);
		} catch (const std::invalid_argument &e) {
			std::cout << e.what() << std::endl;
			return 1;
		}

		if (res) {
			std::cout << *res << std::endl;
			delete res;
		}
	}

	return 0;
}
