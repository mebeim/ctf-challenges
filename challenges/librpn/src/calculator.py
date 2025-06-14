#!/usr/bin/env python3
#
# @mebeim - 2025-06-07
#

from collections import deque
from ctypes import CDLL, c_char_p, c_int, c_int64, byref, POINTER
from enum import Enum


librpn = CDLL('./librpn.so')
librpn.create_function.argtypes = [c_char_p, POINTER(c_char_p), POINTER(c_char_p)]
librpn.create_function.restype  = c_int
librpn.eval_expression.argtypes = [POINTER(c_char_p), POINTER(c_int64)]
librpn.eval_expression.restype  = c_int


class ParseError(Exception):
	pass


class EvalError(Exception):
	pass


class Token:
	pass


class Op(Token, Enum):
	PLUS     = '+'
	MINUS    = '-'
	MULTIPLY = '*'
	DIVIDE   = '/'
	MOD      = '%'

	def precedence(self):
		if self in (self.PLUS, self.MINUS):
			return 1
		elif self in (self.MULTIPLY, self.DIVIDE, self.MOD):
			return 2
		return -1


class Delimiter(Token, Enum):
	LPAREN = '('
	RPAREN = ')'
	LBRACE = '{'
	RBRACE = '}'
	COMMA  = ','


class Keyword(Token, Enum):
	FUNCTION = 'fn'


class Number(Token):
	def __init__(self, value: str):
		self.value = value


class Name(Token):
	def __init__(self, value: str):
		self.value = value


class Parameter(Name):
	pass


class Function(Name):
	def precedence(self):
		return 3


FUNCTIONS: set[str] = set()


def tokenize(stmt: str) -> deque[Token]:
	tokens: deque[Token] = deque()
	q = deque(stmt)

	while q:
		char = q.popleft()
		if char.isspace():
			continue

		if char in '+-*/%':
			tokens.append(Op(char))
			continue

		if char in '(){},':
			tokens.append(Delimiter(char))
			continue

		if char.isdigit():
			value = char

			while q and q[0].isdigit():
				value += q.popleft()

			tokens.append(Number(value))
			continue

		if char.isalpha():
			name = char
			while q and q[0].isalpha():
				name += q.popleft()

			if name == 'fn':
				tokens.append(Keyword(name))
			else:
				tokens.append(Name(name))
			continue

		raise ParseError(f'Bad character in input: {char!r}')

	return tokens


def validate_expression(tokens: deque, is_function: bool) -> bool:
	if not tokens:
		return False

	it = iter(tokens)
	pprev = None
	prev = next(it)

	if len(tokens) == 1:
		return isinstance(prev, Number) or is_function and isinstance(prev, Name)

	if isinstance(prev, Op) or prev in (Delimiter.RPAREN, Delimiter.COMMA):
		return False

	for cur in it:
		if cur == Delimiter.RPAREN and prev == Delimiter.LPAREN:
			if is_function or not isinstance(pprev, Name):
				return False

		match prev:
			case Number() | Delimiter.RPAREN:
				if not isinstance(cur, Op) and cur not in (Delimiter.RPAREN, Delimiter.COMMA):
					return False

			case Name():
				if is_function:
					if not isinstance(cur, Op) and cur not in (Delimiter.RPAREN, Delimiter.COMMA):
						return False
				else:
					if cur != Delimiter.LPAREN:
						return False

			case Op():
				if not isinstance(cur, (Number, Name)) and cur != Delimiter.LPAREN:
					return False

			case Delimiter.LPAREN:
				if not isinstance(cur, (Number, Name)) and cur not in (Delimiter.LPAREN, Delimiter.RPAREN):
					return False

			case Delimiter.COMMA:
				if not isinstance(cur, (Number, Name)) and cur != Delimiter.LPAREN:
					return False

			case _:
				return False

		pprev = prev
		prev = cur

	if is_function:
		return isinstance(cur, (Number, Name)) or cur == Delimiter.RPAREN
	return isinstance(cur, Number) or cur == Delimiter.RPAREN


def parse_expression(tokens: deque, is_function: bool) -> list[Token]:
	op_stack: deque[Op|Function|Delimiter] = deque()
	expr = []

	if not validate_expression(tokens, is_function):
		raise ParseError('Invalid expression')

	while tokens:
		cur = tokens.popleft()

		match cur:
			case Number():
				expr.append(cur)

			case Name():
				if is_function:
					expr.append(Parameter(cur.value))
				else:
					name = cur.value
					if name not in FUNCTIONS:
						raise ParseError(f'Undefined function: {name}')

					op_stack.append(Function(name))

			case Op():
				while op_stack:
					top = op_stack[-1]
					if top == Delimiter.LPAREN or top.precedence() < cur.precedence():
						break

					expr.append(op_stack.pop())

				op_stack.append(cur)

			case Delimiter.LPAREN:
				op_stack.append(cur)

			case Delimiter.RPAREN:
				while op_stack and op_stack[-1] != Delimiter.LPAREN:
					expr.append(op_stack.pop())

				if not op_stack or op_stack[-1] != Delimiter.LPAREN:
					raise ParseError('Mismatched parentheses in expression')

				op_stack.pop()

				if op_stack and isinstance(op_stack[-1], Function):
					expr.append(op_stack.pop())

			case Delimiter.COMMA:
				while op_stack and op_stack[-1] != Delimiter.LPAREN:
					expr.append(op_stack.pop())

				if not op_stack or op_stack[-1] != Delimiter.LPAREN:
					raise ParseError('Missing or mismatched parentheses in function invocation')

			case _:
				raise ParseError(f'Unexpected token in expression: {cur}')

	if Delimiter.LPAREN in op_stack:
		raise ParseError('Mismatched parentheses in expression')

	expr.extend(reversed(op_stack))
	return expr


def parse_function_def(tokens: deque):
	if not tokens:
		raise ParseError('Expected function name after "fn" keyword')

	name = tokens.popleft()
	if not isinstance(name, Name):
		raise ParseError('Expected function name after "fn" keyword')

	if not tokens or tokens.popleft() != Delimiter.LPAREN:
		raise ParseError('Expected parameter list after function name')

	params = []
	param_tokens = []

	while tokens and (cur := tokens.popleft()) != Delimiter.RPAREN:
		param_tokens.append(cur)

	if cur != Delimiter.RPAREN:
		raise ParseError('Unterminated function parameter list')

	if param_tokens and len(param_tokens) % 2 == 0:
		raise ParseError('Invalid function parameter list')

	for i in range(1, len(param_tokens), 2):
		if param_tokens[i] != Delimiter.COMMA:
			raise ParseError('Invalid function parameter list')

	for i in range(0, len(param_tokens), 2):
		if not isinstance(param_tokens[i], Name):
			raise ParseError('Invalid function parameter list')

		params.append(param_tokens[i].value)

	if len(set(params)) != len(params):
		raise ParseError('Duplicated name in function parameter list')

	if not tokens or tokens.popleft() != Delimiter.LBRACE:
		raise ParseError('Expected function body after parameter list')

	if not tokens or tokens[-1] != Delimiter.RBRACE:
		raise ParseError('Unterminated function body')

	tokens.pop()
	if not tokens:
		raise ParseError('Empty function body')

	return name.value, params, parse_expression(tokens, True)


def librpn_create_function(name: str, params: list[str], expr: list[Token]) -> None:
	c_params = (c_char_p * (len(params) + 1))()
	c_expr = (c_char_p * (len(expr) + 1))()

	for i, param in enumerate(params):
		c_params[i] = param.encode()

	for i, token in enumerate(expr):
		c_expr[i] = token.value.encode()

	c_params[len(params)] = None
	c_expr[len(expr)] = None

	res = librpn.create_function(c_char_p(name.encode()), c_params, c_expr)
	if res != 0:
		raise EvalError(f'Failed to create function: error {res}')

	FUNCTIONS.add(name)


def librpn_eval_expression(expr: list[Token]) -> int:
	c_expr = (c_char_p * (len(expr) + 1))()
	c_result = c_int64()

	for i, token in enumerate(expr):
		c_expr[i] = token.value.encode()

	c_expr[len(expr)] = None

	res = librpn.eval_expression(c_expr, byref(c_result))
	if res != 0:
		raise EvalError(f'Failed to evaluate expression: error {res}')

	return c_result.value


def eval_stmt(stmt: str) -> int|None:
	try:
		tokens = tokenize(stmt)
		if not tokens:
			return

		if tokens[0] == Keyword.FUNCTION:
			tokens.popleft()
			args = parse_function_def(tokens)
			fn = librpn_create_function
		else:
			args = (parse_expression(tokens, False),)
			fn = librpn_eval_expression
	except ParseError as e:
		print(f'Parsing error: {e}')
		return None

	try:
		res = fn(*args)
	except EvalError as e:
		print(f'Eval error in {fn}: {e}')
		return None

	return res


def main():
	while 1:
		stmt = input('> ').strip()

		res = eval_stmt(stmt)
		if res is not None:
			print(res)


if __name__ == '__main__':
	main()
