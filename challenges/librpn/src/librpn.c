/*
 * @mebeim - 2025-06-07
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct Function {
	struct Function *next;
	char *name;
	int64_t *stack;
	size_t n_params;
	char **param_names;
	size_t expr_len;
	char **expr;
};

enum Error {
	ERR_STACK_UNDERFLOW   = -1,
	ERR_DIV_ZERO          = -2,
	ERR_BAD_FUNCTION_NAME = -3,
	ERR_BAD_PARAM_NAME    = -4,
	ERR_BAD_FUNCTION_CALL = -5
};

static struct Function *functions = NULL;

static size_t null_terminated_arr_length(char **arr) {
	size_t len;

	for (len = 0; arr[len]; len++)
		;

	return len;
}

static struct Function *find_function(const char *name) {
	struct Function *fn = functions;

	while (fn) {
		if (!strcmp(fn->name, name))
			return fn;

		fn = fn->next;
	}

	return NULL;
}

static void add_function(const char *name, char **param_names, char **expr) {
	struct Function *fn = calloc(1, sizeof *fn);
	if (!fn)
		errx(1, "Memory allocation failure");

	fn->name = strdup(name);
	if (!fn->name)
		errx(1, "Memory allocation failure");

	fn->n_params = null_terminated_arr_length(param_names);

	if (fn->n_params) {
		fn->param_names = calloc(fn->n_params, sizeof(*fn->param_names));
		if (!fn->param_names)
			errx(1, "Memory allocation failure");

		for (size_t i = 0; i < fn->n_params; i++) {
			fn->param_names[i] = strdup(param_names[i]);
			if (!fn->param_names[i])
				errx(1, "Memory allocation failure");
		}
	}

	fn->expr_len = null_terminated_arr_length(expr);
	fn->expr = calloc(fn->expr_len, sizeof(*fn->expr));
	if (!fn->expr)
		errx(1, "Memory allocation failure");

	size_t stack_len = 0;
	size_t max_stack_len = 0;

	for (size_t i = 0; i < fn->expr_len; i++) {
		char *token = expr[i];

		if (isdigit(token[0])) {
			// Number
			stack_len++;
		} else {
			/*
			 * BUG: An Operator token pops from the stack, but a Parameter token
			 * has the same effect as a Number and pushes a value. The stack
			 * size should be incremented in such case. Counting parameters like
			 * this, we will end up with a smaller stack than needed, causing
			 * prolems later since there is no bound checking when the function
			 * gets evaluated.
			 */
			if (stack_len > 0)
				stack_len--;
		}

		if (stack_len > max_stack_len)
			max_stack_len = stack_len;

		fn->expr[i] = strdup(token);
		if (!fn->expr[i])
			errx(1, "Memory allocation failure");
	}

	fn->stack = calloc(max_stack_len, sizeof(*fn->stack));
	if (!fn->stack)
		errx(1, "Memory allocation failure");

	fn->next = functions;
	functions = fn;
}

static void del_funcion(const char *name) {
	struct Function *fn = functions;
	struct Function *prev = NULL;

	while (fn) {
		if (strcmp(fn->name, name) == 0) {
			if (prev)
				prev->next = fn->next;
			else
				functions = fn->next;

			for (size_t i = 0; i < fn->expr_len; i++)
				free(fn->expr[i]);

			if (fn->expr)
				free(fn->expr);

			for (size_t i = 0; i < fn->n_params; i++)
				free(fn->param_names[i]);

			if (fn->param_names)
				free(fn->param_names);

			free(fn->name);
			free(fn);
			return;
		}

		prev = fn;
		fn = fn->next;
	}
}

static const int64_t *get_param(const struct Function *fn, const int64_t *param_values, const char *param_name) {
	for (size_t i = 0; i < fn->n_params; i++) {
		if (!strcmp(fn->param_names[i], param_name))
			return param_values + i;
	}

	return NULL;
}

static int call_function(const struct Function *fn, const int64_t *param_values, int64_t *out) {
	int res = 0;
	size_t sp = 0;
	int64_t *stack = fn->stack;

	for (size_t i = 0; i < fn->expr_len; i++) {
		char *token = fn->expr[i];

		switch (token[0]) {
		case '+':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] += stack[sp - 1];
			sp--;
			continue;

		case '-':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] -= stack[sp - 1];
			sp--;
			continue;

		case '*':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] *= stack[sp - 1];
			sp--;
			continue;

		case '/':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			// Division by zero check
			if (stack[sp - 1] == 0) {
				res = ERR_DIV_ZERO;
				goto err;
			}

			stack[sp - 2] /= stack[sp - 1];
			sp--;
			continue;
		}

		// Number
		if (isdigit(token[0])) {
			stack[sp++] = strtoll(token, NULL, 10);
			continue;
		}

		// Parameter
		const int64_t *p = get_param(fn, param_values, token);
		if (!p) {
			res = ERR_BAD_PARAM_NAME;
			goto err;
		}

		stack[sp++] = *p;
	}

	if (sp < 1) {
		res = ERR_STACK_UNDERFLOW;
		goto err;
	}

	*out = stack[sp - 1];

err:
	return res;
}

int create_function(const char *name, char **param_names, char **expr) {
	del_funcion(name);
	add_function(name, param_names, expr);
	return 0;
}

int eval_expression(char **expr, int64_t *out) {
	int res = 0;
	size_t sp = 0;
	size_t stack_len = 256;
	int64_t *tmp;

	int64_t *stack = calloc(stack_len, sizeof(*stack));
	if (!stack)
		errx(1, "Memory allocation failure");

	for (size_t i = 0; expr[i]; i++) {
		char *token = expr[i];

		switch (token[0]) {
		case '+':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] += stack[sp - 1];
			sp--;
			continue;

		case '-':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] -= stack[sp - 1];
			sp--;
			continue;

		case '*':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			stack[sp - 2] *= stack[sp - 1];
			sp--;
			continue;

		case '/':
			if (sp < 2) {
				res = ERR_STACK_UNDERFLOW;
				goto err;
			}

			// Division by zero check
			if (stack[sp - 1] == 0) {
				res = ERR_DIV_ZERO;
				goto err;
			}

			stack[sp - 2] /= stack[sp - 1];
			sp--;
			continue;
		}

		if (sp >= stack_len) {
			stack_len *= 2;
			tmp = calloc(stack_len, sizeof(*stack));
			if (!tmp)
				errx(1, "Memory allocation failure");

			stack = tmp;
			free(stack);
		}

		// Number
		if (isdigit(token[0])) {
			stack[sp++] = strtoll(token, NULL, 10);
			continue;
		}

		// Function call
		struct Function *fn = find_function(token);
		if (!fn) {
			res = ERR_BAD_FUNCTION_NAME;
			goto err;
		}

		if (sp < fn->n_params) {
			res = ERR_BAD_FUNCTION_CALL;
			goto err;
		}

		int64_t *param_values = &stack[sp - fn->n_params];
		res = call_function(fn, param_values, &stack[sp++]);
		if (res < 0)
			goto err;
	}

	if (sp < 1) {
		res = ERR_STACK_UNDERFLOW;
		goto err;
	}

	*out = stack[sp - 1];

err:
	free(stack);
	return res;
}
