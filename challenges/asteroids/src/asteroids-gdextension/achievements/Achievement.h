/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <godot_cpp/classes/node.hpp>
#include <godot_cpp/variant/string.hpp>

namespace asteroids {

class Achievement : public godot::Node {
	GDCLASS(Achievement, godot::Node)

private:
	virtual void achieve(const uint8_t *key, size_t key_len) {};

protected:
	static void _bind_methods();
	bool achieved_ = false;

public:
	virtual godot::String get_name() const { return godot::String("<UNNAMED>"); };
	virtual void update_score(int new_score) {};
};

}
