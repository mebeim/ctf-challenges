/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "Achievement.h"
#include "Achievement04InterstellarHacker_params.h"

#include <godot_cpp/classes/input_event.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/core/class_db.hpp>

namespace asteroids {

class Achievement04InterstellarHacker : public Achievement {
	GDCLASS(Achievement04InterstellarHacker, Achievement)

private:
	void achieve(const uint8_t *key, size_t key_len) override;
	static constexpr char NAME[] = "INTERSTELLAR HACKER";
	static constexpr size_t CODE_LEN = CHEAT_CODE_HARD_LEN;
	static constexpr uint8_t SHA1[] = CHEAT_CODE_HARD_SHA1;
	godot::String buffer_;

protected:
	static void _bind_methods() {};

public:
	godot::String get_name() const override;
	void _input(const godot::Ref<godot::InputEvent> &p_event) override;
};

}
