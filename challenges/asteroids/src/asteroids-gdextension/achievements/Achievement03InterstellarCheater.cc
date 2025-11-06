/**
 * @mebeim - 2025-09-07
 */
#include <cassert>

#include "Achievement03InterstellarCheater.h"

#include <godot_cpp/classes/input_event.hpp>
#include <godot_cpp/classes/input_event_key.hpp>
#include <godot_cpp/classes/os.hpp>

using namespace asteroids;

static_assert(godot::Key::KEY_A == 'A');

godot::String Achievement03InterstellarCheater::get_name() const {
	return godot::String("INTERSTELLAR CHEATER");
}

void Achievement03InterstellarCheater::_input(const godot::Ref<godot::InputEvent> &p_event) {
	if (achieved_)
		return;

	if (!p_event.is_valid() || !p_event->is_pressed() || p_event->is_echo() || !p_event->is_class("InputEventKey"))
		return;

	const godot::Ref<godot::InputEventKey> key_event = static_cast<godot::Ref<godot::InputEventKey>>(p_event);
	const godot::Key keycode = key_event->get_keycode();
	if (keycode < godot::Key::KEY_A || keycode > godot::Key::KEY_Z)
		return;

	if (CODE[index_] != (char)keycode) {
		index_ = 0;
		return;
	}

	if (++index_ != sizeof(CODE))
		return;

	achieve(KEY, sizeof(KEY));
}
