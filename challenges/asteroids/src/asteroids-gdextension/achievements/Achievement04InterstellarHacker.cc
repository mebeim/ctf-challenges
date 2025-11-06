/**
 * @mebeim - 2025-09-07
 */
#include "Achievement04InterstellarHacker.h"

#include <godot_cpp/classes/input_event.hpp>
#include <godot_cpp/classes/input_event_key.hpp>
#include <godot_cpp/classes/os.hpp>

using namespace asteroids;

godot::String Achievement04InterstellarHacker::get_name() const {
	return godot::String("INTERSTELLAR HACKER");
}

void Achievement04InterstellarHacker::_input(const godot::Ref<godot::InputEvent> &p_event) {
	if (achieved_)
		return;

	if (!p_event.is_valid() || !p_event->is_pressed() || p_event->is_echo() || !p_event->is_class("InputEventKey"))
		return;

	const godot::Ref<godot::InputEventKey> key_event = static_cast<godot::Ref<godot::InputEventKey>>(p_event);
	const godot::Key keycode = key_event->get_keycode();
	if (keycode < godot::Key::KEY_A || keycode > godot::Key::KEY_Z)
		return;

	// Only keep last kCheatCodeLength chars
	if (buffer_.length() == CODE_LEN)
		buffer_ = buffer_.substr(1);

	buffer_ += godot::OS::get_singleton()->get_keycode_string(keycode);
	if (buffer_.length() != CODE_LEN)
		return;

	auto digest = buffer_.sha1_buffer();
	if (memcmp(digest.ptr(), SHA1, digest.size()) != 0)
		return;

	digest = buffer_.sha256_buffer();
	achieve(digest.ptr(), digest.size());
}
