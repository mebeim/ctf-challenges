/**
 * @mebeim - 2025-09-07
 */
#include "Achievement07WarpSpeed.h"

using namespace asteroids;

godot::String Achievement07WarpSpeed::get_name() const {
	return godot::String("WARP SPEED");
}

void Achievement07WarpSpeed::_ready() {
	player_ = get_node_or_null("/root/Game/Player");
}

void Achievement07WarpSpeed::_physics_process(double delta) {
	if (achieved_)
		return;

	// Should never happen unless we fuck up the node path in _ready()
	if (!player_)
		return;

	// This is safe as Variant will auto-cast to a default-constructed Vector2
	// (i.e. Vector2.ZERO) if the property is not a Vector2.
	const godot::Vector2 velocity = player_->get("velocity");
	if (velocity.length() < TARGET) {
		elapsed_time_ = 0;
		return;
	}

	elapsed_time_ += delta;
	if (elapsed_time_ < TIME)
		return;

	achieve(KEY, sizeof(KEY));
}
