/**
 * @mebeim - 2025-09-07
 */
#pragma once

#include "achievements/Achievement.h"

#include <godot_cpp/classes/node.hpp>

namespace asteroids {

class AchievementManager : public godot::Node {
	GDCLASS(AchievementManager, godot::Node)

protected:
	static void _bind_methods();

public:
	void _ready() override;
	void _on_achievement_achieved(godot::String name, godot::String value);
	void update_score(int new_score);
};

}
