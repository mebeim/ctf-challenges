/**
 * @mebeim - 2025-09-07
 */
#include "AchievementManager.h"
#include "achievements/Achievement.h"
#include "achievements/all.h"

#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/core/print_string.hpp>

#define ADD_ACHIEVEMENT(cls) \
	do { \
		Achievement *a = memnew(cls()); \
		a->connect("achieved", godot::Callable(this, "_on_achievement_achieved")); \
		add_child(a); \
	} while (0)

using namespace asteroids;

void AchievementManager::_bind_methods() {
	godot::ClassDB::bind_method(godot::D_METHOD("_on_achievement_achieved", "name", "value"), &AchievementManager::_on_achievement_achieved);
	godot::ClassDB::bind_method(godot::D_METHOD("update_score", "new_score"), &AchievementManager::update_score);
	ADD_SIGNAL(godot::MethodInfo("achievement_achieved",
		godot::PropertyInfo(godot::Variant::STRING, "name"),
		godot::PropertyInfo(godot::Variant::STRING, "value")));
}

void AchievementManager::_ready() {
	ADD_ACHIEVEMENT(Achievement01AsteroidSmasher);
	ADD_ACHIEVEMENT(Achievement02AsteroidAnnihilator);
	ADD_ACHIEVEMENT(Achievement03InterstellarCheater);
	ADD_ACHIEVEMENT(Achievement04InterstellarHacker);
	ADD_ACHIEVEMENT(Achievement05RookieNumbers);
	ADD_ACHIEVEMENT(Achievement06Sharpshooter);
	ADD_ACHIEVEMENT(Achievement07WarpSpeed);
	ADD_ACHIEVEMENT(Achievement08Survivor);
	ADD_ACHIEVEMENT(Achievement09Immortal);
}

void AchievementManager::_on_achievement_achieved(godot::String name, godot::String value) {
	// Propagate any achievement signal up
	emit_signal("achievement_achieved", name, value);
}

void AchievementManager::update_score(int new_score) {
	for (const auto &child : get_children()) {
		Achievement *a = Object::cast_to<Achievement>(child);
		if (!a)
			continue;

		a->update_score(new_score);
	}
}
