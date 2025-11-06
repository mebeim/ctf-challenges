#
# @mebeim - 2025-09-07
#
extends Control

@onready var achievement_popup_scene = preload("res://scenes/achievement_popup.tscn")

@onready var score = $Score:
	set(val):
		score.text = str(val)

@onready var asteroids_exploded = $AsteroidsExploded:
	set(val):
		asteroids_exploded.text = str(val)

@onready var progress = $Progress:
	set(val):
		progress.text = str(int(val * 100)) + "%"

@onready var flag = $Flag

func flash_new_achievement(achievement_name: String) -> void:
	var popup = achievement_popup_scene.instantiate()
	add_child(popup)
	popup.achievement_name = achievement_name

func _ready() -> void:
	# Apparently shader params do not get reset on scene reload
	flag.material.set_shader_parameter("min_alpha", 0.3)
	flag.material.set_shader_parameter("max_alpha", 1.0)
	flag.material.set_shader_parameter("wave", 0.0)

func _on_game_game_over(win: bool) -> void:
	if win:
		flag.material.set_shader_parameter("min_alpha", 1.0)
		flag.material.set_shader_parameter("wave", 1.0)
	else:
		flag.material.set_shader_parameter("max_alpha", 0.3)
