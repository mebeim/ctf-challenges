#
# @mebeim - 2025-09-07
#
extends Control

@onready var subtitle = $GameOverSubtitle
@onready var lose_sound = $Sounds/GameOverLose
@onready var win_sound = $Sounds/GameOverWin

func _on_game_game_over(win: bool) -> void:
	if win:
		subtitle.text = 'MISSION:  COMPLETE'
		subtitle.label_settings.font_color = Color('#29fe33')
	else:
		subtitle.text = 'MISSION:  FAILED'
		subtitle.label_settings.font_color = Color('#e2381e')

	await get_tree().create_timer(1).timeout
	visible = true

	if win:
		win_sound.play()
	else:
		lose_sound.play()

func _on_play_again_button_pressed() -> void:
	get_tree().reload_current_scene()
