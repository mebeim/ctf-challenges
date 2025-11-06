#
# @mebeim - 2025-09-07
#
extends AudioStreamPlayer2D

const sounds = [
	preload("res://assets/background_beat01.wav"),
	preload("res://assets/background_beat02.wav")
]

# Chosen by game logic, increases with number of asteroids on screen
@export var interval_seconds = 1.0
var sound_idx = 0
var done = false

func play_sound():
	if done:
		return

	stream = sounds[sound_idx]
	await get_tree().create_timer(interval_seconds).timeout
	if done:
		return

	play()

func stop_playing() -> void:
	stop()
	done = true

func _ready() -> void:
	play_sound()

func _on_finished() -> void:
	sound_idx = (sound_idx + 1) % sounds.size()
	play_sound()
