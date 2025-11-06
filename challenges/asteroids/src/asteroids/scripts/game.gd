#
# @mebeim - 2025-09-07
#
extends Node2D

signal game_over(win: bool);

# Interval between each asteroid spawn in seconds
const ASTEROID_SPAWN_INTERVAL_MAX = 10.0
const ASTEROID_SPAWN_INTERVAL_MIN = 1.0
# Time (in seconds) from game start when min spawn interval is reached
const ASTEROID_SPAWN_INTERVAL_MIN_TIME = 180
# Max number of asteroids alive (soft cap, won't spwan if above threshold, but
# big/medium asteroids will still spawn smaller ones on explosion)
const ASTEROID_MAX = 250
# Number of asteroids corresponding to fastest bg theme pace (smallest interval)
const ASTEROID_MAX_BG_THEME_PACE = 25
# Safe distance from player for asteroid spawn
const ASTEROID_PLAYER_MIN_DISTANCE = 150

@onready var asteroid_properties_by_size = {
	Asteroid.Size.BIG: {
		"points": 25,
		"velocity_min": 50,
		"velocity_max": 75,
		"explosion_scale": 20.0,
		"explosion_sound": $Sounds/ExplosionBig,
		"scenes": [
			preload("res://scenes/asteroids/asteroid_big01.tscn"),
			preload("res://scenes/asteroids/asteroid_big02.tscn"),
			preload("res://scenes/asteroids/asteroid_big03.tscn"),
			preload("res://scenes/asteroids/asteroid_special01.tscn"),
		],
	},
	Asteroid.Size.MEDIUM: {
		"points": 50,
		"velocity_min": 100,
		"velocity_max": 150,
		"explosion_scale": 10.0,
		"explosion_sound": $Sounds/ExplosionMedium,
		"scenes": [
			preload("res://scenes/asteroids/asteroid_medium01.tscn"),
			preload("res://scenes/asteroids/asteroid_medium02.tscn"),
			preload("res://scenes/asteroids/asteroid_medium03.tscn"),
			preload("res://scenes/asteroids/asteroid_special02.tscn"),
			preload("res://scenes/asteroids/asteroid_special03.tscn"),
		],
	},
	Asteroid.Size.SMALL: {
		"points": 100,
		"velocity_min": 200,
		"velocity_max": 250,
		"explosion_scale": 5.0,
		"explosion_sound": $Sounds/ExplosionSmall,
		"scenes": [
			preload("res://scenes/asteroids/asteroid_small01.tscn"),
			preload("res://scenes/asteroids/asteroid_small02.tscn"),
			preload("res://scenes/asteroids/asteroid_small03.tscn"),
		]
	}
}

@onready var achievement_mgr = $AchievementManager
@onready var asteroids = $Asteroids
@onready var bullets = $Bullets
@onready var explosions = $Explosions
@onready var player = $Player

@onready var hud = $UI/HUD
@onready var flag = $UI/HUD/Flag;

@onready var achievement_sound = $Sounds/Achievement
@onready var bg_theme_sound = $Sounds/BackgroundTheme
@onready var bullet_sound = $Sounds/Bullet
@onready var death_sound = $Sounds/Death
@onready var thrusters_sound = $Sounds/Thrusters

var explosion_scene = preload("res://scenes/explosion.tscn")
# Set on game over to stop doing stuff
var game_is_over: bool = false
# Time from start of game
var elapsed_time: float = 0.0
# Time when next asteroid should spawn
var next_asteroid_spawn_time: float
# Current asteroid spawn interval, decreased over time
var asteroid_spawn_interval: float = ASTEROID_SPAWN_INTERVAL_MAX

var score = 0:
	set(val):
		score = val
		hud.score = val
		achievement_mgr.update_score(score)

var asteroids_exploded = 0:
	set(val):
		asteroids_exploded = val
		hud.asteroids_exploded = val

var progress: float = 0:
	set(val):
		progress = val
		hud.progress = val

func update_bg_theme_pace() -> void:
	var n_asteroids = min(asteroids.get_child_count(), ASTEROID_MAX_BG_THEME_PACE)
	bg_theme_sound.interval_seconds = 1.05 - float(n_asteroids) / ASTEROID_MAX_BG_THEME_PACE

func random_asteroid_spawn_position() -> Vector2:
	var x = random_coord_outside_distance(Globals.xmin, Globals.xmax, player.global_position.x, ASTEROID_PLAYER_MIN_DISTANCE)
	var y = random_coord_outside_distance(Globals.ymin, Globals.ymax, player.global_position.y, ASTEROID_PLAYER_MIN_DISTANCE)
	return Vector2(x, y)

func spawn_asteroid(size: Asteroid.Size, pos: Vector2, direction: float = -1) -> void:
	var props = asteroid_properties_by_size[size]
	var variant = randi_range(0, props["scenes"].size() - 1)
	var asteroid = props["scenes"][variant].instantiate()

	asteroid.global_position = pos
	asteroid.size = size
	asteroid.direction = direction
	asteroid.velocity = randf_range(props["velocity_min"], props["velocity_max"])
	asteroid.connect("exploded", _on_asteroid_exploded)
	asteroids.call_deferred("add_child", asteroid)

func spawn_periodic_asteroid() -> void:
	if min(asteroids.get_child_count(), ASTEROID_MAX) < ASTEROID_MAX:
		spawn_asteroid(Asteroid.Size.BIG, random_asteroid_spawn_position())
		update_bg_theme_pace()

	next_asteroid_spawn_time += asteroid_spawn_interval
	if asteroid_spawn_interval == ASTEROID_SPAWN_INTERVAL_MIN:
		return

	# Linear interpolation for next interval value
	var w = minf(elapsed_time, ASTEROID_SPAWN_INTERVAL_MIN_TIME) / ASTEROID_SPAWN_INTERVAL_MIN_TIME
	asteroid_spawn_interval = lerp(ASTEROID_SPAWN_INTERVAL_MAX, ASTEROID_SPAWN_INTERVAL_MIN, w)

func spawn_explosion(pos: Vector2, scale_max: float, lifetime: float = 0.8) -> void:
	var e = explosion_scene.instantiate()
	e.process_material.scale_max = scale_max
	e.global_position = pos
	e.lifetime = lifetime
	e.emitting = true
	explosions.call_deferred("add_child", e)

func random_coord_outside_distance(vmin: float, vmax: float, pos: float, dist: float) -> float:
	var v = randf_range(vmin, vmax - 2 * dist)
	if v >= pos - dist:
		v += 2 * dist

	return v

func trigger_game_over(win: bool) -> void:
	if game_is_over:
		return

	game_is_over = true
	thrusters_sound.stop()
	bg_theme_sound.stop_playing()
	# Prevent more achievement-related stuff from happening
	remove_child($AchievementManager)

	if win:
		for a in asteroids.get_children():
			a.explode(false)

	emit_signal("game_over", win);

func _process(delta: float) -> void:
	if game_is_over:
		return

	elapsed_time += delta
	if elapsed_time >= next_asteroid_spawn_time:
		spawn_periodic_asteroid()

func _on_player_bullet_shot(b: Node) -> void:
	if game_is_over:
		return

	bullet_sound.play()
	bullets.add_child(b)

func _on_player_thrusters_toggled(on: bool) -> void:
	if game_is_over:
		return

	thrusters_sound.playing = on

func _on_player_died() -> void:
	spawn_explosion(player.global_position, 25, 2.0)
	death_sound.play()
	trigger_game_over(false)

func _on_asteroid_exploded(a: Asteroid, split: bool) -> void:
	var props = asteroid_properties_by_size[a.size]
	asteroids_exploded += 1
	score += props["points"]
	props["explosion_sound"].play()
	spawn_explosion(a.global_position, props["explosion_scale"])

	if split and a.size > Asteroid.Size.SMALL:
		spawn_asteroid(a.size - 1, a.position, a.direction + PI / 2)
		spawn_asteroid(a.size - 1, a.position, a.direction - PI / 2)

	update_bg_theme_pace()

func _on_achievement_manager_achievement_achieved(a_name: String, value: String) -> void:
	var new_flag = flag.text.split('')

	for i in min(value.length(), new_flag.size()):
		if value[i] != '*':
			new_flag[i] = value[i]

	flag.text = ''.join(new_flag)
	hud.flash_new_achievement(a_name)
	achievement_sound.play()

	progress = 1.0 - (float(flag.text.count('*')) / flag.text.length())
	if progress == 1.0:
		trigger_game_over(true)
