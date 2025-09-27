/**
 * @mebeim - 2025-09-27
 */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>

// These should be fully scalable
#define GRID_WIDTH         10
#define GRID_HEIGHT        10
#define GRID_SIZE          (GRID_WIDTH * GRID_HEIGHT)
#define BITMAP_SIZE        GRID_HEIGHT
#define CELL_WIDTH         (20 * opt_scale)
#define CELL_HEIGHT        (20 * opt_scale)
#define CELL_SIZE          (CELL_WIDTH * CELL_HEIGHT)
#define SCREEN_WIDTH       (GRID_WIDTH * CELL_WIDTH)
#define SCREEN_HEIGHT      (GRID_HEIGHT * CELL_HEIGHT)
#define N_PIXELS           (SCREEN_WIDTH * SCREEN_HEIGHT)
#define SNEK_STEP_INTERVAL 300 // ms

// Draw routine assumes this is single digit and non-negative
#define SNEK_LIVES 3
_Static_assert(SNEK_LIVES < 10);
_Static_assert(SNEK_LIVES > 0);

// Texture size is fixed. Other parts of the game, as well as the texture
// generator script, assume 20x20. Renderer will scale to CELL_{WIDTH,HEIGHT}
// automatically when drawing if needed.
#define TEXTURE_WIDTH  20
#define TEXTURE_HEIGHT 20
#define TEXTURE_N_PIXELS (TEXTURE_WIDTH * TEXTURE_HEIGHT)
_Static_assert(TEXTURE_WIDTH == 20);
_Static_assert(TEXTURE_HEIGHT == 20);

#define ARRAY_LENGTH(a) (sizeof(a) / sizeof(*a))


enum Action {
	ACT_NONE = -1,
	ACT_QUIT = 0,
	ACT_UP,
	ACT_DOWN,
	ACT_LEFT,
	ACT_RIGHT,
};

struct Vec2 {
	unsigned short x;
	unsigned short y;
};


static SDL_Window *window;
static SDL_Renderer *renderer;

// Game session record/replay
static bool opt_record;
static bool opt_replay;
static bool opt_fast_replay;
static FILE *replay_fp;
// Window/texture scaling
static unsigned opt_scale = 1;

// Game is over when snek_lives reaches 0. Score does not reset on death.
static bool game_over;
static unsigned game_score;

static struct Vec2 apple;
static bool apple_avail_cells[GRID_SIZE];

// Length, direction and snek[] are also reset on snek_init(), called by
// game_init(), but are initialized here so that they live in .data together
// with textures[] (rather than .bss).
static unsigned snek_lives = SNEK_LIVES;
static unsigned snek_length = 3;
static struct Vec2 snek_direction = {1, 0};
static struct Vec2 snek[GRID_SIZE] = {
	{GRID_WIDTH / 2 + 1, GRID_HEIGHT / 2},
	{GRID_WIDTH / 2    , GRID_HEIGHT / 2},
	{GRID_WIDTH / 2 - 1, GRID_HEIGHT / 2},
};

// Auto-generated at build time
#include "textures.h"
// The texture_info[] array defined here should immediately follow snek[] above
// for the intended solution to be feasible, so that a long snek can linearly
// overflow into texture_info[0].path[].


static void snek_init(void);
static void snek_turn(enum Action);
static void snek_step(void);
static void draw_snek(void);

static void apple_move(void);
static void draw_apple(void);

static void draw_lives(void);
static void draw_score(void);
static void draw_hud(void);

static void draw_texture(int, int, SDL_Texture *);
static void update_screen(void);

static int get_action(enum Action *, int);
static int get_replay_action(enum Action *);
static void record_replay_action(enum Action);

static void save_screen_as_png(void);

static void game_init(void);
static void game_loop(void);

static void quit(int);

static void load_textures(void);

static void sdl_init(void);


static void quit(int exit_staus) {
	if (replay_fp)
		fclose(replay_fp);

	for (unsigned i = 0; i < ARRAY_LENGTH(textures); i++) {
		if (textures[i])
			SDL_DestroyTexture(textures[i]);
	}

	if (renderer)
		SDL_DestroyRenderer(renderer);

	if (window)
		SDL_DestroyWindow(window);

	IMG_Quit();
	SDL_Quit();
	exit(exit_staus);
}

/* This function loads all textures needed by the game. It is called on
 * game_init(), meaning that textures are re-loaded each time snek dies and
 * loses 1 life. We are leaking memory by not freeing pre-existing textures, but
 * that's not really a problem.
 *
 * If any texture is not found, we just print an error and make it a solid
 * white square. This logic is necessary to make the intended exploit
 * possible, since we need to overwrite the first texture path with
 * "flag\x00", but we can only write 4 bytes per run. We first write the
 * final "\x00" resulting in "****\x00", which will fail to load. Then,
 * we write "flag" and the flag file content will be loaded as pixel data
 * for the first texture.
 */
static void load_textures(void) {
	for (unsigned i = 0; i < ARRAY_LENGTH(textures); i++) {
		const char *path = texture_info[i].path;
		const Uint32 pixel_format = texture_info[i].pixel_format;
		const Uint32 pixel_size = texture_info[i].pixel_size;
		const Uint32 blend_mode = texture_info[i].blend_mode;
		const Uint8 *fallback_color = texture_info[i].fallback_color;
		const int pitch = pixel_size * TEXTURE_WIDTH;

		Uint8 *px = calloc(TEXTURE_N_PIXELS, pixel_size);
		if (!px) {
			SDL_LogCritical(SDL_LOG_CATEGORY_ERROR, "Could not allocate memory for texture");
			quit(1);
		}

		FILE *fp = fopen(path, "rb");
		if (!fp) {
			SDL_LogWarn(SDL_LOG_CATEGORY_APPLICATION,
				"Could not open texture file \"%s\": %s", path,
				strerror(errno));
		}

		if (fp && fread(px, pixel_size, TEXTURE_N_PIXELS, fp) == 0) {
			SDL_LogWarn(SDL_LOG_CATEGORY_APPLICATION,
				"Could not read texture data for \"%s\": %s",
				path, feof(fp) ? "EOF" : strerror(errno));
			fclose(fp);
		}

		if (fp) {
			fclose(fp);
		} else {
			// Missing texture, fall back to solid square of given color
			for (Uint8 *p = px; p < px + TEXTURE_N_PIXELS * pixel_size; p += pixel_size)
				memcpy(p, fallback_color, pixel_size);
		}

		textures[i] = SDL_CreateTexture(renderer, pixel_format,
			SDL_TEXTUREACCESS_STATIC, TEXTURE_WIDTH, TEXTURE_HEIGHT);
		if (!textures[i]) {
			SDL_LogCritical(SDL_LOG_CATEGORY_ERROR,
				"Could not create SDL texture for \"%s\": %s",
				path, SDL_GetError());
			free(px);
			quit(1);
		}

		if (SDL_SetTextureBlendMode(textures[i], blend_mode) != 0) {
			SDL_LogCritical(SDL_LOG_CATEGORY_ERROR,
				"Could not set texture blend mode for \"%s\": %s",
				path, SDL_GetError());
			free(px);
			quit(1);
		}

		if (SDL_UpdateTexture(textures[i], NULL, px, pitch) != 0) {
			SDL_LogCritical(SDL_LOG_CATEGORY_ERROR,
				"Could not set texture data for \"%s\": %s",
				path, SDL_GetError());
			free(px);
			quit(1);
		}

		free(px);
	}

}

static void draw_texture(int col, int row, SDL_Texture *t) {
	const SDL_Rect r = {
		.x = col * CELL_WIDTH,
		.y = row * CELL_HEIGHT,
		.w = CELL_WIDTH,
		.h = CELL_HEIGHT
	};

	SDL_RenderCopy(renderer, t, NULL, &r);
}

static void draw_lives(void) {
	SDL_Texture **digit_textures = &TXT_0;
	draw_texture(GRID_WIDTH - 1, 0, digit_textures[snek_lives]);
}

static void draw_score(void) {
	unsigned score = game_score;
	unsigned char digits[32];
	int n_digits = 0;

	if (score == 0) {
		draw_texture(0, 0, TXT_0);
		return;
	}

	while (score > 0) {
		digits[n_digits++] = score % 10;
		score /= 10;
	}

	SDL_Texture **digit_textures = &TXT_0;
	for (int i = 0; i < n_digits; i++)
		draw_texture(i, 0, digit_textures[digits[n_digits - i - 1]]);
}

static void draw_hud(void) {
	draw_score();
	draw_lives();

	if (game_over) {
		const unsigned x = GRID_WIDTH / 2 - 2;
		const unsigned y1 = GRID_HEIGHT / 2 - 1;
		const unsigned y2 = y1 + 1;

		draw_texture(x + 0, y1, TXT_G);
		draw_texture(x + 1, y1, TXT_A);
		draw_texture(x + 2, y1, TXT_M);
		draw_texture(x + 3, y1, TXT_E);
		draw_texture(x + 0, y2, TXT_O);
		draw_texture(x + 1, y2, TXT_V);
		draw_texture(x + 2, y2, TXT_E);
		draw_texture(x + 3, y2, TXT_R);
	}
}

static void apple_move(void) {
	unsigned n_available = ARRAY_LENGTH(apple_avail_cells);
	memset(apple_avail_cells, true, sizeof(apple_avail_cells));

	for (unsigned i = 0; i < snek_length; i++) {
		const unsigned short x = snek[i].x % GRID_WIDTH;
		const unsigned short y = snek[i].y % GRID_HEIGHT;

		if (apple_avail_cells[y * GRID_WIDTH + x]) {
			apple_avail_cells[y * GRID_WIDTH + x] = false;
			n_available--;
		}
	}

	/* BUG #2: in case there are no places available for our apple, no logic is
	 * implemented to "remove" it or to stop/respawn. The apple stays in place
	 * (covered by the snek body because it is drawn above, but still there).
	 * The snek head can then circle back and "eat" the apple again, even though
	 * it technically already occupies the entire grid with its body.
	 *
	 * Furthermore, because of BUG #1 (see below), multiple snek segments can
	 * have overlapping grid position on screen, which is the same position used
	 * above to calculate available places (notice the modulo operation). This
	 * makes it possible for the apple to keep moving around even if the snek is
	 * longer than GRID_SIZE.
	 */
	if (n_available) {
		unsigned target = rand() % n_available;

		for (unsigned i = 0; i < ARRAY_LENGTH(apple_avail_cells); i++) {
			if (apple_avail_cells[i] && target-- == 0) {
				apple.x = i % GRID_WIDTH;
				apple.y = i / GRID_WIDTH;
				break;
			}
		}
	}
}

static void draw_apple(void) {
	draw_texture(apple.x, apple.y, TXT_apple);
}

static void snek_init(void) {
	snek_length = 3;
	snek_direction = (struct Vec2){1, 0};
	snek[0] = (struct Vec2){GRID_WIDTH / 2 + 1, GRID_HEIGHT / 2};
	snek[1] = (struct Vec2){GRID_WIDTH / 2    , GRID_HEIGHT / 2};
	snek[2] = (struct Vec2){GRID_WIDTH / 2 - 1, GRID_HEIGHT / 2};
}

static void snek_turn(enum Action a) {
	struct Vec2 new_direction = {0, 0};

	switch (a) {
		case ACT_UP:
			new_direction.y = -1;
			break;
		case ACT_DOWN:
			new_direction.y = 1;
			break;
		case ACT_LEFT:
			new_direction.x = -1;
			break;
		case ACT_RIGHT:
			new_direction.x = 1;
			break;
		default:
			return;
	}

	// Turning 0 or 180 degrees does nothing
	if (snek_direction.x == new_direction.x || snek_direction.y == new_direction.y)
		return;

	snek_direction = new_direction;
}

static void snek_step(void) {
	// Advane head. No wrap around performed explicitly here: modulo operations
	// need to be used elsewhere in the code. This is technically wrong because
	// wrapping around from x=0 to x=65535 will result in x=5 instead of x=9,
	// making the glitch easily noticeable, but whatever, see if I care.
	struct Vec2 new_head = {
		snek[0].x + snek_direction.x,
		snek[0].y + snek_direction.y,
	};

	// Check for apple collision (account for wrap-around)
	if (new_head.x % GRID_WIDTH == apple.x && new_head.y % GRID_HEIGHT == apple.y) {
		memmove(snek + 1, snek, sizeof(*snek) * snek_length);
		snek[0] = new_head;
		snek_length++;
		game_score++;
		apple_move();
	} else {
		memmove(snek + 1, snek, sizeof(*snek) * (snek_length - 1));
		snek[0] = new_head;
	}

	// Exploit debugging help
	// SDL_Log("len %u pos %hu %hu tail %hu %hu apple %hu %hu | %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx",
	// 	snek_length,
	// 	new_head.x, new_head.y,
	// 	snek[snek_length - 1].x, snek[snek_length - 1].y,
	// 	apple.x, apple.y,
	// 	texture_info[0].path[0], texture_info[0].path[1], texture_info[0].path[2],
	// 	texture_info[0].path[3], texture_info[0].path[4], texture_info[0].path[5]);

	/* BUG #1: body collision check implemented without accounting for
	 * wrap-around (i.e. using modulo operations). This means the that head can
	 * only collide with body segment with the exact same coordinates, when it
	 * should also collide with segments that have different coordinates but are
	 * displayed in the same cell of the grid due to modulo wrap-around logic
	 * applied when drawing (and really anywhere else).
	 *
	 * Coupled with BUG #2 (see above), this makes it possible to keep eating
	 * apples and exceed a snek length of GRID_SIZE (being careful about head
	 * position), overfloing the global snek[] array holding coordinates.
	 */
	for (unsigned i = 1; i < snek_length; i++) {
		if (snek[i].x == new_head.x && snek[i].y == new_head.y) {
			if (--snek_lives == 0)
				game_over = true;
			else
				game_init();
		}
	}
}

static void draw_snek(void) {
	// Grid wrap-around is handled here as a simple modulo operation.
	for (unsigned i = 1; i < snek_length; i++)
		draw_texture(snek[i].x % GRID_WIDTH, snek[i].y % GRID_HEIGHT, TXT_snek);
	draw_texture(snek[0].x % GRID_WIDTH, snek[0].y % GRID_HEIGHT, TXT_head);
}

static void update_screen(void) {
	SDL_RenderClear(renderer);
	draw_apple();
	draw_snek();
	draw_hud();
	SDL_RenderPresent(renderer);
}

static int get_action(enum Action *res, int timeout_ms) {
	SDL_Event e;
	*res = ACT_NONE;

	if (SDL_WaitEventTimeout(&e, timeout_ms) == 0)
		return 0;

	switch (e.type) {
		case SDL_WINDOWEVENT:
			// Alrays re-draw when needed or window content will glitch
			if (e.window.event == SDL_WINDOWEVENT_EXPOSED)
				update_screen();
			break;

		case SDL_QUIT:
			*res = ACT_QUIT;
			break;

		case SDL_KEYDOWN:
			switch (e.key.keysym.sym) {
				case SDLK_w:
				case SDLK_UP:
					*res = ACT_UP;
					break;
				case SDLK_s:
				case SDLK_DOWN:
					*res = ACT_DOWN;
					break;
				case SDLK_a:
				case SDLK_LEFT:
					*res = ACT_LEFT;
					break;
				case SDLK_d:
				case SDLK_RIGHT:
					*res = ACT_RIGHT;
					break;
			}
			break;
	}

	return 1;
}

static int get_replay_action(enum Action *res) {
	SDL_Event e;
	int c;

	// Poll for quit anyway in case we want to close a long running replay
	if (SDL_PollEvent(&e) == 1 && e.type == SDL_QUIT)
		quit(0);

	while (1) {
		c = fgetc(replay_fp);
		if (c == EOF) {
			if (feof(replay_fp))
				return 0;

			SDL_LogCritical(SDL_LOG_CATEGORY_APPLICATION,
				"Could not read action from replay file: %s", strerror(errno));
			quit(1);
		}

		if (!isspace(c))
			break;
	}

	switch (c) {
		case 'W':
			*res = ACT_UP;
			break;
		case 'S':
			*res = ACT_DOWN;
			break;
		case 'A':
			*res = ACT_LEFT;
			break;
		case 'D':
			*res = ACT_RIGHT;
			break;
		case '.':
			*res = ACT_NONE;
			break;
		default:
			SDL_LogCritical(SDL_LOG_CATEGORY_APPLICATION,
				"Unknown action in replay file");
			quit(1);
	}

	return 1;
}

static void record_replay_action(enum Action a) {
	char c;

	switch (a) {
		case ACT_UP:
			c = 'W';
			break;
		case ACT_DOWN:
			c = 'S';
			break;
		case ACT_LEFT:
			c = 'A';
			break;
		case ACT_RIGHT:
			c = 'D';
			break;
		case ACT_NONE:
			c = '.';
			break;
		default:
			SDL_LogCritical(SDL_LOG_CATEGORY_APPLICATION,
				"Internal error: trying to record bad action (%d)", a);
			quit(1);
	}

	if (fputc(c, replay_fp) == EOF) {
		SDL_LogCritical(SDL_LOG_CATEGORY_APPLICATION,
			"Could not record action to replay file: %s", strerror(errno));
		quit(1);
	}
}

static void save_screen_as_png(void) {
	const Uint32 pixel_format = SDL_PIXELFORMAT_RGB24;
	const Uint32 pixel_depth = 24;
	const Uint32 pixel_size = 3;
	int w, h;

	if (SDL_GetRendererOutputSize(renderer, &w, &h) != 0)
		goto err_sdl;

	const int pitch = pixel_size * w;
	void *px = calloc(w * h, pixel_size);
	if (!px)
		goto err_libc;

	if (SDL_RenderReadPixels(renderer, NULL, pixel_format, px, pitch) != 0) {
		free(px);
		goto err_sdl;
	}

	SDL_Surface *surface = SDL_CreateRGBSurfaceWithFormatFrom(px, w, h,
		pixel_depth, pitch, pixel_format);
	if (!surface) {
		free(px);
		goto err_sdl;
	}

	if (IMG_SavePNG(surface, "/tmp/snek.png") != 0) {
		free(px);
		goto err_img;
	}

	free(px);
	return;

err_sdl:
	SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
		"Could not save screenshot: %s", SDL_GetError());
	return;

err_img:
	SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
		"Could not save screenshot: %s", IMG_GetError());
	return;

err_libc:
	SDL_LogError(SDL_LOG_CATEGORY_APPLICATION,
		"Could not save screenshot: %s", strerror(errno));
}

static void game_init(void) {
	load_textures();
	snek_init();
	apple_move();
}

static void game_loop(void) {
	enum Action tick_action = ACT_NONE;
	enum Action a;

	SDL_StopTextInput();
	update_screen();

	Uint64 now = SDL_GetTicks64();
	Uint64 next_tick = now + SNEK_STEP_INTERVAL;

	while (!game_over) {
		if (opt_replay) {
			if (get_replay_action(&a) == 0)
				break;
			if (a != ACT_NONE)
				tick_action = a;
		} else {
			while (now < next_tick) {
				if (get_action(&a, (int)(next_tick - now)) != 1)
					goto next;
				if (a == ACT_QUIT)
					return;
				if (a != ACT_NONE)
					tick_action = a;
next:
				now = SDL_GetTicks64();
			}

			if (opt_record)
				record_replay_action(tick_action);
		}

		if (tick_action != ACT_NONE) {
			snek_turn(tick_action);
			tick_action = ACT_NONE;
		}

		if (!opt_replay)
			next_tick = now + SNEK_STEP_INTERVAL;

		snek_step();

		if (!opt_fast_replay)
			update_screen();
	}

	// Game over / end replay. Save final screenshot and wait for user to quit.
	update_screen();
	save_screen_as_png();

	// Quit automatically if running in headless mode.
	const char *drv = getenv("SDL_VIDEODRIVER");
	if (drv && !strcmp(drv, "dummy"))
		return;

	a = ACT_NONE;
	while (a != ACT_QUIT)
		get_action(&a, 1000);
}

static void sdl_init(void) {
	if (SDL_Init(SDL_INIT_VIDEO) != 0)
		errx(1, "Could not initialize SDL graphics: %s", SDL_GetError());

	if (IMG_Init(IMG_INIT_PNG) == 0)
		errx(1, "Could not initialize SDL_image: %s", IMG_GetError());

	window = SDL_CreateWindow("Snek", SDL_WINDOWPOS_UNDEFINED,
		SDL_WINDOWPOS_UNDEFINED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN);
	if (!window) {
		SDL_LogCritical(SDL_LOG_CATEGORY_ERROR,
			"Could not create SDL window: %s", SDL_GetError());
		quit(1);
	}

	renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_PRESENTVSYNC);
	if (!renderer) {
		SDL_LogCritical(SDL_LOG_CATEGORY_ERROR,
			"Could not create SDL renderer: %s", SDL_GetError());
		quit(1);
	}

	SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
}

static void usage_exit(const char *argv0, int status) {
	errx(status, "Usage: %s [--help] [--scale N] "
		"[{--record|--replay|--fast-replay} replay.txt]", argv0 ?: "snek");
}

static void parse_args(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help"))
			usage_exit(argv[0], 0);

		if (!strcmp(argv[i], "--record")) {
			if (opt_record || opt_replay)
				goto bad;

			opt_record = true;
		} else if (!strcmp(argv[i], "--replay")) {
			if (opt_record || opt_replay)
				goto bad;

			opt_replay = true;
		} else if (!strcmp(argv[i], "--fast-replay")) {
			if (opt_record || opt_replay)
				goto bad;

			opt_replay = true;
			opt_fast_replay = true;
		} else if (!strcmp(argv[i], "--scale")) {
			if (++i >= argc)
				goto bad;

			opt_scale = atoi(argv[i]);
			if (opt_scale < 1 || opt_scale > 5) {
				errx(1, "Invalid scale (min 1, max 5)");
				goto bad;
			}
		}

		if (!replay_fp && (opt_record || opt_replay)) {
			if (++i >= argc)
				goto bad;

			replay_fp = fopen(argv[i], opt_record ? "w" : "r");
			if (!replay_fp)
				err(1, "Could not open replay file \"%s\"", argv[2]);

			warnx(opt_record ? "Recording to \"%s\"" : "Replaying from \"%s\"",
				argv[i]);
		}
	}

	return;
bad:
	usage_exit(argv[0], 1);
}

int main(int argc, char **argv) {
	parse_args(argc, argv);
	sdl_init();
	game_init();
	game_loop();
	quit(0);
}
