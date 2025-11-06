shader_type canvas_item;

uniform float min_alpha = 0.3;
uniform float max_alpha = 1.0;
uniform float wave = 0.0;
varying vec2 vertex_pos;

void vertex() {
	vertex_pos = VERTEX;
	VERTEX.y += wave * (-10.0 + 10.0 * sin(PI * VERTEX.x / 300.0 + TIME * 3.0));
}

void fragment() {
	vec2 tex_size = vec2(textureSize(TEXTURE, 0));
	vec2 real_uv = vertex_pos / tex_size;
	COLOR.a *= min(max_alpha, max(min_alpha, sin(PI/4.0 * real_uv.x - TIME * 3.0)));
}