/* Obliance VM console helper — protocol v2.
 *
 * Connects to a Hyper-V VM basic console (host 2179 + VM GUID pre-connection
 * blob, SSO/SYSTEM auth, no stored creds), captures the FreeRDP framebuffer,
 * converts BGRA->I420 (FreeRDP primitives) and encodes H.264 Annex-B (libx264).
 * Keyboard / mouse / typed text arrive as JSON lines on stdin.
 *
 * Output modes (argv[2]):
 *   <file.h264>  : raw Annex-B to a file (playable in ffplay/VLC) — local test.
 *   "-"          : STREAM to stdout, framed: [u8 type][u32 LE length][payload]
 *                    'I' init   : u32 w, u32 h (re-sent on every size change / refresh)
 *                    'F' frame  : one H.264 Annex-B access unit
 *                    'S' status : JSON object (UTF-8), see emit_status_* below:
 *                       {"state":"connecting"}
 *                       {"state":"connected","width":W,"height":H,"unicode":bool}
 *                       {"state":"reconnecting","attempt":N,"reason":"<code>"}
 *                       {"state":"ended","code":"<code>","message":"...","error":"0x%08X"}
 *                         code: connect_failed | other_connection | auth_failed |
 *                               server_closed | reconnect_failed | encoder_failed | stdin_closed
 *                       {"state":"typing","done":n,"total":m}
 *                       {"state":"typing_cancelled","done":n,"total":m}
 *
 * stdin (stream mode), one JSON object per line (<= 1 MiB):
 *   {"type":"mouse","action":"move|down|up|scroll|hscroll","x","y","button","delta"}
 *   {"type":"key","action":"down|up","code":"KeyA","key":"a"}
 *   {"type":"type_text","text":"...","layout":"0000040C","guest":"windows|linux"}
 *     (guest optional, absent / other value = windows)
 *   {"type":"type_cancel"} {"type":"sas"} {"type":"release_all"} {"type":"refresh"}
 *
 * Exit codes: 0 normal end (stdin EOF), 2 usage, 3 init, 4 first connection
 * failed, 5 WSAStartup, 6 output, 7 connection lost for good.
 *
 * Build (MSYS2 mingw64) — see build.ps1:
 *   gcc -D__STDC_NO_THREADS__ -O2 -Wall vmconsole.c -o vmconsole.exe \
 *       $(pkg-config --cflags --libs freerdp3 x264) -lws2_32
 *
 * Run (file):     vmconsole.exe <vm-guid> out.h264 30
 * Run (stream):   vmconsole.exe <vm-guid> - 0 [host]       (0 = unlimited)
 * Self-test:      vmconsole.exe --selftest
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <io.h>
#include <fcntl.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winpr/synch.h>
#include <winpr/json.h>
#include <winpr/wlog.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/settings.h>
#include <freerdp/codec/color.h>
#include <freerdp/primitives.h>
#include <freerdp/input.h>
#include <freerdp/error.h>
#include <x264.h>

#define PROTOCOL_VERSION 2
#define MAX_LINE (1024 * 1024)
#define MAX_TYPE_CHARS 20000
#define FRAME_INTERVAL_MS 33
#define RECONNECT_EVERY_MS 3000
#define RECONNECT_WINDOW_MS 300000

typedef struct
{
	rdpContext context;
} vmCtx;

/* ── global state ───────────────────────────────────────────────────────── */

static int g_maxframes = 0; /* 0 = unlimited */
static int g_stream = 0;    /* 1 = framed protocol to stdout, 0 = raw to file */
static FILE* g_out = NULL;
static int g_frames = 0;
static long long g_pts = 0;
static int g_init_sent = 0;
static volatile LONG g_out_broken = 0;
static volatile LONG g_stdin_closed = 0;
static CRITICAL_SECTION g_outLock;
static CRITICAL_SECTION g_inLock;

static x264_t* g_enc = NULL;
static x264_picture_t g_picin;
static int g_encw = 0, g_ench = 0;
static primitives_t* g_prims = NULL;
static int g_force_idr = 0;
static volatile LONG g_refresh_req = 0;
static int g_dirty = 0;
static ULONGLONG g_last_encode = 0;

static freerdp* g_instance = NULL;
static rdpInput* g_input = NULL;
static volatile LONG g_desk_w = 0, g_desk_h = 0;
static BOOL g_unicode_ok = FALSE;
static char g_layout[16] = "00000409";
/* Guest OS of the last type_text job (TRUE = Linux, FALSE = Windows, the
 * default and the only mode of a Desktop that does not send `guest`). Also
 * used by inject_key's one-character path. */
static BOOL g_guest_linux = FALSE;

/* ── test recorder (selftest: events recorded instead of sent) ───────────── */

typedef struct
{
	char kind; /* 'k' key, 'u' unicode, 'm' mouse, 'x' extended mouse, 'p' pause */
	UINT16 flags;
	UINT16 a, b;
} TestEv;
static int g_testmode = 0;
static TestEv g_tev[4096];
static int g_ntev = 0;

static void rec_ev(char kind, UINT16 flags, UINT16 a, UINT16 b)
{
	if (g_ntev < (int)(sizeof(g_tev) / sizeof(g_tev[0])))
	{
		g_tev[g_ntev].kind = kind;
		g_tev[g_ntev].flags = flags;
		g_tev[g_ntev].a = a;
		g_tev[g_ntev].b = b;
		g_ntev++;
	}
}

/* ── stream framing ─────────────────────────────────────────────────────── */

static void mark_out_broken(void)
{
	if (InterlockedExchange(&g_out_broken, 1) == 0 && g_instance && g_instance->context)
		freerdp_abort_connect_context(g_instance->context);
}

/* Writes one framed message (thread-safe). */
static void emit_msg(char type, const void* a, size_t alen, const void* b, size_t blen)
{
	if (!g_stream || g_out_broken)
		return;
	const uint32_t len = (uint32_t)(alen + blen);
	unsigned char hdr[5] = { (unsigned char)type, (unsigned char)(len), (unsigned char)(len >> 8),
		                     (unsigned char)(len >> 16), (unsigned char)(len >> 24) };
	EnterCriticalSection(&g_outLock);
	BOOL ok = fwrite(hdr, 1, 5, g_out) == 5;
	if (ok && alen)
		ok = fwrite(a, 1, alen, g_out) == alen;
	if (ok && blen)
		ok = fwrite(b, 1, blen, g_out) == blen;
	if (ok)
		ok = fflush(g_out) == 0;
	LeaveCriticalSection(&g_outLock);
	if (!ok)
		mark_out_broken();
}

static void json_escape(const char* in, char* out, size_t outsz)
{
	size_t o = 0;
	for (const unsigned char* p = (const unsigned char*)(in ? in : ""); *p && o + 7 < outsz; p++)
	{
		if (*p == '"' || *p == '\\')
		{
			out[o++] = '\\';
			out[o++] = (char)*p;
		}
		else if (*p < 0x20)
			o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", *p);
		else
			out[o++] = (char)*p;
	}
	out[o] = '\0';
}

static void emit_status(const char* fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n >= (int)sizeof(buf))
		n = (int)sizeof(buf) - 1;
	fprintf(stderr, "status %s\n", buf);
	emit_msg('S', buf, (size_t)n, NULL, 0);
}

static void emit_ended(const char* code, const char* message, UINT32 err)
{
	char esc[512];
	json_escape(message, esc, sizeof(esc));
	emit_status("{\"state\":\"ended\",\"code\":\"%s\",\"message\":\"%s\",\"error\":\"0x%08X\"}", code, esc,
	            (unsigned)err);
}

static void emit_init(int w, int h)
{
	if (!g_stream || g_init_sent)
		return;
	unsigned char p[8] = { (unsigned char)w, (unsigned char)(w >> 8), (unsigned char)(w >> 16),
		                   (unsigned char)(w >> 24), (unsigned char)h, (unsigned char)(h >> 8),
		                   (unsigned char)(h >> 16), (unsigned char)(h >> 24) };
	emit_msg('I', p, 8, NULL, 0);
	g_init_sent = 1;
	fprintf(stderr, "init %dx%d\n", w, h);
}

static void emit_frame(const unsigned char* data, int len, int keyframe)
{
	if (g_stream)
		emit_msg('F', data, (size_t)len, NULL, 0);
	else
	{
		if (fwrite(data, 1, (size_t)len, g_out) != (size_t)len)
			mark_out_broken();
		printf("frame #%d: %d bytes H.264 (%s)\n", g_frames + 1, len, keyframe ? "KEY" : "delta");
		fflush(stdout);
	}
}

/* ── encoder ────────────────────────────────────────────────────────────── */

static BOOL setup_encoder(int w, int h)
{
	x264_param_t p;
	if (x264_param_default_preset(&p, "ultrafast", "zerolatency") < 0)
		return FALSE;
	p.i_csp = X264_CSP_I420;
	p.i_width = w;
	p.i_height = h;
	p.i_fps_num = 30;
	p.i_fps_den = 1;
	p.i_keyint_max = 60;
	p.b_annexb = 1;
	p.b_repeat_headers = 1;
	p.i_log_level = X264_LOG_NONE;
	if (x264_param_apply_profile(&p, "high") < 0)
		return FALSE;
	g_enc = x264_encoder_open(&p);
	if (!g_enc)
		return FALSE;
	if (x264_picture_alloc(&g_picin, X264_CSP_I420, w, h) < 0)
	{
		x264_encoder_close(g_enc);
		g_enc = NULL;
		return FALSE;
	}
	if (!g_prims)
		g_prims = primitives_get();
	g_encw = w;
	g_ench = h;
	return TRUE;
}

static void close_encoder(void)
{
	if (g_enc)
	{
		x264_picture_clean(&g_picin);
		x264_encoder_close(g_enc);
		g_enc = NULL;
	}
	g_encw = g_ench = 0;
}

/* Encodes the current framebuffer (main thread only). */
static BOOL encode_now(rdpContext* ctx)
{
	rdpGdi* gdi = ctx->gdi;
	g_dirty = 0;
	g_last_encode = GetTickCount64();
	if (!gdi || !gdi->primary_buffer)
		return TRUE;
	InterlockedExchange(&g_desk_w, (LONG)gdi->width);
	InterlockedExchange(&g_desk_h, (LONG)gdi->height);
	/* x264 I420 needs even dimensions: drop the last odd row / column. */
	const int w = (int)gdi->width & ~1;
	const int h = (int)gdi->height & ~1;
	if (w < 2 || h < 2)
		return TRUE;

	if (InterlockedExchange(&g_refresh_req, 0))
	{
		g_force_idr = 1;
		g_init_sent = 0;
	}
	if (!g_enc || g_encw != w || g_ench != h)
	{
		close_encoder();
		if (!setup_encoder(w, h))
		{
			fprintf(stderr, "encoder setup failed (%dx%d)\n", w, h);
			emit_ended("encoder_failed", "H.264 encoder setup failed", 0);
			return FALSE;
		}
		g_init_sent = 0;
		g_force_idr = 1;
	}
	emit_init(w, h);

	BYTE* dst[3] = { g_picin.img.plane[0], g_picin.img.plane[1], g_picin.img.plane[2] };
	const UINT32 dstStep[3] = { (UINT32)g_picin.img.i_stride[0], (UINT32)g_picin.img.i_stride[1],
		                        (UINT32)g_picin.img.i_stride[2] };
	const prim_size_t roi = { (UINT32)w, (UINT32)h };
	g_prims->RGBToYUV420_8u_P3AC4R(gdi->primary_buffer, gdi->dstFormat, gdi->stride, dst, dstStep, &roi);

	g_picin.i_pts = g_pts++;
	g_picin.i_type = g_force_idr ? X264_TYPE_IDR : X264_TYPE_AUTO;
	g_force_idr = 0;
	x264_nal_t* nals = NULL;
	int i_nals = 0;
	x264_picture_t pic_out;
	int sz = x264_encoder_encode(g_enc, &nals, &i_nals, &g_picin, &pic_out);
	if (sz > 0)
	{
		emit_frame(nals[0].p_payload, sz, pic_out.b_keyframe);
		g_frames++;
	}
	if (g_maxframes > 0 && g_frames >= g_maxframes)
		freerdp_abort_connect_context(ctx);
	return TRUE;
}

/* EndPaint: at most ~30 pictures/s; a picture drawn sooner stays "dirty" and
 * is flushed by the main loop. */
static BOOL vm_end_paint(rdpContext* ctx)
{
	g_dirty = 1;
	if (GetTickCount64() - g_last_encode >= FRAME_INTERVAL_MS)
		return encode_now(ctx);
	return TRUE;
}

static BOOL vm_desktop_resize(rdpContext* ctx)
{
	rdpSettings* s = ctx->settings;
	const UINT32 w = freerdp_settings_get_uint32(s, FreeRDP_DesktopWidth);
	const UINT32 h = freerdp_settings_get_uint32(s, FreeRDP_DesktopHeight);
	fprintf(stderr, "desktop resize %ux%u\n", (unsigned)w, (unsigned)h);
	if (ctx->gdi && !gdi_resize(ctx->gdi, w, h))
		return FALSE;
	InterlockedExchange(&g_desk_w, (LONG)w);
	InterlockedExchange(&g_desk_h, (LONG)h);
	g_dirty = 1; /* the encoder is re-created at the new size by encode_now */
	return TRUE;
}

static BOOL vm_post_connect(freerdp* instance)
{
	rdpContext* ctx = instance->context;
	if (ctx->gdi)
	{
		/* Reconnect on the same instance: keep the GDI, follow the size. */
		if (!gdi_resize(ctx->gdi, freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopWidth),
		                freerdp_settings_get_uint32(ctx->settings, FreeRDP_DesktopHeight)))
			return FALSE;
	}
	else if (!gdi_init(instance, PIXEL_FORMAT_BGRA32))
		return FALSE;
	ctx->update->EndPaint = vm_end_paint;
	ctx->update->DesktopResize = vm_desktop_resize;
	return TRUE;
}

static BOOL vm_authenticate(freerdp* instance, char** user, char** domain, char** pass)
{
	(void)instance;
	(void)user;
	(void)domain;
	(void)pass;
	return TRUE;
}

static DWORD vm_verify_cert_ex(freerdp* instance, const char* host, UINT16 port,
                               const char* common_name, const char* subject, const char* issuer,
                               const char* fingerprint, DWORD flags)
{
	(void)instance;
	(void)host;
	(void)port;
	(void)common_name;
	(void)subject;
	(void)issuer;
	(void)fingerprint;
	(void)flags;
	return 2; /* accept for this session only (local host console) */
}

/* ── low-level input (callers hold g_inLock) ─────────────────────────────── */

static BOOL g_keydown[2][256];
static UINT32 g_buttons = 0; /* bit i = DOM button i pressed */

static void ev_key(UINT8 sc, BOOL ext, BOOL down)
{
	const UINT16 flags = (UINT16)((ext ? KBD_FLAGS_EXTENDED : 0) | (down ? 0 : KBD_FLAGS_RELEASE));
	g_keydown[ext ? 1 : 0][sc] = down;
	if (g_testmode)
		rec_ev('k', flags, sc, 0);
	else if (g_input)
		freerdp_input_send_keyboard_event(g_input, flags, sc);
}

static void ev_unicode(UINT16 ch, BOOL down)
{
	const UINT16 flags = down ? 0 : KBD_FLAGS_RELEASE;
	if (g_testmode)
		rec_ev('u', flags, ch, 0);
	else if (g_input)
		freerdp_input_send_unicode_keyboard_event(g_input, flags, ch);
}

static void ev_pause(void)
{
	if (g_testmode)
		rec_ev('p', 0, 0, 0);
	else if (g_input)
		freerdp_input_send_keyboard_pause_event(g_input);
}

static void ev_mouse(UINT16 flags, UINT16 x, UINT16 y)
{
	if (g_testmode)
		rec_ev('m', flags, x, y);
	else if (g_input)
		freerdp_input_send_mouse_event(g_input, flags, x, y);
}

static void ev_xmouse(UINT16 flags, UINT16 x, UINT16 y)
{
	if (g_testmode)
		rec_ev('x', flags, x, y);
	else if (g_input)
		freerdp_input_send_extended_mouse_event(g_input, flags, x, y);
}

/* Wheel flags: delta > 0 = wheel up (away from the user), < 0 = down. */
static UINT16 wheel_flags(int delta, BOOL horizontal)
{
	UINT16 f = horizontal ? PTR_FLAGS_HWHEEL : PTR_FLAGS_WHEEL;
	if (delta < 0)
		f |= PTR_FLAGS_WHEEL_NEGATIVE | 0x0088; /* -120 in 9-bit two's complement */
	else
		f |= 0x0078; /* +120 */
	return f;
}

/* ── DOM KeyboardEvent.code -> PS/2 set-1 scancode (+ extended flag) ─────── */

struct kmap
{
	const char* code;
	UINT8 sc;
	BOOL ext;
};
#define SC_PAUSE 0xFF /* special: Pause/Break sequence */
static const struct kmap KMAP[] = {
	{ "Escape", 0x01, 0 }, { "Digit1", 0x02, 0 }, { "Digit2", 0x03, 0 }, { "Digit3", 0x04, 0 },
	{ "Digit4", 0x05, 0 }, { "Digit5", 0x06, 0 }, { "Digit6", 0x07, 0 }, { "Digit7", 0x08, 0 },
	{ "Digit8", 0x09, 0 }, { "Digit9", 0x0A, 0 }, { "Digit0", 0x0B, 0 }, { "Minus", 0x0C, 0 },
	{ "Equal", 0x0D, 0 }, { "Backspace", 0x0E, 0 }, { "Tab", 0x0F, 0 }, { "KeyQ", 0x10, 0 },
	{ "KeyW", 0x11, 0 }, { "KeyE", 0x12, 0 }, { "KeyR", 0x13, 0 }, { "KeyT", 0x14, 0 },
	{ "KeyY", 0x15, 0 }, { "KeyU", 0x16, 0 }, { "KeyI", 0x17, 0 }, { "KeyO", 0x18, 0 },
	{ "KeyP", 0x19, 0 }, { "BracketLeft", 0x1A, 0 }, { "BracketRight", 0x1B, 0 }, { "Enter", 0x1C, 0 },
	{ "ControlLeft", 0x1D, 0 }, { "KeyA", 0x1E, 0 }, { "KeyS", 0x1F, 0 }, { "KeyD", 0x20, 0 },
	{ "KeyF", 0x21, 0 }, { "KeyG", 0x22, 0 }, { "KeyH", 0x23, 0 }, { "KeyJ", 0x24, 0 },
	{ "KeyK", 0x25, 0 }, { "KeyL", 0x26, 0 }, { "Semicolon", 0x27, 0 }, { "Quote", 0x28, 0 },
	{ "Backquote", 0x29, 0 }, { "ShiftLeft", 0x2A, 0 }, { "Backslash", 0x2B, 0 }, { "KeyZ", 0x2C, 0 },
	{ "KeyX", 0x2D, 0 }, { "KeyC", 0x2E, 0 }, { "KeyV", 0x2F, 0 }, { "KeyB", 0x30, 0 },
	{ "KeyN", 0x31, 0 }, { "KeyM", 0x32, 0 }, { "Comma", 0x33, 0 }, { "Period", 0x34, 0 },
	{ "Slash", 0x35, 0 }, { "ShiftRight", 0x36, 0 }, { "NumpadMultiply", 0x37, 0 }, { "AltLeft", 0x38, 0 },
	{ "Space", 0x39, 0 }, { "CapsLock", 0x3A, 0 }, { "F1", 0x3B, 0 }, { "F2", 0x3C, 0 }, { "F3", 0x3D, 0 },
	{ "F4", 0x3E, 0 }, { "F5", 0x3F, 0 }, { "F6", 0x40, 0 }, { "F7", 0x41, 0 }, { "F8", 0x42, 0 },
	{ "F9", 0x43, 0 }, { "F10", 0x44, 0 }, { "NumLock", 0x45, 0 }, { "ScrollLock", 0x46, 0 },
	{ "Numpad7", 0x47, 0 }, { "Numpad8", 0x48, 0 }, { "Numpad9", 0x49, 0 }, { "NumpadSubtract", 0x4A, 0 },
	{ "Numpad4", 0x4B, 0 }, { "Numpad5", 0x4C, 0 }, { "Numpad6", 0x4D, 0 }, { "NumpadAdd", 0x4E, 0 },
	{ "Numpad1", 0x4F, 0 }, { "Numpad2", 0x50, 0 }, { "Numpad3", 0x51, 0 }, { "Numpad0", 0x52, 0 },
	{ "NumpadDecimal", 0x53, 0 }, { "IntlBackslash", 0x56, 0 }, { "F11", 0x57, 0 }, { "F12", 0x58, 0 },
	{ "NumpadEqual", 0x59, 0 }, { "F13", 0x64, 0 }, { "F14", 0x65, 0 }, { "F15", 0x66, 0 },
	{ "F16", 0x67, 0 }, { "F17", 0x68, 0 }, { "F18", 0x69, 0 }, { "F19", 0x6A, 0 }, { "F20", 0x6B, 0 },
	{ "F21", 0x6C, 0 }, { "F22", 0x6D, 0 }, { "F23", 0x6E, 0 }, { "KanaMode", 0x70, 0 },
	{ "IntlRo", 0x73, 0 }, { "F24", 0x76, 0 }, { "Convert", 0x79, 0 }, { "NonConvert", 0x7B, 0 },
	{ "IntlYen", 0x7D, 0 }, { "NumpadComma", 0x7E, 0 },
	/* extended (0xE0-prefixed) */
	{ "ControlRight", 0x1D, 1 }, { "AltRight", 0x38, 1 }, { "NumpadEnter", 0x1C, 1 },
	{ "NumpadDivide", 0x35, 1 }, { "PrintScreen", 0x37, 1 }, { "Insert", 0x52, 1 }, { "Delete", 0x53, 1 },
	{ "Home", 0x47, 1 }, { "End", 0x4F, 1 }, { "PageUp", 0x49, 1 }, { "PageDown", 0x51, 1 },
	{ "ArrowUp", 0x48, 1 }, { "ArrowLeft", 0x4B, 1 }, { "ArrowRight", 0x4D, 1 }, { "ArrowDown", 0x50, 1 },
	{ "MetaLeft", 0x5B, 1 }, { "MetaRight", 0x5C, 1 }, { "OSLeft", 0x5B, 1 }, { "OSRight", 0x5C, 1 },
	{ "ContextMenu", 0x5D, 1 },
	/* special */
	{ "Pause", SC_PAUSE, 0 }, { NULL, 0, 0 },
};

static BOOL code_to_sc(const char* code, UINT8* sc, BOOL* ext)
{
	if (!code)
		return FALSE;
	for (int i = 0; KMAP[i].code; i++)
		if (strcmp(KMAP[i].code, code) == 0)
		{
			*sc = KMAP[i].sc;
			*ext = KMAP[i].ext;
			return TRUE;
		}
	return FALSE;
}

/* ── keyboard layout mapping (text typing) ──────────────────────────────── */

static HKL g_hkl_cache_h[16];
static char g_hkl_cache_id[16][16];
static int g_hkl_cache_n = 0;

static BOOL valid_klid(const char* s)
{
	if (!s || strlen(s) != 8)
		return FALSE;
	for (int i = 0; i < 8; i++)
	{
		const char c = s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
			return FALSE;
	}
	return TRUE;
}

static HKL layout_handle(const char* klid)
{
	if (!valid_klid(klid))
		klid = "00000409";
	for (int i = 0; i < g_hkl_cache_n; i++)
		if (_stricmp(g_hkl_cache_id[i], klid) == 0)
			return g_hkl_cache_h[i];
	WCHAR w[16];
	MultiByteToWideChar(CP_ACP, 0, klid, -1, w, 16);
	HKL h = LoadKeyboardLayoutW(w, KLF_NOTELLSHELL);
	if (h && g_hkl_cache_n < 16)
	{
		strncpy(g_hkl_cache_id[g_hkl_cache_n], klid, 15);
		g_hkl_cache_id[g_hkl_cache_n][15] = '\0';
		g_hkl_cache_h[g_hkl_cache_n++] = h;
	}
	return h;
}

/* Character -> scancode + shift state (1 shift, 2 ctrl, 4 alt; 6 = AltGr). */
static BOOL map_char(HKL hkl, WCHAR ch, UINT8* sc, BOOL* ext, int* state)
{
	if (!hkl)
		return FALSE;
	const SHORT r = VkKeyScanExW(ch, hkl);
	if (r == -1 || (r & 0xFF) == 0xFF)
		return FALSE;
	const UINT vk = (UINT)(r & 0xFF);
	const int st = (r >> 8) & 0xFF;
	if (st & ~0x07)
		return FALSE; /* Hankaku / kana modifiers: not reproducible */
	const UINT vsc = MapVirtualKeyExW(vk, MAPVK_VK_TO_VSC_EX, hkl);
	if ((vsc & 0xFF) == 0)
		return FALSE;
	*sc = (UINT8)(vsc & 0xFF);
	*ext = ((vsc & 0xFF00) == 0xE000);
	*state = st;
	return TRUE;
}

/* Is the key VkKeyScanEx chose for ch (with shift state st) a DEAD key on
 * this layout ('^' on French)? Typed alone it only arms the accent and the
 * NEXT character comes out combined ("^e" -> "ê") or swallowed. Same rule as
 * the Oblireach agent (engine/typetext_windows.go obli_plan_rune):
 *    0  not a dead key: type the key as usual;
 *    1  dead key, and dead key + Space gives ch: type it then Space;
 *   -1  dead key that does not give ch even with Space: not typable this way.
 * The probe runs on the HOST layout and leaves no dead state behind. */
static int dead_key_kind(HKL hkl, WCHAR ch, int st)
{
	const SHORT r = VkKeyScanExW(ch, hkl);
	if (r == -1)
		return 0;
	const UINT vk = (UINT)(r & 0xFF);
	BYTE ks[256];
	memset(ks, 0, sizeof(ks));
	if (st & 1)
		ks[VK_SHIFT] = ks[VK_LSHIFT] = 0x80;
	if (st & 2)
		ks[VK_CONTROL] = ks[VK_LCONTROL] = 0x80;
	if (st & 4)
		ks[VK_MENU] = ks[VK_RMENU] = 0x80;
	const UINT scan = MapVirtualKeyExW(vk, MAPVK_VK_TO_VSC, hkl);
	WCHAR buf[8] = { 0 };
	/* wFlags 0x4: do not change the keyboard state (Windows 10 1607+). */
	if (ToUnicodeEx(vk, scan, ks, buf, 8, 0x4, hkl) >= 0)
		return 0;
	/* Dead key: arm it, then does Space give ch? */
	BYTE ks0[256];
	memset(ks0, 0, sizeof(ks0));
	const UINT spScan = MapVirtualKeyExW(VK_SPACE, MAPVK_VK_TO_VSC, hkl);
	WCHAR d1[8] = { 0 }, sp[8] = { 0 };
	ToUnicodeEx(vk, scan, ks, d1, 8, 0, hkl);
	const int rs = ToUnicodeEx(VK_SPACE, spScan, ks0, sp, 8, 0, hkl);
	if (rs == 1 && sp[0] == ch)
		return 1;
	/* make sure no dead state lingers */
	ToUnicodeEx(VK_SPACE, spScan, ks0, sp, 8, 0, hkl);
	ToUnicodeEx(VK_SPACE, spScan, ks0, sp, 8, 0, hkl);
	return -1;
}

/* 10 ms lost characters in the Hyper-V console (fast "Type text"): 20 ms per
 * key event, plus one more pause between characters (type_thread_proc). */
static DWORD g_type_delay = 20;
static volatile LONG g_type_cancel = 0;

static void type_pause(void)
{
	if (!g_testmode && g_type_delay)
		Sleep(g_type_delay);
}

/* One key event under the input lock, then the inter-event delay. */
static void tkey(UINT8 sc, BOOL ext, BOOL down)
{
	EnterCriticalSection(&g_inLock);
	ev_key(sc, ext, down);
	LeaveCriticalSection(&g_inLock);
	type_pause();
}

/* Types one UTF-16 unit. Returns FALSE when it could not be typed.
 *
 * guest_linux (the Desktop says the VM runs Linux):
 *   - AltGr is Right Alt alone: Linux does not read LCtrl + RAlt as AltGr
 *     (it sees Ctrl+AltGr+key, a shortcut, not the character);
 *   - a character that needs Ctrl alone or Alt alone (control characters,
 *     shortcuts) is not typed, nor are C0 control characters other than
 *     Tab / Enter (Backspace, Escape... would edit the guest's command line);
 *   - no Unicode fallback: the Hyper-V basic console does not deliver
 *     Unicode keyboard events to a Linux guest. Unmappable = skipped.
 * Both guests: a dead key is followed by Space so the character itself comes
 * out (see dead_key_kind). */
static BOOL type_char(HKL hkl, WCHAR ch, BOOL guest_linux)
{
	if (ch == L'\r')
		return TRUE;
	if (ch == L'\n')
	{
		tkey(0x1C, FALSE, TRUE);
		tkey(0x1C, FALSE, FALSE);
		return TRUE;
	}
	if (ch == L'\t')
	{
		tkey(0x0F, FALSE, TRUE);
		tkey(0x0F, FALSE, FALSE);
		return TRUE;
	}
	if (guest_linux && (ch < 0x20 || ch == 0x7F))
		return FALSE;
	UINT8 sc;
	BOOL ext;
	int st;
	int dead = 0;
	BOOL mapped = map_char(hkl, ch, &sc, &ext, &st);
	if (mapped && guest_linux && ((st & 6) == 2 || (st & 6) == 4))
		return FALSE; /* Ctrl-only / Alt-only: a control character or shortcut */
	if (mapped)
	{
		dead = dead_key_kind(hkl, ch, st);
		if (dead < 0)
			mapped = FALSE;
	}
	if (mapped)
	{
		const BOOL altgr = (st & 6) == 6;
		const BOOL ctrl = !altgr && (st & 2);
		const BOOL alt = !altgr && (st & 4);
		const BOOL shift = (st & 1) != 0;
		if (altgr)
		{
			if (!guest_linux)
				tkey(0x1D, FALSE, TRUE); /* LCtrl */
			tkey(0x38, TRUE, TRUE);      /* RAlt (AltGr) */
		}
		if (ctrl)
			tkey(0x1D, FALSE, TRUE);
		if (alt)
			tkey(0x38, FALSE, TRUE);
		if (shift)
			tkey(0x2A, FALSE, TRUE);
		tkey(sc, ext, TRUE);
		tkey(sc, ext, FALSE);
		if (shift)
			tkey(0x2A, FALSE, FALSE);
		if (alt)
			tkey(0x38, FALSE, FALSE);
		if (ctrl)
			tkey(0x1D, FALSE, FALSE);
		if (altgr)
		{
			tkey(0x38, TRUE, FALSE);
			if (!guest_linux)
				tkey(0x1D, FALSE, FALSE);
		}
		if (dead > 0)
		{
			tkey(0x39, FALSE, TRUE); /* Space: the accent comes out alone */
			tkey(0x39, FALSE, FALSE);
		}
		return TRUE;
	}
	if (guest_linux)
		return FALSE;
	if (g_unicode_ok)
	{
		EnterCriticalSection(&g_inLock);
		ev_unicode(ch, TRUE);
		ev_unicode(ch, FALSE);
		LeaveCriticalSection(&g_inLock);
		type_pause();
		return TRUE;
	}
	return FALSE;
}

static void release_all_locked(void)
{
	for (int e = 0; e < 2; e++)
		for (int sc = 0; sc < 256; sc++)
			if (g_keydown[e][sc])
				ev_key((UINT8)sc, e == 1, FALSE);
	const UINT16 x = 0, y = 0;
	if (g_buttons & 1)
		ev_mouse(PTR_FLAGS_BUTTON1, x, y);
	if (g_buttons & 2)
		ev_mouse(PTR_FLAGS_BUTTON3, x, y);
	if (g_buttons & 4)
		ev_mouse(PTR_FLAGS_BUTTON2, x, y);
	if (g_buttons & 8)
		ev_xmouse(PTR_XFLAGS_BUTTON1, x, y);
	if (g_buttons & 16)
		ev_xmouse(PTR_XFLAGS_BUTTON2, x, y);
	g_buttons = 0;
}

typedef struct
{
	WCHAR* text;
	int len;
	HKL hkl;
	BOOL guest_linux;
} TypeJob;

static HANDLE g_type_thread = NULL;
static int g_type_last_skipped = 0; /* self-test: skipped count of the last job */

static DWORD WINAPI type_thread_proc(LPVOID arg)
{
	TypeJob* job = (TypeJob*)arg;
	int done = 0, skipped = 0, next_report = 200;
	for (int i = 0; i < job->len; i++)
	{
		if (g_type_cancel || g_stdin_closed || g_out_broken)
			break;
		const WCHAR c = job->text[i];
		if (job->guest_linux && IS_HIGH_SURROGATE(c) && i + 1 < job->len && IS_LOW_SURROGATE(job->text[i + 1]))
		{
			/* a character outside the BMP (emoji...) has no key on any
			 * layout and Linux gets no Unicode fallback: ONE skipped char */
			skipped++;
			i++;
			done += 2;
		}
		else
		{
			if (!type_char(job->hkl, c, job->guest_linux))
				skipped++;
			type_pause(); /* the guest lets the previous key go before the next one */
			done++;
		}
		if (done >= next_report)
		{
			emit_status("{\"state\":\"typing\",\"done\":%d,\"total\":%d}", done, job->len);
			next_report = (done / 200 + 1) * 200;
		}
	}
	g_type_last_skipped = skipped;
	if (done < job->len)
	{
		EnterCriticalSection(&g_inLock);
		release_all_locked();
		LeaveCriticalSection(&g_inLock);
		emit_status("{\"state\":\"typing_cancelled\",\"done\":%d,\"total\":%d}", done, job->len);
	}
	else
		emit_status("{\"state\":\"typing\",\"done\":%d,\"total\":%d,\"skipped\":%d}", done, job->len, skipped);
	free(job->text);
	free(job);
	return 0;
}

static void stop_typing(void)
{
	if (g_type_thread)
	{
		InterlockedExchange(&g_type_cancel, 1);
		WaitForSingleObject(g_type_thread, INFINITE);
		CloseHandle(g_type_thread);
		g_type_thread = NULL;
	}
	InterlockedExchange(&g_type_cancel, 0);
}

/* guest: "linux" or "windows"; NULL / anything else = windows (a Desktop
 * that predates the field). */
static void start_typing(const char* utf8, const char* layout, const char* guest)
{
	stop_typing();
	if (layout && valid_klid(layout))
	{
		strncpy(g_layout, layout, sizeof(g_layout) - 1);
		g_layout[sizeof(g_layout) - 1] = '\0';
	}
	g_guest_linux = (guest && strcmp(guest, "linux") == 0);
	int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	if (n <= 1)
		return;
	TypeJob* job = (TypeJob*)calloc(1, sizeof(TypeJob));
	if (!job)
		return;
	job->text = (WCHAR*)calloc((size_t)n, sizeof(WCHAR));
	if (!job->text)
	{
		free(job);
		return;
	}
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, job->text, n);
	job->len = n - 1;
	if (job->len > MAX_TYPE_CHARS)
		job->len = MAX_TYPE_CHARS;
	job->hkl = layout_handle(g_layout);
	job->guest_linux = g_guest_linux;
	if (g_testmode)
	{
		type_thread_proc(job); /* synchronous in the self-test */
		return;
	}
	g_type_thread = CreateThread(NULL, 0, type_thread_proc, job, 0, NULL);
	if (!g_type_thread)
	{
		free(job->text);
		free(job);
	}
}

/* ── JSON input dispatch ────────────────────────────────────────────────── */

static int json_int(WINPR_JSON* o, const char* k)
{
	WINPR_JSON* it = WINPR_JSON_GetObjectItem(o, k);
	return (it && WINPR_JSON_IsNumber(it)) ? (int)WINPR_JSON_GetNumberValue(it) : 0;
}
static const char* json_str(WINPR_JSON* o, const char* k)
{
	WINPR_JSON* it = WINPR_JSON_GetObjectItem(o, k);
	return (it && WINPR_JSON_IsString(it)) ? WINPR_JSON_GetStringValue(it) : NULL;
}

static UINT16 clamp_coord(int v, LONG size)
{
	if (v < 0)
		v = 0;
	if (size > 0 && v > size - 1)
		v = (int)size - 1;
	if (v > 0xFFFF)
		v = 0xFFFF;
	return (UINT16)v;
}

static void inject_mouse(WINPR_JSON* o, const char* action)
{
	const UINT16 x = clamp_coord(json_int(o, "x"), g_desk_w);
	const UINT16 y = clamp_coord(json_int(o, "y"), g_desk_h);
	EnterCriticalSection(&g_inLock);
	if (strcmp(action, "move") == 0)
		ev_mouse(PTR_FLAGS_MOVE, x, y);
	else if (strcmp(action, "scroll") == 0 || strcmp(action, "hscroll") == 0)
	{
		const int d = json_int(o, "delta");
		if (d != 0)
			ev_mouse(wheel_flags(d, action[0] == 'h'), x, y);
	}
	else if (strcmp(action, "down") == 0 || strcmp(action, "up") == 0)
	{
		const BOOL down = action[0] == 'd';
		const int b = json_int(o, "button");
		if (b >= 0 && b <= 4)
		{
			if (down)
				g_buttons |= (1u << b);
			else
				g_buttons &= ~(1u << b);
		}
		if (b == 3 || b == 4)
			ev_xmouse((UINT16)((b == 3 ? PTR_XFLAGS_BUTTON1 : PTR_XFLAGS_BUTTON2) | (down ? PTR_XFLAGS_DOWN : 0)),
			          x, y);
		else
		{
			const UINT16 bf = (b == 2) ? PTR_FLAGS_BUTTON2 : (b == 1) ? PTR_FLAGS_BUTTON3 : PTR_FLAGS_BUTTON1;
			ev_mouse((UINT16)(bf | (down ? PTR_FLAGS_DOWN : 0)), x, y);
		}
	}
	LeaveCriticalSection(&g_inLock);
}

static void inject_key(WINPR_JSON* o, const char* action)
{
	const BOOL down = (strcmp(action, "down") == 0);
	if (!down && strcmp(action, "up") != 0)
		return;
	UINT8 sc;
	BOOL ext;
	if (code_to_sc(json_str(o, "code"), &sc, &ext))
	{
		EnterCriticalSection(&g_inLock);
		if (sc == SC_PAUSE)
		{
			if (down)
				ev_pause();
		}
		else
			ev_key(sc, ext, down);
		LeaveCriticalSection(&g_inLock);
		return;
	}
	/* Unknown code (soft keyboards): one printable character -> the layout
	 * path on the press (the release is part of it), unicode otherwise. */
	const char* key = json_str(o, "key");
	if (!down || !key || !key[0])
		return;
	WCHAR w[4] = { 0 };
	const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, key, -1, w, 4);
	if (n != 2) /* exactly one UTF-16 unit + terminator */
		return;
	const DWORD saved = g_type_delay;
	g_type_delay = 0;
	type_char(layout_handle(g_layout), w[0], g_guest_linux);
	g_type_delay = saved;
}

static void inject_sas(void)
{
	/* Ctrl+Alt+Del as scancodes: the Hyper-V basic console (VmConnectMode)
	 * injects it into the VM like vmconnect's own Ctrl+Alt+Del action. */
	EnterCriticalSection(&g_inLock);
	ev_key(0x1D, FALSE, TRUE);
	ev_key(0x38, FALSE, TRUE);
	ev_key(0x53, TRUE, TRUE);
	LeaveCriticalSection(&g_inLock);
	if (!g_testmode)
		Sleep(50);
	EnterCriticalSection(&g_inLock);
	ev_key(0x53, TRUE, FALSE);
	ev_key(0x38, FALSE, FALSE);
	ev_key(0x1D, FALSE, FALSE);
	LeaveCriticalSection(&g_inLock);
}

/* Handles one input line. Returns FALSE when the line is not valid JSON. */
static BOOL handle_line(const char* line)
{
	WINPR_JSON* o = WINPR_JSON_Parse(line);
	if (!o)
		return FALSE;
	const char* type = json_str(o, "type");
	const char* action = json_str(o, "action");
	if (type)
	{
		if (strcmp(type, "mouse") == 0 && action)
			inject_mouse(o, action);
		else if (strcmp(type, "key") == 0 && action)
			inject_key(o, action);
		else if (strcmp(type, "type_text") == 0)
		{
			const char* text = json_str(o, "text");
			if (text)
				start_typing(text, json_str(o, "layout"), json_str(o, "guest"));
		}
		else if (strcmp(type, "type_cancel") == 0)
			stop_typing();
		else if (strcmp(type, "sas") == 0)
			inject_sas();
		else if (strcmp(type, "release_all") == 0)
		{
			EnterCriticalSection(&g_inLock);
			release_all_locked();
			LeaveCriticalSection(&g_inLock);
		}
		else if (strcmp(type, "refresh") == 0)
			InterlockedExchange(&g_refresh_req, 1);
		/* unknown types: ignored */
	}
	WINPR_JSON_Delete(o);
	return TRUE;
}

/* Line splitter: lines longer than MAX_LINE are dropped whole. */
typedef struct
{
	char* buf;
	size_t len, cap;
	BOOL overflow;
} LineBuf;

static void feed_bytes(LineBuf* lb, const char* data, size_t n, void (*on_line)(const char*))
{
	for (size_t i = 0; i < n; i++)
	{
		const char c = data[i];
		if (c == '\n')
		{
			if (!lb->overflow && lb->len > 0)
			{
				if (lb->buf[lb->len - 1] == '\r')
					lb->len--;
				lb->buf[lb->len] = '\0';
				on_line(lb->buf);
			}
			lb->len = 0;
			lb->overflow = FALSE;
			continue;
		}
		if (lb->overflow)
			continue;
		if (lb->len + 2 > lb->cap)
		{
			size_t nc = lb->cap ? lb->cap * 2 : 4096;
			if (nc > MAX_LINE + 2)
				nc = MAX_LINE + 2;
			if (lb->len + 2 > nc)
			{
				lb->overflow = TRUE;
				lb->len = 0;
				continue;
			}
			char* nb = (char*)realloc(lb->buf, nc);
			if (!nb)
			{
				lb->overflow = TRUE;
				lb->len = 0;
				continue;
			}
			lb->buf = nb;
			lb->cap = nc;
		}
		lb->buf[lb->len++] = c;
	}
}

static void on_input_line(const char* line)
{
	(void)handle_line(line);
}

static DWORD WINAPI stdin_thread(LPVOID arg)
{
	(void)arg;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	LineBuf lb = { 0 };
	char chunk[8192];
	DWORD got = 0;
	while (ReadFile(h, chunk, sizeof(chunk), &got, NULL) && got > 0)
		feed_bytes(&lb, chunk, got, on_input_line);
	free(lb.buf);
	fprintf(stderr, "stdin closed\n");
	InterlockedExchange(&g_stdin_closed, 1);
	InterlockedExchange(&g_type_cancel, 1);
	if (g_instance && g_instance->context)
		freerdp_abort_connect_context(g_instance->context);
	return 0;
}

/* ── error classification ───────────────────────────────────────────────── */

static BOOL is_other_connection(UINT32 err, UINT32 errinfo)
{
	return errinfo == ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION ||
	       err == FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION;
}

static BOOL is_auth_error(UINT32 err, UINT32 errinfo)
{
	if (errinfo == ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES || errinfo == ERRINFO_SERVER_DENIED_CONNECTION)
		return TRUE;
	if ((err >> 16) != FREERDP_ERROR_CONNECT_CLASS)
		return FALSE;
	switch (err & 0xFFFF)
	{
		case ERRCONNECT_AUTHENTICATION_FAILED:
		case ERRCONNECT_INSUFFICIENT_PRIVILEGES:
		case ERRCONNECT_LOGON_FAILURE:
		case ERRCONNECT_WRONG_PASSWORD:
		case ERRCONNECT_ACCESS_DENIED:
		case ERRCONNECT_ACCOUNT_RESTRICTION:
		case ERRCONNECT_ACCOUNT_LOCKED_OUT:
		case ERRCONNECT_ACCOUNT_EXPIRED:
		case ERRCONNECT_ACCOUNT_DISABLED:
		case ERRCONNECT_LOGON_TYPE_NOT_GRANTED:
		case ERRCONNECT_NO_OR_MISSING_CREDENTIALS:
			return TRUE;
		default:
			return FALSE;
	}
}

static const char* err_text(UINT32 err)
{
	const char* s = freerdp_get_last_error_string(err);
	return s ? s : "unknown error";
}

/* ── self-test ──────────────────────────────────────────────────────────── */

static int g_fail = 0;
#define CHECK(cond, ...)                         \
	do                                           \
	{                                            \
		if (cond)                                \
			printf("ok   - ");                   \
		else                                     \
		{                                        \
			printf("FAIL - ");                   \
			g_fail++;                            \
		}                                        \
		printf(__VA_ARGS__);                     \
		printf("\n");                            \
	} while (0)

static void test_map(const char* klid, WCHAR ch, const char* name, BOOL expect, UINT8 esc, int est)
{
	UINT8 sc = 0;
	BOOL ext = FALSE;
	int st = -1;
	const BOOL got = map_char(layout_handle(klid), ch, &sc, &ext, &st);
	if (!expect)
		CHECK(!got, "layout %s: '%s' not typable (got=%d)", klid, name, got);
	else
		CHECK(got && sc == esc && st == est, "layout %s: '%s' -> sc 0x%02X state %d (got %d sc 0x%02X state %d)",
		      klid, name, esc, est, got, sc, st);
}

/* The recorded events are exactly these key events (scancode + flags). */
static void check_seq(const char* name, const UINT16* sc, const UINT16* fl, int n)
{
	BOOL same = (g_ntev == n);
	for (int i = 0; same && i < n; i++)
		same = g_tev[i].kind == 'k' && g_tev[i].a == sc[i] && g_tev[i].flags == fl[i];
	CHECK(same, "%s (%d events)", name, g_ntev);
	if (!same)
		for (int i = 0; i < g_ntev; i++)
			printf("       ev %d: %c sc 0x%02X flags 0x%04X\n", i, g_tev[i].kind, g_tev[i].a, g_tev[i].flags);
}

static int run_selftest(void)
{
	g_testmode = 1;
	g_type_delay = 0;
	InitializeCriticalSection(&g_outLock);
	InitializeCriticalSection(&g_inLock);

	/* scancode table */
	UINT8 sc;
	BOOL ext;
	CHECK(code_to_sc("IntlBackslash", &sc, &ext) && sc == 0x56 && !ext, "IntlBackslash -> 0x56");
	CHECK(code_to_sc("AltRight", &sc, &ext) && sc == 0x38 && ext, "AltRight -> 0x38 ext");
	CHECK(code_to_sc("PrintScreen", &sc, &ext) && sc == 0x37 && ext, "PrintScreen -> 0x37 ext");
	CHECK(code_to_sc("NumpadEqual", &sc, &ext) && sc == 0x59, "NumpadEqual -> 0x59");
	CHECK(code_to_sc("F24", &sc, &ext) && sc == 0x76, "F24 -> 0x76");
	CHECK(code_to_sc("OSLeft", &sc, &ext) && sc == 0x5B && ext, "OSLeft -> Meta");
	CHECK(code_to_sc("Pause", &sc, &ext) && sc == SC_PAUSE, "Pause special");
	CHECK(!code_to_sc("Bogus", &sc, &ext), "unknown code refused");
	{
		/* no duplicate codes in the table */
		int dup = 0;
		for (int i = 0; KMAP[i].code; i++)
			for (int j = i + 1; KMAP[j].code; j++)
				if (strcmp(KMAP[i].code, KMAP[j].code) == 0)
					dup++;
		CHECK(dup == 0, "no duplicate code in the table (%d)", dup);
	}

	/* wheel flags */
	CHECK(wheel_flags(1, FALSE) == 0x0278, "wheel up = 0x0278 (got 0x%04X)", wheel_flags(1, FALSE));
	CHECK(wheel_flags(-1, FALSE) == 0x0388, "wheel down = 0x0388 (got 0x%04X)", wheel_flags(-1, FALSE));
	CHECK(wheel_flags(-1, TRUE) == 0x0588, "hwheel left = 0x0588 (got 0x%04X)", wheel_flags(-1, TRUE));

	/* JSON lines -> events (desktop 800x600) */
	g_desk_w = 800;
	g_desk_h = 600;
	g_ntev = 0;
	CHECK(handle_line("{\"type\":\"key\",\"action\":\"down\",\"code\":\"IntlBackslash\",\"key\":\"<\"}"), "key line parsed");
	CHECK(g_ntev == 1 && g_tev[0].kind == 'k' && g_tev[0].a == 0x56 && g_tev[0].flags == 0, "key down 0x56 press flags 0");
	handle_line("{\"type\":\"key\",\"action\":\"up\",\"code\":\"ControlRight\"}");
	CHECK(g_ntev == 2 && g_tev[1].flags == (KBD_FLAGS_EXTENDED | KBD_FLAGS_RELEASE), "ControlRight up = ext|release");
	g_ntev = 0;
	handle_line("{\"type\":\"mouse\",\"action\":\"move\",\"x\":5000,\"y\":-3}");
	CHECK(g_ntev == 1 && g_tev[0].a == 799 && g_tev[0].b == 0, "mouse clamped to 799,0 (got %u,%u)", g_tev[0].a,
	      g_tev[0].b);
	handle_line("{\"type\":\"mouse\",\"action\":\"scroll\",\"delta\":-1,\"x\":10,\"y\":10}");
	CHECK(g_ntev == 2 && g_tev[1].flags == 0x0388, "scroll down line -> 0x0388");
	handle_line("{\"type\":\"mouse\",\"action\":\"down\",\"button\":2,\"x\":10,\"y\":10}");
	CHECK(g_ntev == 3 && g_tev[2].flags == (PTR_FLAGS_BUTTON2 | PTR_FLAGS_DOWN), "right button down");
	handle_line("{\"type\":\"mouse\",\"action\":\"down\",\"button\":3,\"x\":10,\"y\":10}");
	CHECK(g_ntev == 4 && g_tev[3].kind == 'x' && g_tev[3].flags == (PTR_XFLAGS_BUTTON1 | PTR_XFLAGS_DOWN),
	      "back button = extended XBUTTON1 down");
	g_ntev = 0;
	handle_line("{\"type\":\"release_all\"}");
	{
		int keyups = 0, btn = 0;
		for (int i = 0; i < g_ntev; i++)
		{
			if (g_tev[i].kind == 'k' && (g_tev[i].flags & KBD_FLAGS_RELEASE))
				keyups++;
			if (g_tev[i].kind == 'm' || g_tev[i].kind == 'x')
				btn++;
		}
		CHECK(keyups == 1 && btn == 2, "release_all releases the held key + 2 buttons (keys %d, buttons %d)", keyups,
		      btn);
	}
	g_ntev = 0;
	handle_line("{\"type\":\"sas\"}");
	CHECK(g_ntev == 6 && g_tev[2].a == 0x53 && (g_tev[2].flags & KBD_FLAGS_EXTENDED), "sas = Ctrl+Alt+Del (6 events)");
	g_ntev = 0;
	handle_line("{\"type\":\"key\",\"action\":\"down\",\"code\":\"Pause\"}");
	handle_line("{\"type\":\"key\",\"action\":\"up\",\"code\":\"Pause\"}");
	CHECK(g_ntev == 1 && g_tev[0].kind == 'p', "Pause = one pause sequence");
	CHECK(!handle_line("not json"), "invalid JSON refused");
	g_ntev = 0;
	handle_line("{\"type\":\"whatever\",\"action\":\"down\"}");
	CHECK(g_ntev == 0, "unknown type ignored");

	/* line splitter */
	{
		LineBuf lb = { 0 };
		const char* data = "{\"type\":\"refresh\"}\r\n\n{\"type\":\"refresh\"}\n";
		g_refresh_req = 0;
		feed_bytes(&lb, data, strlen(data), on_input_line);
		CHECK(g_refresh_req == 1, "line splitter: CRLF + empty lines handled");
		char* big = (char*)malloc(MAX_LINE + 100);
		memset(big, 'a', MAX_LINE + 50);
		big[MAX_LINE + 50] = '\n';
		g_refresh_req = 0;
		feed_bytes(&lb, big, MAX_LINE + 51, on_input_line);
		feed_bytes(&lb, data, strlen(data), on_input_line);
		CHECK(g_refresh_req == 1 && lb.len == 0, "oversize line dropped, next lines still parsed");
		free(big);
		free(lb.buf);
	}

	/* layouts */
	test_map("00000409", L'a', "a", TRUE, 0x1E, 0);
	test_map("00000409", L'A', "A", TRUE, 0x1E, 1);
	test_map("00000409", L'@', "@", TRUE, 0x03, 1);
	test_map("00000409", 0x00E9, "e-acute", FALSE, 0, 0);
	test_map("00000409", 0x20AC, "euro", FALSE, 0, 0);
	test_map("00000409", L'<', "<", TRUE, 0x33, 1);
	test_map("0000040C", L'a', "a", TRUE, 0x10, 0);
	test_map("0000040C", L'A', "A", TRUE, 0x10, 1);
	test_map("0000040C", L'@', "@", TRUE, 0x0B, 6);
	test_map("0000040C", 0x00E9, "e-acute", TRUE, 0x03, 0);
	test_map("0000040C", 0x20AC, "euro", TRUE, 0x12, 6);
	test_map("0000040C", L'<', "<", TRUE, 0x56, 0);

	/* typing: newline -> Enter, AltGr sequence, unmapped skipped */
	g_ntev = 0;
	g_unicode_ok = FALSE;
	start_typing("\xE2\x82\xAC\n", "0000040C", NULL); /* "€\n" */
	CHECK(g_ntev == 8 && g_tev[0].a == 0x1D && g_tev[1].a == 0x38 && (g_tev[1].flags & KBD_FLAGS_EXTENDED) &&
	          g_tev[2].a == 0x12 && g_tev[6].a == 0x1C,
	      "type '\\u20ac\\n' (fr): LCtrl, RAlt(ext), E, ..., Enter (%d events)", g_ntev);
	g_ntev = 0;
	start_typing("\xE2\x82\xAC", "00000409", NULL);
	CHECK(g_ntev == 0,"type euro (us, no unicode): skipped");
	g_unicode_ok = TRUE;
	g_ntev = 0;
	start_typing("\xE2\x82\xAC", "00000409", NULL);
	CHECK(g_ntev == 2 && g_tev[0].kind == 'u' && g_tev[0].a == 0x20AC, "type euro (us, unicode server): unicode event");
	g_ntev = 0;
	strcpy(g_layout, "0000040C");
	handle_line("{\"type\":\"key\",\"action\":\"down\",\"code\":\"\",\"key\":\"\xC3\xA9\"}");
	CHECK(g_ntev == 2 && g_tev[0].a == 0x03, "unknown code + key 'e-acute' (layout fr kept): typed via layout");

	/* guest windows (explicit) = same as no guest: LCtrl + RAlt for AltGr */
	g_unicode_ok = FALSE;
	g_ntev = 0;
	handle_line("{\"type\":\"type_text\",\"text\":\"@\",\"layout\":\"0000040C\",\"guest\":\"windows\"}");
	{
		static const UINT16 sc[] = { 0x1D, 0x38, 0x0B, 0x0B, 0x38, 0x1D };
		static const UINT16 fl[] = { 0, KBD_FLAGS_EXTENDED, 0, KBD_FLAGS_RELEASE, KBD_FLAGS_EXTENDED | KBD_FLAGS_RELEASE,
			                         KBD_FLAGS_RELEASE };
		check_seq("guest windows '@' (fr): LCtrl, RAlt(ext), 0x0B, releases", sc, fl, 6);
	}
	/* an unknown guest value = windows */
	g_ntev = 0;
	handle_line("{\"type\":\"type_text\",\"text\":\"@\",\"layout\":\"0000040C\",\"guest\":\"macos\"}");
	CHECK(g_ntev == 6 && g_tev[0].a == 0x1D && !g_guest_linux, "unknown guest -> windows (LCtrl first, %d events)", g_ntev);

	/* guest linux: AltGr = RAlt(ext) alone */
	g_ntev = 0;
	handle_line("{\"type\":\"type_text\",\"text\":\"@\",\"layout\":\"0000040C\",\"guest\":\"linux\"}");
	{
		static const UINT16 sc[] = { 0x38, 0x0B, 0x0B, 0x38 };
		static const UINT16 fl[] = { KBD_FLAGS_EXTENDED, 0, KBD_FLAGS_RELEASE, KBD_FLAGS_EXTENDED | KBD_FLAGS_RELEASE };
		check_seq("guest linux '@' (fr): RAlt(ext), 0x0B, releases, no LCtrl", sc, fl, 4);
	}
	/* guest linux: no unicode fallback, even on a unicode-capable server */
	g_unicode_ok = TRUE;
	g_ntev = 0;
	start_typing("\xE2\x82\xAC", "00000409", "linux");
	CHECK(g_ntev == 0 && g_type_last_skipped == 1, "guest linux euro (us, unicode server): skipped (events %d, skipped %d)",
	      g_ntev, g_type_last_skipped);
	g_ntev = 0;
	start_typing("a\xF0\x9F\x98\x80" "b", "00000409", "linux"); /* "a😀b" */
	CHECK(g_ntev == 4 && g_type_last_skipped == 1, "guest linux emoji: one skipped char, a and b typed (events %d, skipped %d)",
	      g_ntev, g_type_last_skipped);
	/* guest linux: Ctrl-only character (U+0001 = Ctrl+A) skipped; windows unchanged */
	g_ntev = 0;
	handle_line("{\"type\":\"type_text\",\"text\":\"\\u0001\",\"layout\":\"00000409\",\"guest\":\"linux\"}");
	CHECK(g_ntev == 0 && g_type_last_skipped == 1, "guest linux U+0001 (Ctrl-only): skipped (events %d, skipped %d)",
	      g_ntev, g_type_last_skipped);
	g_ntev = 0;
	handle_line("{\"type\":\"type_text\",\"text\":\"\\u0001\",\"layout\":\"00000409\"}");
	CHECK(g_ntev == 4 && g_tev[0].a == 0x1D && g_tev[1].a == 0x1E && g_type_last_skipped == 0,
	      "guest windows U+0001: Ctrl+A as before (events %d)", g_ntev);
	/* guest linux: Backspace / Escape characters are not typed */
	g_ntev = 0;
	start_typing("\x08\x1B", "00000409", "linux");
	CHECK(g_ntev == 0 && g_type_last_skipped == 2, "guest linux BS + ESC chars: skipped (events %d, skipped %d)", g_ntev,
	      g_type_last_skipped);
	/* dead keys: '^' on fr = dead circumflex -> the key then Space (both guests) */
	{
		static const UINT16 sc[] = { 0x1A, 0x1A, 0x39, 0x39 };
		static const UINT16 fl[] = { 0, KBD_FLAGS_RELEASE, 0, KBD_FLAGS_RELEASE };
		g_ntev = 0;
		start_typing("^", "0000040C", "linux");
		check_seq("guest linux '^' (fr, dead key): ^ then Space", sc, fl, 4);
		g_ntev = 0;
		start_typing("^", "0000040C", "windows");
		check_seq("guest windows '^' (fr, dead key): ^ then Space", sc, fl, 4);
	}
	{
		/* '~' on fr = AltGr + 2 (dead tilde) */
		static const UINT16 sc[] = { 0x38, 0x03, 0x03, 0x38, 0x39, 0x39 };
		static const UINT16 fl[] = { KBD_FLAGS_EXTENDED, 0, KBD_FLAGS_RELEASE, KBD_FLAGS_EXTENDED | KBD_FLAGS_RELEASE, 0,
			                         KBD_FLAGS_RELEASE };
		g_ntev = 0;
		start_typing("~", "0000040C", "linux");
		check_seq("guest linux '~' (fr, AltGr dead key): RAlt, 0x03, releases, Space", sc, fl, 6);
	}
	/* the dead-key probe leaves no dead state behind, non-dead keys untouched */
	{
		const HKL fr = layout_handle("0000040C");
		CHECK(dead_key_kind(fr, L'e', 0) == 0, "after the probes: 'e' (fr) is not dead");
		CHECK(dead_key_kind(fr, 0x00E9, 0) == 0 && dead_key_kind(fr, L'@', 6) == 0, "e-acute / '@' (fr) not dead");
		CHECK(dead_key_kind(layout_handle("00000409"), L'^', 1) == 0, "'^' (us) not dead");
		g_ntev = 0;
		start_typing("e^e", "0000040C", "linux");
		CHECK(g_ntev == 8 && g_tev[0].a == 0x12 && g_tev[6].a == 0x12, "guest linux 'e^e' (fr): e, ^, Space, e (%d events)",
		      g_ntev);
	}
	/* a later type_text without guest is windows again */
	g_ntev = 0;
	g_unicode_ok = TRUE;
	start_typing("\xE2\x82\xAC", "00000409", NULL);
	CHECK(g_ntev == 2 && g_tev[0].kind == 'u' && !g_guest_linux, "no guest after linux: windows again (unicode event)");

	printf("%s: %d failure(s)\n", g_fail ? "SELFTEST FAILED" : "SELFTEST OK", g_fail);
	return g_fail ? 1 : 0;
}

/* ── main ───────────────────────────────────────────────────────────────── */

static int run_session_loop(freerdp* instance)
{
	rdpContext* ctx = instance->context;
	while (!freerdp_shall_disconnect_context(ctx))
	{
		HANDLE handles[64];
		DWORD n = freerdp_get_event_handles(ctx, handles, 64);
		if (n == 0)
			return 0;
		DWORD timeout = 1000;
		if (g_dirty || g_refresh_req)
		{
			const ULONGLONG el = GetTickCount64() - g_last_encode;
			timeout = el >= FRAME_INTERVAL_MS ? 0 : (DWORD)(FRAME_INTERVAL_MS - el);
		}
		if (WaitForMultipleObjects(n, handles, FALSE, timeout) == WAIT_FAILED)
			return 0;
		if (!freerdp_check_event_handles(ctx))
			return 0;
		if ((g_dirty || g_refresh_req) && GetTickCount64() - g_last_encode >= FRAME_INTERVAL_MS)
		{
			if (g_refresh_req)
				g_dirty = 1;
			if (!encode_now(ctx))
				return -1;
		}
	}
	return 0;
}

static void emit_connected(freerdp* instance)
{
	rdpContext* ctx = instance->context;
	g_unicode_ok = freerdp_settings_get_bool(ctx->settings, FreeRDP_UnicodeInput);
	const int w = ctx->gdi ? (int)ctx->gdi->width : 0;
	const int h = ctx->gdi ? (int)ctx->gdi->height : 0;
	InterlockedExchange(&g_desk_w, w);
	InterlockedExchange(&g_desk_h, h);
	emit_status("{\"state\":\"connected\",\"width\":%d,\"height\":%d,\"unicode\":%s}", w, h,
	            g_unicode_ok ? "true" : "false");
}

int main(int argc, char** argv)
{
	if (argc >= 2 && strcmp(argv[1], "--selftest") == 0)
		return run_selftest();
	if (argc >= 2 && strcmp(argv[1], "--version") == 0)
	{
		printf("vmconsole protocol=%d\n", PROTOCOL_VERSION);
		return 0;
	}
	if (argc < 2)
	{
		fprintf(stderr, "usage: vmconsole <vm-guid> [out.h264|-] [maxframes] [host] | --selftest | --version\n");
		return 2;
	}
	const char* guid = argv[1];
	const char* out = (argc > 2) ? argv[2] : "out.h264";
	if (argc > 3)
		g_maxframes = atoi(argv[3]);
	const char* host = (argc > 4) ? argv[4] : "127.0.0.1";
	{
		const char* d = getenv("VMCONSOLE_TYPE_DELAY_MS");
		if (d && *d)
		{
			const int v = atoi(d);
			if (v >= 0 && v <= 1000)
				g_type_delay = (DWORD)v;
		}
	}

	InitializeCriticalSection(&g_outLock);
	InitializeCriticalSection(&g_inLock);

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		fprintf(stderr, "WSAStartup failed\n");
		return 5;
	}

	if (strcmp(out, "-") == 0)
	{
		g_stream = 1;
		/* The framed byte stream gets a PRIVATE duplicate of the stdout pipe,
		 * then fd 1 / STD_OUTPUT_HANDLE are pointed at stderr: anything else
		 * that writes to "stdout" (FreeRDP's WLog console appender, a stray
		 * printf in a library) lands in the diagnostics, never inside the
		 * frames. Seen on Server 2025: a WLog line "[16:58:51:284]
		 * [ERRO..." on stdout was read by the agent as a frame header of
		 * 893007409 bytes ("16:5") and the console closed before its first
		 * picture. */
		int fdFrames = _dup(_fileno(stdout));
		if (fdFrames < 0 || !(g_out = _fdopen(fdFrames, "wb")))
		{
			fprintf(stderr, "cannot duplicate stdout for the frame stream\n");
			return 6;
		}
		_setmode(fdFrames, _O_BINARY); /* no CRLF translation on the byte stream */
		setvbuf(g_out, NULL, _IOFBF, 1 << 16);
		fflush(stdout);
		_dup2(_fileno(stderr), _fileno(stdout));
		SetStdHandle(STD_OUTPUT_HANDLE, GetStdHandle(STD_ERROR_HANDLE));
		/* And FreeRDP's own logger explicitly on stderr (its console appender
		 * picks stdout for the lower levels by default). */
		{
			wLog* root = WLog_GetRoot();
			if (root && WLog_SetLogAppenderType(root, WLOG_APPENDER_CONSOLE))
			{
				wLogAppender* app = WLog_GetLogAppender(root);
				if (app)
					WLog_ConfigureAppender(app, "outputstream", (void*)"stderr");
			}
		}
	}
	else
	{
		g_out = fopen(out, "wb");
		if (!g_out)
		{
			fprintf(stderr, "cannot open output %s\n", out);
			return 6;
		}
		if (g_maxframes <= 0)
			g_maxframes = 1; /* file mode: default capture one frame */
	}

	freerdp* instance = freerdp_new();
	if (!instance)
		return 3;
	instance->ContextSize = sizeof(vmCtx);
	instance->PostConnect = vm_post_connect;
	instance->Authenticate = vm_authenticate;
	instance->VerifyCertificateEx = vm_verify_cert_ex;

	if (!freerdp_context_new(instance))
	{
		freerdp_free(instance);
		return 3;
	}
	g_instance = instance;

	rdpSettings* s = instance->context->settings;
	freerdp_settings_set_string(s, FreeRDP_ServerHostname, host);
	freerdp_settings_set_uint32(s, FreeRDP_ServerPort, 2179);
	freerdp_settings_set_bool(s, FreeRDP_VmConnectMode, TRUE);
	freerdp_settings_set_string(s, FreeRDP_PreconnectionBlob, guid);
	freerdp_settings_set_bool(s, FreeRDP_SendPreconnectionPdu, TRUE);
	freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE);
	freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, TRUE);
	freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, TRUE);
	freerdp_settings_set_bool(s, FreeRDP_NegotiateSecurityLayer, FALSE);
	freerdp_settings_set_bool(s, FreeRDP_UnicodeInput, TRUE); /* we can send it; the server says if it takes it */

	{
		const char* u = getenv("FRDP_USER");
		const char* p = getenv("FRDP_PASS");
		const char* d = getenv("FRDP_DOMAIN");
		if (u && *u)
			freerdp_settings_set_string(s, FreeRDP_Username, u);
		if (p && *p)
			freerdp_settings_set_string(s, FreeRDP_Password, p);
		if (d && *d)
			freerdp_settings_set_string(s, FreeRDP_Domain, d);
	}

	/* The input reader starts first: a closed stdin aborts even a connect
	 * still in progress. */
	g_input = instance->context->input;
	if (g_stream)
	{
		HANDLE th = CreateThread(NULL, 0, stdin_thread, NULL, 0, NULL);
		if (th)
			CloseHandle(th);
	}

	emit_status("{\"state\":\"connecting\"}");
	int rc = 0;
	if (!freerdp_connect(instance))
	{
		const UINT32 err = freerdp_get_last_error(instance->context);
		const UINT32 info = freerdp_error_info(instance);
		fprintf(stderr, "CONNECT FAILED: 0x%08x (errinfo 0x%08x) %s\n", (unsigned)err, (unsigned)info, err_text(err));
		if (g_stdin_closed)
			rc = 0;
		else
		{
			if (is_other_connection(err, info))
				emit_ended("other_connection", "Another connection holds the VM console", err);
			else if (is_auth_error(err, info))
				emit_ended("auth_failed", err_text(err), err);
			else
				emit_ended("connect_failed", err_text(err), err);
			rc = 4;
		}
		goto done;
	}
	emit_connected(instance);

	for (;;)
	{
		if (run_session_loop(instance) < 0)
		{
			rc = 7;
			break;
		}
		if (g_stdin_closed || g_out_broken || (g_maxframes > 0 && g_frames >= g_maxframes))
		{
			rc = g_out_broken ? 6 : 0;
			if (g_stdin_closed && g_stream)
				emit_ended("stdin_closed", "Input closed by the agent", 0);
			break;
		}
		const UINT32 err = freerdp_get_last_error(instance->context);
		const UINT32 info = freerdp_error_info(instance);
		fprintf(stderr, "connection lost: 0x%08x (errinfo 0x%08x) %s\n", (unsigned)err, (unsigned)info,
		        err_text(err));
		if (is_other_connection(err, info))
		{
			emit_ended("other_connection", "Another connection took over the VM console", err);
			rc = 7;
			break;
		}
		if (is_auth_error(err, info))
		{
			emit_ended("auth_failed", err_text(err), err);
			rc = 7;
			break;
		}
		if (!g_stream)
		{
			rc = 7;
			break;
		}
		/* Unexpected loss (VM rebooting / turned off and on): try again. */
		EnterCriticalSection(&g_inLock);
		memset(g_keydown, 0, sizeof(g_keydown));
		g_buttons = 0;
		LeaveCriticalSection(&g_inLock);
		const ULONGLONG start = GetTickCount64();
		int attempt = 0;
		BOOL back = FALSE;
		while (!g_stdin_closed && !g_out_broken && GetTickCount64() - start < RECONNECT_WINDOW_MS)
		{
			attempt++;
			emit_status("{\"state\":\"reconnecting\",\"attempt\":%d,\"reason\":\"server_closed\"}", attempt);
			if (freerdp_reconnect(instance))
			{
				back = TRUE;
				break;
			}
			const UINT32 e2 = freerdp_get_last_error(instance->context);
			if (is_other_connection(e2, freerdp_error_info(instance)))
				break;
			for (int i = 0; i < RECONNECT_EVERY_MS / 100 && !g_stdin_closed; i++)
				Sleep(100);
		}
		if (g_stdin_closed)
		{
			rc = 0;
			break;
		}
		if (!back)
		{
			const UINT32 e3 = freerdp_get_last_error(instance->context);
			if (is_other_connection(e3, freerdp_error_info(instance)))
				emit_ended("other_connection", "Another connection took over the VM console", e3);
			else
				emit_ended("reconnect_failed", "The VM console did not come back", e3);
			rc = 7;
			break;
		}
		/* Same instance, maybe a new size: new keyframe + init. */
		g_init_sent = 0;
		g_force_idr = 1;
		g_dirty = 1;
		InterlockedExchange(&g_refresh_req, 1);
		emit_connected(instance);
	}

	freerdp_disconnect(instance);
done:
	stop_typing();
	close_encoder();
	if (g_out && g_out != stdout)
		fclose(g_out);
	g_instance = NULL;
	if (instance->context && instance->context->gdi)
		gdi_free(instance);
	freerdp_context_free(instance);
	freerdp_free(instance);
	if (!g_stream)
		fprintf(stderr, "DONE — %d H.264 frame(s) -> %s\n", g_frames, out);
	return rc;
}
