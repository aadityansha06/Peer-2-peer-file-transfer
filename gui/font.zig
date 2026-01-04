const std = @import("std");
const sdl = @import("sdl.zig").sdl;

pub const FontManager = struct {
    font: ?*sdl.TTF_Font = null,
    
    pub fn init(font_data: []const u8, size: f32) !FontManager {
        const stream = sdl.SDL_IOFromConstMem(font_data.ptr, font_data.len) orelse {
            return error.SDLIOCreateFailed;
        };
        const font = sdl.TTF_OpenFontIO(stream, true, size) orelse {
            const err = sdl.SDL_GetError();
            std.debug.print("TTF_OpenFontIO failed: {s}\n", .{err});
            return error.FontLoadFailed;
        };
        return FontManager{ .font = font };
    }

    pub fn deinit(self: *FontManager) void {
        if (self.font) |f| {
            sdl.TTF_CloseFont(f);
        }
    }

    pub fn drawText(self: *FontManager, renderer: *sdl.SDL_Renderer, text: []const u8, x: f32, y: f32, color: sdl.SDL_Color) void {
        if (self.font == null) return;
        if (text.len == 0) return;

        const c_text = std.heap.page_allocator.dupeZ(u8, text) catch return;
        defer std.heap.page_allocator.free(c_text);

        const surface = sdl.TTF_RenderText_Blended(self.font, c_text.ptr, 0, color) orelse return;
        defer sdl.SDL_DestroySurface(surface);

        const texture = sdl.SDL_CreateTextureFromSurface(renderer, surface) orelse return;
        defer sdl.SDL_DestroyTexture(texture);

        var w: f32 = 0;
        var h: f32 = 0;
        _ = sdl.SDL_GetTextureSize(texture, &w, &h);

        const dst_rect = sdl.SDL_FRect{ .x = x, .y = y, .w = w, .h = h };
        _ = sdl.SDL_RenderTexture(renderer, texture, null, &dst_rect);
    }
};