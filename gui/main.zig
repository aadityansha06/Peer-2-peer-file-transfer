const std = @import("std");
const sdl = @import("sdl.zig").sdl;
const font_mod = @import("font.zig");
const backend = @cImport({
    @cInclude("backend.h");
});

const PORT_DISCOVERY = 9091;
const PORT_TRANSFER = 9090;

const Tab = enum {
    sender,
    receiver,
};

const Peer = struct {
    ip: [16]u8,
    hostname: [64]u8,
    last_seen: i64,
    mode: Tab,
};

var peers: std.ArrayListUnmanaged(Peer) = .empty;
var peers_allocator: std.mem.Allocator = undefined;
var peers_mutex = std.Thread.Mutex{};

var current_tab = Tab.sender;
var selected_file: [1024]u8 = [_]u8{0} ** 1024;
var has_selected_file = false;
var selected_peer_ip: ?[16]u8 = null;
var is_listening = false;

const embedded_font = @embedFile("font.ttf");
var font_mgr: font_mod.FontManager = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    peers_allocator = allocator;

    if (!sdl.SDL_Init(sdl.SDL_INIT_VIDEO | sdl.SDL_INIT_EVENTS)) {
        std.debug.print("SDL could not initialize! SDL_Error: {s}\n", .{sdl.SDL_GetError()});
        return error.SDLInitFailed;
    }
    defer sdl.SDL_Quit();

    if (!sdl.TTF_Init()) {
        std.debug.print("TTF could not initialize! SDL_Error: {s}\n", .{sdl.SDL_GetError()});
        return error.TTFInitFailed;
    }
    defer sdl.TTF_Quit();

    font_mgr = try font_mod.FontManager.init(embedded_font, 18);
    defer font_mgr.deinit();

    const window = sdl.SDL_CreateWindow("Peer-2-Peer File Transfer", 800, 600, sdl.SDL_WINDOW_RESIZABLE) orelse {
        std.debug.print("Window could not be created! SDL_Error: {s}\n", .{sdl.SDL_GetError()});
        return error.SDLWindowCreationFailed;
    };
    defer sdl.SDL_DestroyWindow(window);

    const renderer = sdl.SDL_CreateRenderer(window, null) orelse {
        std.debug.print("Renderer could not be created! SDL_Error: {s}\n", .{sdl.SDL_GetError()});
        return error.SDLRendererCreationFailed;
    };
    defer sdl.SDL_DestroyRenderer(renderer);

    // Start discovery thread
    const discovery_thread = try std.Thread.spawn(.{}, discoveryWorker, .{});
    discovery_thread.detach();

    // Start beacon thread (to be discoverable)
    const beacon_thread = try std.Thread.spawn(.{}, beaconWorker, .{});
    beacon_thread.detach();

    var quit = false;
    var event: sdl.SDL_Event = undefined;

    while (!quit) {
        while (sdl.SDL_PollEvent(&event)) {
            if (event.type == sdl.SDL_EVENT_QUIT) {
                quit = true;
            } else if (event.type == sdl.SDL_EVENT_MOUSE_BUTTON_DOWN) {
                handleMouseClick(event.button.x, event.button.y);
            }
        }

        _ = sdl.SDL_SetRenderDrawColor(renderer, 40, 40, 40, 255);
        _ = sdl.SDL_RenderClear(renderer);

        drawUI(renderer);

        _ = sdl.SDL_RenderPresent(renderer);
        sdl.SDL_Delay(16);
    }
}

fn handleMouseClick(x: f32, y: f32) void {
    if (y >= 10 and y <= 50) {
        if (x >= 10 and x <= 150) {
            current_tab = .sender;
        } else if (x >= 160 and x <= 300) {
            current_tab = .receiver;
        }
    }

    if (current_tab == .sender) {
        if (y >= 100 and y <= 140) {
            if (x >= 10 and x <= 200) {
                selectFile();
            } else if (x >= 210 and x <= 350) {
                // SEND button
                if (has_selected_file and selected_peer_ip != null) {
                    startSending(selected_peer_ip.?);
                }
            }
        }
        
        peers_mutex.lock();
        defer peers_mutex.unlock();
        var py: f32 = 210;
        for (peers.items) |peer| {
            if (peer.mode == .receiver) {
                if (y >= py and y <= py + 30 and x >= 10 and x <= 780) {
                    selected_peer_ip = peer.ip;
                }
                py += 40;
            }
        }
    } else {
        if (y >= 100 and y <= 140) {
            if (x >= 10 and x <= 220) {
                startReceiving();
            }
        }
    }
}

fn drawUI(renderer: *sdl.SDL_Renderer) void {
    drawButton(renderer, "SENDER", 10, 10, 140, 40, current_tab == .sender);
    drawButton(renderer, "RECEIVER", 160, 10, 140, 40, current_tab == .receiver);

    if (current_tab == .sender) {
        font_mgr.drawText(renderer, "SENDER MODE", 10, 70, .{ .r = 255, .g = 255, .b = 255, .a = 255 });
        drawButton(renderer, "SELECT FILE", 10, 100, 190, 40, false);
        
        const send_active = has_selected_file and selected_peer_ip != null;
        drawButton(renderer, "SEND", 210, 100, 140, 40, send_active);

        if (has_selected_file) {
            const path_slice = std.mem.sliceTo(&selected_file, 0);
            font_mgr.drawText(renderer, path_slice, 10, 150, .{ .r = 200, .g = 200, .b = 200, .a = 255 });
        }

        if (selected_peer_ip) |ip| {
            var buf: [64]u8 = undefined;
            const ip_slice = std.mem.sliceTo(&ip, 0);
            const text = std.fmt.bufPrint(&buf, "Target: {s}", .{ip_slice}) catch "Error";
            font_mgr.drawText(renderer, text, 360, 110, .{ .r = 142, .g = 192, .b = 124, .a = 255 });
        }

        font_mgr.drawText(renderer, "AVAILABLE RECEIVERS:", 10, 180, .{ .r = 250, .g = 189, .b = 47, .a = 255 });
        
        peers_mutex.lock();
        defer peers_mutex.unlock();
        var y: f32 = 210;
        for (peers.items) |peer| {
            if (peer.mode == .receiver) {
                var buf: [128]u8 = undefined;
                const ip_slice = std.mem.sliceTo(&peer.ip, 0);
                const host_slice = std.mem.sliceTo(&peer.hostname, 0);
                const text = std.fmt.bufPrint(&buf, "{s} ({s})", .{ host_slice, ip_slice }) catch "Error";
                
                const is_selected = if (selected_peer_ip) |sip| std.mem.eql(u8, std.mem.sliceTo(&sip, 0), std.mem.sliceTo(&peer.ip, 0)) else false;
                drawButton(renderer, text, 10, y, 780, 30, is_selected);
                y += 40;
            }
        }
    } else {
        font_mgr.drawText(renderer, "RECEIVER MODE", 10, 70, .{ .r = 255, .g = 255, .b = 255, .a = 255 });
        drawButton(renderer, "START LISTENING", 10, 100, 220, 40, is_listening);
        
        if (is_listening) {
            font_mgr.drawText(renderer, "STATUS: LISTENING ON PORT 9090...", 10, 160, .{ .r = 142, .g = 192, .b = 124, .a = 255 });
        } else {
            font_mgr.drawText(renderer, "STATUS: IDLE. CLICK BUTTON TO START.", 10, 160, .{ .r = 251, .g = 73, .b = 52, .a = 255 });
        }
    }
}

fn drawButton(renderer: *sdl.SDL_Renderer, text: []const u8, x: f32, y: f32, w: f32, h: f32, active: bool) void {
    const rect = sdl.SDL_FRect{ .x = x, .y = y, .w = w, .h = h };
    if (active) {
        _ = sdl.SDL_SetRenderDrawColor(renderer, 142, 192, 124, 255);
    } else {
        _ = sdl.SDL_SetRenderDrawColor(renderer, 102, 92, 84, 255);
    }
    _ = sdl.SDL_RenderFillRect(renderer, &rect);
    _ = sdl.SDL_SetRenderDrawColor(renderer, 235, 219, 178, 255);
    _ = sdl.SDL_RenderRect(renderer, &rect);
    
    const text_x = x + 10;
    const text_y = y + (h - 18) / 2;
    font_mgr.drawText(renderer, text, text_x, text_y, .{ .r = 255, .g = 255, .b = 255, .a = 255 });
}

fn selectFile() void {
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "zenity", "--file-selection", "--title=Select File to Send" },
    }) catch return;

    if (result.stdout.len > 0) {
        const path = std.mem.trim(u8, result.stdout, "\n\r ");
        if (path.len < selected_file.len) {
            @memcpy(selected_file[0..path.len], path);
            selected_file[path.len] = 0;
            has_selected_file = true;
        }
    }
}

fn startSending(ip: [16]u8) void {
    _ = std.Thread.spawn(.{}, struct {
        fn run(target_ip: [16]u8, file_path_ptr: [*]const u8) void {
            const ip_slice = std.mem.sliceTo(&target_ip, 0);
            const file_path = std.mem.span(@as([*:0]const u8, @ptrCast(file_path_ptr)));
            
            var ip_buf: [17]u8 = [_]u8{0} ** 17;
            @memcpy(ip_buf[0..ip_slice.len], ip_slice);
            
            backend.sender(&ip_buf[0], file_path.ptr);
        }
    }.run, .{ ip, &selected_file }) catch return;
}

fn startReceiving() void {
    if (is_listening) return;
    _ = std.Thread.spawn(.{}, struct {
        fn run() void {
            is_listening = true;
            backend.reciver();
            is_listening = false;
        }
    }.run, .{}) catch return;
}

fn discoveryWorker() void {
    const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return;
    defer std.posix.close(socket);

    var addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, PORT_DISCOVERY),
        .addr = 0, // INADDR_ANY
    };
    
    std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(i32, 1))) catch {};

    std.posix.bind(socket, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in)) catch return;

    var buf: [1024]u8 = undefined;
    while (true) {
        var from_addr: std.posix.sockaddr.in = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.posix.recvfrom(socket, &buf, 0, @ptrCast(&from_addr), &from_len) catch continue;
        if (n > 0) {
            const msg = buf[0..n];
            if (std.mem.startsWith(u8, msg, "PEER_INFO:")) {
                var it = std.mem.splitScalar(u8, msg[10..], ':');
                const hostname = it.next() orelse continue;
                
                var ip_buf: [16]u8 = [_]u8{0} ** 16;
                const ip_ptr = @as(*const [4]u8, @ptrCast(&from_addr.addr));
                _ = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3] }) catch continue;

                peers_mutex.lock();
                var found = false;
                for (peers.items) |*peer| {
                    if (std.mem.eql(u8, std.mem.sliceTo(&peer.ip, 0), std.mem.sliceTo(&ip_buf, 0))) {
                        peer.last_seen = std.time.timestamp();
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    var new_peer = Peer{
                        .ip = ip_buf,
                        .last_seen = std.time.timestamp(),
                        .mode = .receiver, // Discovery only hears receivers now
                        .hostname = [_]u8{0} ** 64,
                    };
                    @memcpy(new_peer.hostname[0..@min(hostname.len, 63)], hostname[0..@min(hostname.len, 63)]);
                    peers.append(peers_allocator, new_peer) catch {};
                }
                peers_mutex.unlock();
            }
        }
    }
}

fn beaconWorker() void {
    const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return;
    defer std.posix.close(socket);

    std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.BROADCAST, &std.mem.toBytes(@as(i32, 1))) catch {};

    var addr = std.posix.sockaddr.in{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, PORT_DISCOVERY),
        .addr = 0xFFFFFFFF, // 255.255.255.255
    };

    var hostname_buf: [64]u8 = [_]u8{0} ** 64;
    const hostname = std.posix.gethostname(&hostname_buf) catch hostname_buf[0..0];

    while (true) {
        // Only broadcast if in Receiver mode AND actively listening on port 9090
        if (current_tab == .receiver and is_listening) {
            var msg_buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "PEER_INFO:{s}:RECEIVER", .{ hostname }) catch continue;
            
            _ = std.posix.sendto(socket, msg, 0, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in)) catch continue;
        }
        std.Thread.sleep(2 * std.time.ns_per_s);
    }
}
