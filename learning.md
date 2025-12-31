  /*A file descriptor (FD) is just an integer that represents an open resource in your program — such as:

files

sockets

pipes

Linux treats almost everything like a file, including network sockets.

🧠 Why 3?

In every program, the first three file descriptors are already in use:

FD	Meaning
0	stdin
1	stdout
2	stderr

So the next available file descriptor is 3.
Your socket is the fourth open resource, so it becomes FD 3.*/



To talk with aclient we will use  clientfd (client file discriptor)



It allows your server to reuse the port immediately, even if it’s in the TIME_WAIT state.

Normally, when you close a server on port 7070 and restart it quickly, you get:

Bind failed: Address already in use


Because the port enters TIME_WAIT for ~60 seconds.

SO_REUSEADDR fixes this.

✔️ After enabling it:

You can restart your server instantly.

No waiting.

No errors.

🧠 Why TIME_WAIT happens?

When a TCP connection closes, the OS keeps the port reserved for a bit to avoid old packets being mixed with new ones.

This is why port reuse is blocked by default.

🛠 Use it like this:
int opt = 1;
setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));


Place it right after creating the socket and before bind():

int sockfd = socket(AF_INET, SOCK_STREAM, 0);

int opt = 1;
setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

bind(sockfd, ...);



IGINT  = Signal Interrupt (Ctrl+C)
SIGTERM = Signal Terminate (kill command)
```

When you kill a process, the OS sends these signals. By default, your program exits **immediately** without cleanup.

#include <unistd.h>
#include <signal.h>

### 2. **Why Ports Stay "In Use"**
```
Normal flow:
Server running → bind() locks port 7070 → You press Ctrl+C → 
Program exits IMMEDIATELY → close(sockfd) never called → 
Port 7070 still locked by OS → "Address already in use" error
3. Signal Handlers - Catching the Kill Signal
Think of it like this:
c// Without handler:
Ctrl+C pressed → Program dies instantly → No cleanup

// With handler:
Ctrl+C pressed → Your function runs first → close(sockfd) → Then exit
4. What You Need to Add:
Step 1: Make socket global
cint sockfd;  // Move outside main() so signal handler can access it
Step 2: Create cleanup function
cvoid cleanup_handler(int sig) {
    printf("\nShutting down...\n");
    close(sockfd);  // This releases the port!
    exit(0);
}



Step 3: Register handlers at start of main()
csignal(SIGINT, cleanup_handler);   // Catches Ctrl+C
signal(SIGTERM, cleanup_handler);  // Catches kill command

