# P2P File Transfer

*Simple • Powerful • Peer-to-Peer*

alright so look, this is a simple peer-to-peer file transfer application that lets two users directly share files over a TCP connection without any intermediary server. one person sends, one person receives. that's it.

## ⚠️ Important Notice

**this is an experimental project and NOT production-ready.** it's a learning project to understand socket programming and P2P file transfer concepts. use it at your own risk.

found bugs? got ideas? want to contribute? feel free to [raise an issue](https://github.com/aadityansha06/Peer-2-peer-file-transfer/issues) or submit a pull request. all feedback is welcome!

## Installation

```bash
git clone https://github.com/aadityansha06/Peer-2-peer-file-transfer.git
cd Peer-2-peer-file-transfer
zig build
```

## How It Works

basically here's the deal - you got two users right? one's gonna be the sender (User A) and the other's the receiver (User B). here's what happens:

**the receiver starts first** - they fire up the program, choose "accept" mode, and it starts listening on port 9090. they share their IP address with the sender.

**then the sender does their thing** - they start the program, choose "send" mode, enter the receiver's IP, and select the file they wanna transfer.

**here's where it gets interesting** - instead of loading the entire file into memory (which would be insane for large files), the sender reads it in **16KB chunks** (pages). this is way more efficient and handles large files like a champ.

**the handshake** - first, the sender shoots over a header containing:
- the file name (with extension)
- the total file size

the receiver gets this, creates a file with the same name, allocates memory, and sends back a response code `1` saying "yo, i'm ready, send the data"

**the actual transfer** - now the sender starts pumping out the file data in 16KB chunks. the receiver catches each chunk, writes it to the file, and keeps track of how many bytes have been written. this loop keeps running until all the received bytes equal the total file size.

**the confirmation** - once everything's received and written, the receiver sends back a `100 OK` status. if something went wrong, it sends a `400 FAIL` instead.

**cleanup** - both sides close their connections and we're done.

## Flow Chart

<img width="1094" height="743" alt="image" src="https://github.com/user-attachments/assets/62b12c82-bd72-4d99-942a-7923228e6463" />



## Key Features

**chunked transfer** - files are read and sent in 16KB pages, so you're not loading massive files into RAM all at once. memory efficient af.

**progress tracking** - the receiver shows real-time progress as bytes come in and get written to disk.

**error handling** - if the connection drops or something goes wrong, both sides know about it with proper response codes.

**permission management** - the receiver temporarily grants write permissions if needed, then restores the original permissions after transfer.

**file integrity** - we verify that the total bytes received matches what was promised in the header.

## Technical Details

**protocol**: TCP (reliable, connection-oriented)

**port**: 9090 (hardcoded for now)

**buffer size**: 16KB (16,384 bytes)

**response codes**:
- `1` = RESPONSE1_OK (ready to receive)
- `100` = TRANSFER_SUCCESS (file transferred successfully)
- `400` = TRANSFER_FAIL (something went wrong)

## The Architecture

here's what makes this thing tick:

**sender side**:
1. opens the file in binary read mode
2. gets the total file size using fseek/ftell
3. establishes TCP connection to receiver
4. sends header with file metadata
5. waits for green light (response code 1)
6. reads file in 16KB chunks and sends each one
7. waits for final confirmation
8. closes everything

**receiver side**:
1. binds to port 9090 and starts listening
2. accepts incoming connection
3. receives header and parses file info
4. sends response code 1 (ready)
5. creates the output file
6. enters a loop: receive chunk → write to file → update counter
7. continues until received_bytes == total_file_size
8. sends final status (100 or 400)
9. closes everything

## Usage

**step 1 - receiver**: run the program, choose option 2 (receiver mode), note your IP address

**step 2 - sender**: run the program, choose option 1 (sender mode), enter receiver's IP and file path

**step 3 - wait**: watch the magic happen as chunks transfer and progress updates

**step 4 - done**: both sides confirm and close

## Why 16KB Chunks?

because that's a standard page size on most systems and it's a sweet spot between:
- making too many small reads (inefficient)
- loading huge chunks (memory hungry)

plus it gives smooth progress updates without overwhelming the network or disk I/O.

## Future Improvements

some ideas for making this even better:
- encryption for secure transfers
- resume capability if connection drops
- multiple file transfer in one session
- compression on the fly
- GUI instead of terminal
- configurable port and buffer size
- IPv6 support

## Dependencies

you'll need:
- standard C libraries (stdio, stdlib, unistd)
- socket libraries (sys/socket.h, netinet/in.h, arpa/inet.h)
- linux/limits.h for PATH_MAX
- custom header files (lib/header.h, lib/ui.h)

## Compiling

**on linux**:
```bash
gcc -o p2p_transfer transfer.c -Wall -Wextra
```

if you get linking errors, you might need:
```bash
gcc -o p2p_transfer transfer.c -Wall -Wextra -lpthread
```

**on android (termux)**:

first install the necessary packages:
```bash
pkg update
pkg install clang
```

then compile:
```bash
clang -o p2p_transfer transfer.c -Wall -Wextra
```

run it:
```bash
./p2p_transfer
```

## Notes

- receiver MUST start before sender (it's listening for the connection)
- both machines need to be on the same network (or have proper port forwarding set up)
- file permissions are temporarily modified if needed, then restored
- progress is shown in real-time on the receiver side
- the application handles binary files just fine (images, videos, executables, whatever)

## Troubleshooting

**"Bind failed: Address already in use"**

this happens when port 9090 is already being used by another process (maybe you didn't close the previous session properly). here's how to fix it:

**on linux**:

first, find which process is using the port:
```bash
sudo lsof -i :9090
```

or

```bash
sudo netstat -tulpn | grep 9090
```

you'll see something like:
```
tcp  0  0  0.0.0.0:9090  0.0.0.0:*  LISTEN  12345/p2p_transfer
```

that `12345` is the PID (process ID). kill it:
```bash
sudo kill 12345
```

if it's being stubborn:
```bash
sudo kill -9 12345
```

**on android (termux)**:

termux doesn't need sudo, so just:
```bash
lsof -i :9090
```

or

```bash
netstat -tulpn | grep 9090
```

then kill it:
```bash
kill 12345
```

or force kill:
```bash
kill -9 12345
```

**"Connection refused"**

- make sure the receiver started first
- check if firewall is blocking port 9090
- verify both devices are on the same network
- double-check the IP address you entered

**on linux**:
```bash
sudo ufw allow 9090/tcp
```

**"Permission denied" when creating file**

the receiver tries to handle this automatically, but if it still fails:
- check if you have write permissions in the current directory
- try running from a directory where you have write access
- on linux, you might need to run with sudo (not recommended though)

**file transfer hangs or freezes**

- network connection might be unstable
- try transferring a smaller file first to test
- check if both programs are still running (not crashed)
- restart both sender and receiver

**wrong file size or corrupted file**

- could be a network issue interrupting the transfer
- verify the source file isn't corrupted
- try the transfer again
- check available disk space on receiver side

---

that's pretty much it. simple P2P file transfer without any cloud nonsense or third-party servers. direct connection, direct transfer. old school but it works.
