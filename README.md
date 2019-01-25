# SHA256 for all ATARIs
## What it is
A port from Amiga project: https://github.com/Leffmann/SHA256

Very few things changed; freely adapted to ST series.

All SHA256 calculations are performed in 68000 assembly code.


## How to use it?
sha256.prg is intended to be ran from a shell but it works also on plain TOS (just double-click on sha256.prg or drap&drop files to it).

Syntax:

sha256.prg <file1> <file2> ... <filen>
  
If no parameters are passed, sha256.prg will simply compute SHA256 on test vectors and estimate the SHA256 speed.

e.g.:

```
sha256.prg
```
Test mode:
SHA256()=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855...OK 

SHA256(abc)=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad...OK 

SHA256(abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq)=248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1...OK 

SHA256(abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu)=cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1...OK 

All test vectors OK

Perfomance tests:

SHA256 on 512KB took 10ms (51200KB/s)

SHA256 on 1024KB took 20ms (51200KB/s)

SHA256 on 2048KB took 20ms (102400KB/s)

SHA256 on 4096KB took 60ms (68266KB/s)

SHA256 on 8192KB took 120ms (68266KB/s)

SHA256 on 16384KB took 220ms (74472KB/s)

SHA256 on 32768KB took 460ms (71234KB/s)

SHA256 on 65536KB took 900ms (72817KB/s)

SHA256 on 131072KB took 1810ms (72415KB/s)


```
sha256.prg abc.txt v3.txt
```
SHA256(file:abc.txt)=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

SHA256(file:v3.txt)=cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1

## License
This project is licensed under the MIT License; see LICENSE file.
