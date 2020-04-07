### Fritzl

- Frida hooks and helpers mostly aimed at finding crypto functions.

### How to use

- Modify the `index.js` to suit your needs.
- Use `npm install` to install the dependencies.
- Use `frida-compile`: `node_modules/.bin/frida-compile index.js -o compiled.js`.
- Load the compiled file: `frida -f </path/to/someapplication> -F -l compiled.js`.

### Notice

- Use the `Utils.telescope` and `Utils.hexdump` to find pointers in memory.
- You might be able to use the `golang.js` module to hook `Golang` executables (as long as that binary is linked to `libc`).

### Steal

- Grab whatever you want or need from this code. I am a lousy developer, so I am sure you will improve it ;)
