/*
Utils provides 'random' functionality like a memory telescope and coloring.
*/

"use strict";

const Utils = {
	colors: {
		red: function(string) {
			return '\x1b[31m' + string + '\x1b[0m';
		},

		green: function(string) {
			return '\x1b[32m' + string + '\x1b[0m';
		},

		yellow: function(string) {
			return '\x1b[33m' + string + '\x1b[0m';
		},

		blue: function(string) {
			return '\x1b[34m' + string + '\x1b[0m';
		},

		cyan: function(string) {
			return '\x1b[36m' + string + '\x1b[0m';
		},
	},

	islittleEndian: function() {
		var a = new Uint32Array([0x12345678]);
	    var b = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
	    return (b[0] == 0x78);
	},

	// Convert a ptr itself into ascii
	ptrToAscii: function(address) {
		var address = ptr(address);
		var output = [];
		for (var i=0; i<Process.pointerSize; i++) {
			var b = address.shr(Process.pointerSize * i).and(0xff);
			if ((b > 0x1f) && (b < 0x7f)) {
				output.push(this.colors.green(String.fromCharCode(b)));
			} else {
				output.push(this.colors.red('.'))
			}
		}
		return output.join('');
	},

	backtrace: function(context) {
		return 'Backtrace:\n' + Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n') + '\n';
	},

	telescope: function(address) {
		var items = this.addressResolve(address);
		var results = [];
		for (var i=0; i < items.length - 1; i++) {
			var item = items[i];
			var range = Process.findRangeByAddress(item['address']);
			if(range) {
				if (range.protection.match(/^..x$/)) {
					results.push(this.colors.red(item['address']));
				}
				else if (range.protection.match(/^.w.$/)) {
					results.push(this.colors.blue(item['address']));
				}
				else if (range.protection.match(/^r..$/)) {
					results.push(this.colors.yellow(item['address']));
				}
				else {
					results.push(this.colors.cyan(item['address']));
				}
			}
		}
		var output = results.join(' -> ');
		output += (" = " + items[items.length - 1]['address']);
		output += (": " + this.ptrToAscii(items[items.length - 1]['address']));
		return output;
	},

	// Recursive function to walk addresses.
	addressResolve: function(address, max, stack) {
		address = ptr(address);
		if (!stack) {
			stack = [];
		}
		if (!max) {
			max = 10;
		}
		if (stack.length >= max) {
			return stack;
		}
		var record = {
			address: address,
		};
		try {
			if (Process.pointerSize == 8) {
				record['value'] = address.readU64();
			} else {
				record['value'] = address.readU32();
			}
			try {
				record['string'] = address.readUtf8String();
			} catch (error) {}
		}
		catch (error) {}
		stack.push(record);
		if (record['value']) {
			stack = this.addressResolve(ptr(record['value']), max, stack);
		}
		return stack;
	},

	hexdump: function(address, options) {
		address = ptr(address);

		// Setting default options where required.
		options = options || {};
		if (!options.hasOwnProperty('length')) {
			options.length = 256;
		}
		if (!options.hasOwnProperty('addressColors')) {
			options.addressColors = true;
		}
		if (!options.hasOwnProperty('header')) {
			options.header = true;
		}
		if (!options.hasOwnProperty('le')) {
			options.le = Utils.islittleEndian();
		}
		if ((options.length > 256) && (options.addressColors)) {
			console.warn("Warning: applying colors on such a large set will slow down the application!");
		}

		const pSize = Process.pointerSize;
		const buffer = address.readByteArray(options.length);
		const dv = new DataView(buffer);
		var byteStrArray = [];
		var asciiArray = [];
		// var ttotal = 0;
		if (options.addressColors) {
			for (var di = 0; di < dv.byteLength; di++) {
				if (di + (pSize - 1) < dv.byteLength) {
					var value;
					switch(pSize) {
						// Dword
						case 4:
							value = dv.getUint32(di, options.le);
							break;
						// Qword
						case 8:
							const left = dv.getUint32(di, options.le);
							const right = dv.getUint32((di+4), options.le);
							value = options.le ? left + 2**32*right : 2**32*left + right;
							break;
						// Are you insane?
						default:
							throw("Can't handle pointer size '" + pSize + "'");
							return null;
					}
					// var t0 = performance.now();
					// This is the performance hit!
					const range = Process.findRangeByAddress(ptr(value));
					// ttotal += performance.now() - t0;
					if (range) {
						const protection = range.protection;
						for (var bi = di; bi < (di + pSize); bi++) {
							// Add the color to each byte in the value
							const byte = dv.getUint8(bi)
							const byteStr = byte > 15 ? byte.toString(16) : "0" + byte.toString(16);

							if (protection.match(/^..x$/)) {
								byteStrArray.push(this.colors.red(byteStr));
							} else if (protection.match(/^.w.$/)) {
								byteStrArray.push(this.colors.blue(byteStr));
							} else if (protection.match(/^r..$/)) {
								byteStrArray.push(this.colors.yellow(byteStr));
							} else {
								byteStrArray.push(this.colors.cyan(byteStr));
							}

							if ((byte > 0x1f) && (byte < 0x7f)) {
								asciiArray.push(this.colors.green(String.fromCharCode(byte)));
							} else {
								asciiArray.push(this.colors.red('.'));
							}
						}
						// The value was found to be an address,
						// we can skip this address by setting di to bi-1.
						// The loop should be continued to evaluate the next
						// possible address.
						di = bi - 1;
						continue;
					}
				}
				// Either we are nearing the end of the buffer,
				// or the value is not within any defined memory range.
				// Add the single byte to the byteStrArray buffer.
				const byte = dv.getUint8(di);
				const byteStr = byte > 15 ? byte.toString(16) : "0" + byte.toString(16);
				if ((byte > 0x1f) && (byte < 0x7f)) {
					// Set the color for ascii bytes
					byteStrArray.push(this.colors.green(byteStr));
					asciiArray.push(this.colors.green(String.fromCharCode(byte)));
				} else {
					byteStrArray.push(byteStr);
					asciiArray.push(this.colors.red('.'));
				}
			}
			// console.log("Checking addresses took " + ttotal + " milliseconds.");
		} else {
			// No address colors, but we still color ascii bytes.
			for (var di = 0; di < dv.byteLength; di++) {
				const byte = dv.getUint8(di);
				const byteStr = byte > 15 ? byte.toString(16) : "0" + byte.toString(16);
				if ((byte > 0x1f) && (byte < 0x7f)) {
					byteStrArray.push(this.colors.green(byteStr));
					asciiArray.push(this.colors.green(String.fromCharCode(byte)));
				} else {
					byteStrArray.push(byteStr);
					asciiArray.push(this.colors.red('.'));
				}
			}
		}

		function prepad(s, mod, char) {
			var m = s.length % mod;
			if (m != 0) {
				var padLen = mod - m;
				return (char[0].repeat(padLen)) + s;
			}
			return s;
		}

		// There are now two arrays with the information.
		// Join them to create a hexdump view
		const hexLegend = ' 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F';
		const asciiLegend = '0123456789ABCDEF';
		var output = [''];
		var columnSpace = 2;
		var line;
		if (options.header) {
			line  = '';
			line += ' '.repeat(2 + (pSize*2));	// Addresses
			line += ' '.repeat(columnSpace);
			line += hexLegend;					// Bytes
			line += ' '.repeat(columnSpace);
			line += asciiLegend;				// Ascii value
			output.push(line);
		}
		var padlen = 0;
		for (var i = 0; i < byteStrArray.length; i+=16) {
			if (i + 16 > byteStrArray.length) {
				// Needs padding (based on the number of items in the array)
				// Note we can't use .length once it is a string, since it might
				// containt color characters.
				padlen = 16 - (byteStrArray.length % 16);
			}
			line = "0x" + prepad(address.add(i).toString(16), (pSize*2), '0');
			line += ' '.repeat(columnSpace);
			line += byteStrArray.slice(i, i+16).join(' ');
			line += '   '.repeat(padlen);
			line += ' '.repeat(columnSpace);
			line += asciiArray.slice(i, i+16).join('');
			line += ' '.repeat(padlen);
			output.push(line)
		}
		return output.join('\n');
	}
};

module.exports = Utils;