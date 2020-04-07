/*
Golang provides functions to interact with Golang based binaries.
*/

const Golang = {
	goSymbolTable: null,
	symbolmap: null,

	// This function attempts to find the start of the Go symbol table.
	// https://golang.org/src/debug/gosym/symtab.go
	findGoSymbolTable: function() {
		if (this.goSymbolTable) {
			return this.goSymbolTable;
		}
		const pattern = "FB FF FF FF 00 00";
		var mainmodule = Process.enumerateModules()[0];
		var ranges = Process.enumerateRangesSync('r--');
		for (let i in ranges) {
			var range = ranges[i];
			if (range['base'] && range['size'] &&
				range['file'] && (range['file']['path'] == mainmodule['path'])) {
				var matches = Memory.scanSync(range['base'], range['size'], pattern);
				if (matches && matches.length > 0) {
					for (let i in matches) {
						// Check if this is the table by comparing its first entry defined
						// address with the defined offset + the found address.
						var address = matches[i]['address'];
						var entry = address.add(8).add(Process.pointerSize).readPointer();
						var offset = address.add(8).add(Process.pointerSize * 2).readPointer();
						if (address.add(offset).readPointer().compare(entry) == 0) {
							this.goSymbolTable = address;
							return this.goSymbolTable;
						}
					};
				}
			}
		}
		return null;
	},

	enumerateSymbolsSync: function() {
		if (this.symbolmap) {
			return this.symbolmap;
		}
		var address = this.findGoSymbolTable();
		var output = [];
		if(address) {
			// Read the header
			var headerSize = 8;
			var tableBase = address;
			var recordSize = Process.pointerSize * 2;
			var cursor = address.add(headerSize);
			var tableEnd = address.add(cursor.readUInt() * recordSize);
			cursor = cursor.add(Process.pointerSize);
			// Enumerate the records
			while ((cursor.compare(tableEnd) == -1)) {
				var offset = cursor.add(Process.pointerSize).readPointer();
				var functionAddress = tableBase.add(offset).readPointer();
				var nameOffset = tableBase.add(offset).add(Process.pointerSize).readU32();
				var name = tableBase.add(nameOffset).readUtf8String();
				output.push({
					address: functionAddress,
					name: name,
					// table: tableBase.add(offset),
					// tableBase: tableBase,
				})
				cursor = cursor.add(recordSize);
			}

		}
		this.symbolmap = output;
		return this.symbolmap;
	},

	findSymbolByName: function(name) {
		var map = this.enumerateSymbolsSync();
		for (let i in map) {
			if (map[i]['name'] === name) {
				return map[i]['address'];
			}
		}
		return null;
	},

	findSymbolsByPattern: function(pattern) {
		var map = this.enumerateSymbolsSync();
		var output = []
		for (let i in map) {
			if (map[i]['name'].match(pattern)) {
				output.push(map[i]);
			}
		}
		return output;
	},
};

module.exports = Golang;