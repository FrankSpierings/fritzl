/*
This file glues it all together.
*/
"use strict";

var Fritzl = require('./lib/fritzl');
var Utils = require('./lib/utils');

function hd(address, options) {
	console.log(Utils.hexdump(ptr(address), options));
}

function ts(address) {
	console.log(Utils.telescope(ptr(address)));
}

Fritzl.disablePinning();
Fritzl.hookDecryption();
Fritzl.hookEncryption();
Fritzl.hookHMAC();
Fritzl.hookKeygen();

global.Fritzl = Fritzl;
global.Utils = Utils;
global.hd = hd;
global.ts = ts;

console.log(Utils.colors.green('[+] Loaded'));