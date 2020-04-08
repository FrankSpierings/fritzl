/*
This file glues it all together.
*/
"use strict";

var Fritzl = require('./lib/fritzl');
var Golang = require('./lib/golang');
var Utils = require('./lib/utils');

function hd(address, options) {
	console.log(Utils.hexdump(ptr(address), options));
}

function ts(address, max) {
	console.log(Utils.telescope(ptr(address), max));
}

Fritzl.hd = hd;
Fritzl.ts = ts;
Fritzl.Golang = Golang;
Fritzl.Utils = Utils;

module.exports = Fritzl;