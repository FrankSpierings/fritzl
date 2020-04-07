/*
Fritzl provides functionality to abuse OpenSSL functionality.
*/

"use strict";

var Openssl = require('./openssl');
var Golang = require('./golang');
var Utils = require('./utils');

const Fritzl = {
	exportPKEY: function(pkey) {
		const BUFSIZE = 4096;
		var buffer = Memory.alloc(BUFSIZE);
		var output = '';
		//Create a memory bio to hold the output
		var mem = Openssl.BIO_new(Openssl.BIO_s_mem());
		//Print key information using the OpenSSL API
		Openssl.EVP_PKEY_print_private(mem, pkey, 0, ptr(0));
		//Export the public key using OpenSSL API
		Openssl.PEM_write_bio_PUBKEY(mem, pkey);
		//Export the key using OpenSSL API
		Openssl.PEM_write_bio_PrivateKey(mem, pkey, ptr(0), ptr(0), 0, ptr(0), ptr(0))
		//Loop through the bio output and place it in a javascript buffer
		while (Openssl.BIO_gets(mem, buffer, BUFSIZE) > 0) {
			output += buffer.readUtf8String();
		}
		//Clean up bio
		Openssl.BIO_free(mem);
		//Return the output buffer
		return output;
	},
	exportRSA: function(rsa) {
		const BUFSIZE = 4096;
		var buffer = Memory.alloc(BUFSIZE);
		var output = '';
		//Create a memory bio to hold the output
		var mem = Openssl.BIO_new(Openssl.BIO_s_mem());
		if (rsa != ptr(0)) {
			//Export the RSA public key using OpenSSL API
			Openssl.PEM_write_bio_RSAPublicKey(mem, rsa);
			//Export the RSA private key using OpenSSL API
			Openssl.PEM_write_bio_RSAPrivateKey(mem, rsa, ptr(0), ptr(0), 0, ptr(0), ptr(0));
			//Loop through the bio output and place it in a javascript buffer
			while (Openssl.BIO_gets(mem, buffer, BUFSIZE) > 0) {
					output += buffer.readUtf8String();
			}
		}
		//Clean up bio
		Openssl.BIO_free(mem);
		//Return the output buffer
		return output;
	},

	exportPKEYFromEVP_PKEY_CTX: function(ctx) {
		//This is a hack, if the structure changes, this will no longer work!
		// https://github.com/openssl/openssl/blob/master/include/crypto/evp.h#L21
		var pkey = ctx.add(16).readPointer();
		return this.exportPKEY(pkey);
	},

	evpCipherTypeString: function(ctx) {
		var pstr = Openssl.OBJ_nid2ln(Openssl.EVP_CIPHER_CTX_nid(ctx));
		if (pstr == null){
			return 'Cipher: unknown';
		}
		else {
			return 'Cipher: ' + pstr.readUtf8String();
		}
	},

	disablePinning: function() {
		console.log(Utils.colors.green('[+] Setting hooks to disable pinning'));

		(function() {
			var name = 'SSL_set_verify';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log(Utils.colors.green('[!] Hooking: ' + name + ' @ 0x' + address.toString(16)));
				Interceptor.attach(address, {
					onEnter: function(args) {
						this.ssl = args[0];
						this.mode = args[1];
						//Replace the value!
						args[1] = ptr(0);
						console.log(Utils.colors.green(Utils.colors.green('[+] Setting ' + name + ' to mode = ' + args[1])));
					},
				});
			}
		})();

		(function() {
			var name = 'EVP_PKEY_verify';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log(Utils.colors.green('[!] Hooking: ' + name + ' @ 0x' + address.toString(16)));
				Interceptor.attach(address, {
					onLeave: function(result) {
						//Replace the value!
						result.replace(1);
						console.log(Utils.colors.green('[+] Setting ' + name + ' to result = ' + result));
					}
				});
			}
		})();
	},

	hookGoEncryption: function () {
		(function() {
			var name = 'crypto/aes.NewCipher';
			var address = Golang.findSymbolByName(name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							var argp = this.context['rsp'].add(Process.pointerSize);
							for (var i=0; i<6; i++) {
								this.args.push(argp.readPointer());
								argp = argp.add(Process.pointerSize);
							}
						},
						onLeave: function(result) {
							console.log(name);
							var size = this.args[1].toInt32();
							console.log('Key:');
							console.log(Utils.hexdump(this.args[0], {length: size}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'crypto/cipher.newCFB';
			var address = Golang.findSymbolByName(name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = []
							var argp = this.context['rsp'].add(Process.pointerSize);
							for (var i=0; i<10; i++) {
								this.args.push(argp.readPointer());
								argp = argp.add(Process.pointerSize);
							}
						},
						onLeave: function(result) {
							console.log(name);
							// for (var i in this.args) {
							// 	console.log('arg[' + i + '] ' + Utils.telescope(this.args[i]));
							// }
							var size = this.args[3].toInt32();
							console.log('IV:');
							console.log(Utils.hexdump(this.args[2], {length: size}));
						},
					});
				}
				catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'crypto/cipher.(*cfb).XORKeyStream';
			var address = Golang.findSymbolByName(name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = []
							var argp = this.context['rsp'].add(Process.pointerSize);
							for (var i=0; i<6; i++) {
								this.args.push(argp.readPointer());
								argp = argp.add(Process.pointerSize);
							}
						},
						onLeave: function(result) {
							console.log(name);
							var outlen = this.args[2].toInt32();
							outlen = outlen > 64 ? 64 : outlen;
							var inlen = this.args[5].toInt32();
							inlen = inlen > 64 ? 64 : inlen;
							console.log('Input:' + Utils.hexdump(this.args[4], {length: inlen}));
							console.log('Output:' + Utils.hexdump(this.args[1], {length: outlen}));
						},
					});
				}
				catch (error) { console.error(error);}
			}
		})();
	},

	hookKeygen: function() {
		(function() {
			var name = 'EVP_PKEY_keygen';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'ppkey=' + this.args[1] + ') = ' + result);
							var pkey = this.args[1].readPointer();
							console.log(Utils.colors.red(Fritzl.exportPKEY(pkey)));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();
	},

	hookHMAC: function() {
		(function() {
			var name = 'HMAC_Init_ex';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'key=' + this.args[1] + ', ' + 'len=' + this.args[2] + ', ' + 'md=' + this.args[3] + ', ' + 'impl=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.cyan('Key: '));
							console.log(Utils.hexdump(ptr(this.args[1]), {length: this.args[2].toInt32()}));
							console.log(Utils.colors.red(Utils.backtrace(this.context)));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'PKCS5_PBKDF2_HMAC';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]); this.args.push(args[5]); this.args.push(args[6]); this.args.push(args[7]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'pass=' + this.args[0] + ', ' + 'passlen=' + this.args[1] + ', ' + 'salt=' + this.args[2] + ', ' + 'saltlen=' + this.args[3] + ', ' + 'iter=' + this.args[4] + ', ' + 'digest=' + this.args[5] + ', ' + 'keylen=' + this.args[6] + ', ' + 'out=' + this.args[7] + ') = ' + result);
							console.log(Utils.colors.cyan('Pass: ' + this.args[0].readUtf8String()));
							console.log(Utils.colors.cyan('Salt: '));
							console.log(Utils.colors.cyan(Utils.hexdump(ptr(this.args[2]), {length: this.args[3].toInt32()})));
							console.log(Utils.colors.cyan('Key: '));
							console.log(Utils.hexdump(ptr(this.args[7]), {length: this.args[6].toInt32()}));
							console.log(Utils.colors.red(Utils.backtrace(this.context)));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();
	},

	hookEncryption: function() {
		(function() {
			var name = 'RSA_private_encrypt';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'flen=' + this.args[0] + ', ' + 'from=' + this.args[1] + ', ' + 'to=' + this.args[2] + ', ' + 'rsa=' + this.args[3] + ', ' + 'padding=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.red(Fritzl.exportRSA(this.args[3])));
							console.log(Utils.colors.cyan('Buffer from: '));
							console.log(Utils.hexdump(ptr(this.args[1]), {length: result.toInt32()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_EncryptInit_ex';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'cipher=' + this.args[1] + ', ' + 'impl=' + this.args[2] + ', ' + 'key=' + this.args[3] + ', ' + 'iv=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.blue(Fritzl.evp_ciper_type_str(this.args[0])));
							console.log(Utils.colors.blue('Key:'));
							console.log(Utils.hexdump(this.args[3], {length: 32}));
							console.log(Utils.colors.blue('IV:'));
							console.log(Utils.hexdump(this.args[4], {length: 16}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_EncryptUpdate';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'out=' + this.args[1] + ', ' + 'outl=' + this.args[2] + ', ' + 'in=' + this.args[3] + ', ' + 'inl=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.cyan('Buffer in: '));
							console.log(Utils.hexdump(ptr(this.args[3]), {length: this.args[4].toInt32()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_EncryptFinal_ex';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'out=' + this.args[1] + ', ' + 'outl=' + this.args[2] + ') = ' + result);
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_PKEY_encrypt';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'out=' + this.args[1] + ', ' + 'outlen=' + this.args[2] + ', ' + 'in=' + this.args[3] + ', ' + 'inlen=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.red(Fritzl.exportPKEYFromEVP_PKEY_CTX(this.args[0])));
							console.log(Utils.colors.cyan('Buffer in: '));
							console.log(Utils.hexdump(ptr(this.args[3]), {length: this.args[4].toInt32()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();
	},

	hookDecryption: function() {
		(function() {
			var name = 'RSA_public_decrypt';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'flen=' + this.args[0] + ', ' + 'from=' + this.args[1] + ', ' + 'to=' + this.args[2] + ', ' + 'rsa=' + this.args[3] + ', ' + 'padding=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.red(Fritzl.exportRSA(this.args[3])));
							console.log(Utils.colors.cyan('Buffer to: '));
							console.log(Utils.hexdump(ptr(this.args[2]), {length: result.toInt32()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_DecryptInit_ex';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'cipher=' + this.args[1] + ', ' + 'impl=' + this.args[2] + ', ' + 'key=' + this.args[3] + ', ' + 'iv=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.blue(Fritzl.evpCipherTypeString(this.args[0])));
							console.log(Utils.colors.blue('Key:'));
							console.log(Utils.hexdump(this.args[3], {length: 32}));
							console.log(Utils.colors.blue('IV:'));
							console.log(Utils.hexdump(this.args[4], {length: 16}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_DecryptUpdate';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]); this.args.push(args[3]); this.args.push(args[4]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'out=' + this.args[1] + ', ' + 'outl=' + this.args[2] + ', ' + 'in=' + this.args[3] + ', ' + 'inl=' + this.args[4] + ') = ' + result);
							console.log(Utils.colors.cyan('Buffer out: '));
							console.log(Utils.hexdump(ptr(this.args[1]), {length: this.args[2].readUInt()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

		(function() {
			var name = 'EVP_DecryptFinal_ex';
			var address = Module.findExportByName(null, name);
			if (address != null) {
				console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
				try {
					Interceptor.attach(address, {
						onEnter: function(args) {
							this.args = [];
							this.args.push(args[0]); this.args.push(args[1]); this.args.push(args[2]);
						},
						onLeave: function(result) {
							console.log(name + '(' + 'ctx=' + this.args[0] + ', ' + 'outm=' + this.args[1] + ', ' + 'outl=' + this.args[2] + ') = ' + result);
							console.log(Utils.colors.cyan('Buffer out: '));
							console.log(Utils.hexdump(ptr(this.args[1]), {length: this.args[2].readUInt()}));
						},
					});
				} catch (error) { console.error(error);}
			}
		})();

	},
}

module.exports = Fritzl;