/*
Openssl provides the Frida implementation of OpenSSL API definitions.
*/

"use strict";

const Openssl = {
	BIO_new: function(BIO_METHOD) {
		var name = "BIO_new";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'pointer', ['pointer']);
			var retval = f(BIO_METHOD);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	BIO_free: function(a) {
		var name = "BIO_free";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer']);
			var retval = f(a);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	BIO_s_mem: function() {
		var name = "BIO_s_mem";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'pointer', []);
			var retval = f();
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	BIO_gets: function(b, buf, size) {
		var name = "BIO_gets";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'int']);
			var retval = f(b, buf, size);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	BIO_read: function(b, buf, len) {
		var name = "BIO_read";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'int']);
			var retval = f(b, buf, len);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	BIO_reset: function(b) {
		var name = "BIO_reset";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'int']);
			var retval = f(b);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	EVP_PKEY_id: function(pkey) {
		var name = "EVP_PKEY_id";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer']);
			var retval = f(pkey);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	EVP_PKEY_get1_RSA: function(pkey) {
		var name = "EVP_PKEY_get1_RSA";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'pointer', ['pointer']);
			var retval = f(pkey);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	PEM_write_bio_PrivateKey: function(bp, x, enc, kstr, klen, cb, u) {
		var name = "PEM_write_bio_PrivateKey";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'pointer', 'pointer']);
			var retval = f(bp, x, enc, kstr, klen, cb, u);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	PEM_write_bio_PUBKEY: function(bp, x) {
		var name = "PEM_write_bio_PUBKEY";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer']);
			var retval = f(bp, x);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	PEM_write_bio_RSAPrivateKey: function(bp, x, enc, kstr, klen, cb, u) {
		var name = "PEM_write_bio_RSAPrivateKey";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'pointer', 'pointer']);
			var retval = f(bp, x, enc, kstr, klen, cb, u);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	PEM_write_bio_RSAPublicKey: function(bp, x) {
		var name = "PEM_write_bio_RSAPublicKey";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer']);
			var retval = f(bp, x);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	EVP_PKEY_print_private: function(out, pkey, indent, pctx) {
		var name = "EVP_PKEY_print_private";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'int', 'pointer']);
			var retval = f(out, pkey, indent, pctx);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	RSA_print: function(bp, x, offset) {
		var name = "RSA_print";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer', 'pointer', 'int']);
			var retval = f(bp, x, offset);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	EVP_CIPHER_CTX_nid: function(ctx) {
		var name = "EVP_CIPHER_CTX_nid";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'int', ['pointer']);
			var retval = f(ctx);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
	OBJ_nid2ln: function(n) {
		var name = "OBJ_nid2ln";
		var address = Module.findExportByName(null, name);
		if (address) {
			var f = new NativeFunction(address, 'pointer', ['int']);
			var retval = f(n);
			return retval;
		} else { throw("Function '" + name + "' not found"); }
	},
}

module.exports = Openssl;