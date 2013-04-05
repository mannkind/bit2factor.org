
Bitcoin.ECDSA = (function () {
	var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
	var rng = new SecureRandom();

	function implShamirsTrick(P, k, Q, l) {
		var m = Math.max(k.bitLength(), l.bitLength());
		var Z = P.add2D(Q);
		var R = P.curve.getInfinity();

		for (var i = m - 1; i >= 0; --i) {
			R = R.twice2D();

			R.z = BigInteger.ONE;

			if (k.testBit(i)) {
				if (l.testBit(i)) {
					R = R.add2D(Z);
				} else {
					R = R.add2D(P);
				}
			} else {
				if (l.testBit(i)) {
					R = R.add2D(Q);
				}
			}
		}

		return R;
	};

	var ECDSA = {
		getBigRandom: function (limit) {
			return new BigInteger(limit.bitLength(), rng)
		.mod(limit.subtract(BigInteger.ONE))
		.add(BigInteger.ONE);
		},
		sign: function (hash, priv) {
			var d = priv;
			var n = ecparams.getN();
			var e = BigInteger.fromByteArrayUnsigned(hash);

			do {
				var k = ECDSA.getBigRandom(n);
				var G = ecparams.getG();
				var Q = G.multiply(k);
				var r = Q.getX().toBigInteger().mod(n);
			} while (r.compareTo(BigInteger.ZERO) <= 0);

			var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

			return ECDSA.serializeSig(r, s);
		},

		serializeSig: function (r, s) {
			var rBa = r.toByteArrayUnsigned();
			var sBa = s.toByteArrayUnsigned();

			var sequence = [];
			sequence.push(0x02); // INTEGER
			sequence.push(rBa.length);
			sequence = sequence.concat(rBa);

			sequence.push(0x02); // INTEGER
			sequence.push(sBa.length);
			sequence = sequence.concat(sBa);

			sequence.unshift(sequence.length);
			sequence.unshift(0x30) // SEQUENCE

			return sequence;
		},

		verify: function (hash, sig, pubkey) {
			var obj = ECDSA.parseSig(sig);
			var r = obj.r;
			var s = obj.s;

			var n = ecparams.getN();
			var e = BigInteger.fromByteArrayUnsigned(hash);

			if (r.compareTo(BigInteger.ONE) < 0 ||
		r.compareTo(n) >= 0)
				return false;

			if (s.compareTo(BigInteger.ONE) < 0 ||
		s.compareTo(n) >= 0)
				return false;

			var c = s.modInverse(n);

			var u1 = e.multiply(c).mod(n);
			var u2 = r.multiply(c).mod(n);

			var G = ecparams.getG();
			var Q = ECPointFp.decodeFrom(ecparams.getCurve(), pubkey);

			var point = implShamirsTrick(G, u1, Q, u2);

			var v = point.x.toBigInteger().mod(n);

			return v.equals(r);
		},

		parseSig: function (sig) {
			var cursor;
			if (sig[0] != 0x30)
				throw new Error("Signature not a valid DERSequence");

			cursor = 2;
			if (sig[cursor] != 0x02)
				throw new Error("First element in signature must be a DERInteger"); ;
			var rBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);

			cursor += 2 + sig[cursor + 1];
			if (sig[cursor] != 0x02)
				throw new Error("Second element in signature must be a DERInteger");
			var sBa = sig.slice(cursor + 2, cursor + 2 + sig[cursor + 1]);

			cursor += 2 + sig[cursor + 1];

			//if (cursor != sig.length)
			//	throw new Error("Extra bytes in signature");

			var r = BigInteger.fromByteArrayUnsigned(rBa);
			var s = BigInteger.fromByteArrayUnsigned(sBa);

			return { r: r, s: s };
		}
	};

	return ECDSA;
})();









Bitcoin.ECKey = (function () {
	var ECDSA = Bitcoin.ECDSA;
	var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
	var rng = new SecureRandom();

	var ECKey = function (input) {
		if (!input) {
			// Generate new key
			var n = ecparams.getN();
			this.priv = ECDSA.getBigRandom(n);
		} else if (input instanceof BigInteger) {
			// Input is a private key value
			this.priv = input;
		} else if (Bitcoin.Util.isArray(input)) {
			// Prepend zero byte to prevent interpretation as negative integer
			this.priv = BigInteger.fromByteArrayUnsigned(input);
		} else if ("string" == typeof input) {
			// Prepend zero byte to prevent interpretation as negative integer
			this.priv = BigInteger.fromByteArrayUnsigned(Crypto.util.base64ToBytes(input));
		}
	};

	ECKey.privateKeyPrefix = 0x80; // mainnet

	ECKey.prototype.getPub = function () {
		if (this.pub) return this.pub;
		return this.pub = ecparams.getG().multiply(this.priv).getEncoded(0);
	};

	ECKey.prototype.getPubKeyHex = function () {
		if (this.pubKeyHex) return this.pubKeyHex;
		return this.pubKeyHex = Crypto.util.bytesToHex(this.getPub()).toString().toUpperCase();
	};

	ECKey.prototype.getPubKeyHexCompressed = function () {
		if (this.pubKeyHexCompressed) return this.pubKeyHexCompressed;
		return this.pubKeyHexCompressed = Crypto.util.bytesToHex(this.getPubCompressed()).toString().toUpperCase();
	};

	ECKey.prototype.getPubCompressed = function () {
		if (this.pubCompressed) return this.pubCompressed;
		return this.pubCompressed = ecparams.getG().multiply(this.priv).getEncoded(1);
	};

	ECKey.prototype.getPubKeyHash = function () {
		if (this.pubKeyHash) return this.pubKeyHash;
		return this.pubKeyHash = Bitcoin.Util.sha256ripe160(this.getPub());
	};

	ECKey.prototype.getPubKeyHashCompressed = function () {
		if (this.pubKeyHashCompressed) return this.pubKeyHashCompressed;
		return this.pubKeyHashCompressed = Bitcoin.Util.sha256ripe160(this.getPubCompressed());
	};

	ECKey.prototype.getBitcoinAddress = function () {
		var hash = this.getPubKeyHash();
		var addr = new Bitcoin.Address(hash);
		return addr.toString();
	};

	ECKey.prototype.getBitcoinAddressCompressed = function () {
		var hash = this.getPubKeyHashCompressed();
		var addr = new Bitcoin.Address(hash);
		return addr.toString();
	};

	// Sipa Private Key Wallet Import Format 
	ECKey.prototype.getBitcoinWalletImportFormat = function () {
		var bytes = this.getBitcoinPrivateKeyByteArray();
		bytes.unshift(ECKey.privateKeyPrefix); // prepend 0x80 byte
		var checksum = Bitcoin.Util.dsha256(bytes);
		bytes = bytes.concat(checksum.slice(0, 4));
		var privWif = Bitcoin.Base58.encode(bytes);
		return privWif;
	};

	// Sipa Private Key Wallet Import Format Compressed
	ECKey.prototype.getBitcoinWalletImportFormatCompressed = function () {
		var bytes = this.getBitcoinPrivateKeyByteArray();
		bytes.unshift(ECKey.privateKeyPrefix); // prepend 0x80 byte	
		bytes.push(0x01);    // append 0x01 byte for compressed format
		var checksum = Bitcoin.Util.dsha256(bytes);
		bytes = bytes.concat(checksum.slice(0, 4));
		var privWifComp = Bitcoin.Base58.encode(bytes);
		return privWifComp;
	};

	// Private Key Hex Format 
	ECKey.prototype.getBitcoinHexFormat = function () {
		return Crypto.util.bytesToHex(this.getBitcoinPrivateKeyByteArray()).toString().toUpperCase();
	};

	// Private Key Base64 Format 
	ECKey.prototype.getBitcoinBase64Format = function () {
		return Crypto.util.bytesToBase64(this.getBitcoinPrivateKeyByteArray());
	};

	ECKey.prototype.getBitcoinPrivateKeyByteArray = function () {
		// Get a copy of private key as a byte array
		var bytes = this.priv.toByteArrayUnsigned();
		// zero pad if private key is less than 32 bytes 
		while (bytes.length < 32) bytes.unshift(0x00);
		return bytes;
	};

	ECKey.prototype.setPub = function (pub) {
		this.pub = pub;
	};

	ECKey.prototype.setPubCompressed = function (pubCompressed) {
		this.pubCompressed = pubCompressed;
	};

	ECKey.prototype.toString = function (format) {
		format = format || "";

		if (format.toString().toLowerCase() == "base64" || format.toString().toLowerCase() == "b64") {
			return this.getBitcoinBase64Format();
		}
		// Wallet Import Format
		else if (format.toString().toLowerCase() == "wif") {
			return this.getBitcoinWalletImportFormat();
		}
		else if (format.toString().toLowerCase() == "wifcomp") {
			return this.getBitcoinWalletImportFormatCompressed();
		}
		else {
			return this.getBitcoinHexFormat();
		}
	};

	ECKey.prototype.sign = function (hash) {
		return ECDSA.sign(hash, this.priv);
	};

	ECKey.prototype.verify = function (hash, sig) {
		return ECDSA.verify(hash, sig, this.getPub());
	};

	return ECKey;
})();






// Bitcoin utility functions
Bitcoin.Util = {
	isArray: Array.isArray || function (o) {
		return Object.prototype.toString.call(o) === '[object Array]';
	},
	makeFilledArray: function (len, val) {
		var array = [];
		var i = 0;
		while (i < len) {
			array[i++] = val;
		}
		return array;
	},
	numToVarInt: function (i) {
		if (i < 0xfd) {
			// unsigned char
			return [i];
		} else if (i <= 1 << 16) {
			// unsigned short (LE)
			return [0xfd, i >>> 8, i & 255];
		} else if (i <= 1 << 32) {
			// unsigned int (LE)
			return [0xfe].concat(Crypto.util.wordsToBytes([i]));
		} else {
			// unsigned long long (LE)
			return [0xff].concat(Crypto.util.wordsToBytes([i >>> 32, i]));
		}
	},
	valueToBigInt: function (valueBuffer) {
		if (valueBuffer instanceof BigInteger) return valueBuffer;

		// Prepend zero byte to prevent interpretation as negative integer
		return BigInteger.fromByteArrayUnsigned(valueBuffer);
	},
	formatValue: function (valueBuffer) {
		var value = this.valueToBigInt(valueBuffer).toString();
		var integerPart = value.length > 8 ? value.substr(0, value.length - 8) : '0';
		var decimalPart = value.length > 8 ? value.substr(value.length - 8) : value;
		while (decimalPart.length < 8) decimalPart = "0" + decimalPart;
		decimalPart = decimalPart.replace(/0*$/, '');
		while (decimalPart.length < 2) decimalPart += "0";
		return integerPart + "." + decimalPart;
	},
	parseValue: function (valueString) {
		var valueComp = valueString.split('.');
		var integralPart = valueComp[0];
		var fractionalPart = valueComp[1] || "0";
		while (fractionalPart.length < 8) fractionalPart += "0";
		fractionalPart = fractionalPart.replace(/^0+/g, '');
		var value = BigInteger.valueOf(parseInt(integralPart));
		value = value.multiply(BigInteger.valueOf(100000000));
		value = value.add(BigInteger.valueOf(parseInt(fractionalPart)));
		return value;
	},
	sha256ripe160: function (data) {
		return Crypto.RIPEMD160(Crypto.SHA256(data, { asBytes: true }), { asBytes: true });
	},
	dsha256: function (data) {
		return Crypto.SHA256(Crypto.SHA256(data, { asBytes: true }), { asBytes: true });
	}
};