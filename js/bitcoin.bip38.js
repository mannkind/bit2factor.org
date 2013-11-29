
Bitcoin.BIP38 = {
	// 58 base58 characters starting with 6P
	isBIP38Format: function (key) {
		key = key.toString();
		return (/^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(key));
	},
	EncryptedKeyToByteArrayAsync: function (base58Encrypted, passphrase, callback) {
		var hex;
		try {
			hex = Bitcoin.Base58.decode(base58Encrypted);
		} catch (e) {
			callback(new Error("Invalid Private Key"));
			return;
		}

		if (hex.length != 43) {
			callback(new Error("Invalid Private Key"));
			return;
		} else if (hex[0] != 0x01) {
			callback(new Error("Invalid Private Key"));
			return;
		}

		var expChecksum = hex.slice(-4);
		hex = hex.slice(0, -4);

		var checksum = Bitcoin.Util.dsha256(hex);
		if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
			callback(new Error("Invalid Private Key"));
			return;
		}

		var isCompPoint = false;
		var isECMult = false;
		var hasLotSeq = false;
		if (hex[1] == 0x42) {
			if (hex[2] == 0xe0) {
				isCompPoint = true;
			} else if (hex[2] != 0xc0) {
				callback(new Error("Invalid Private Key"));
				return;
			}
		} else if (hex[1] == 0x43) {
			isECMult = true;
			isCompPoint = (hex[2] & 0x20) != 0;
			hasLotSeq = (hex[2] & 0x04) != 0;
			if ((hex[2] & 0x24) != hex[2]) {
				callback(new Error("Invalid Private Key"));
				return;
			}
		} else {
			callback(new Error("Invalid Private Key"));
			return;
		}

		var decrypted;
		var AES_opts = {mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true};

		var verifyHashAndReturn = function() {
			var tmpkey = new Bitcoin.ECKey(decrypted);
			var base58AddrText = isCompPoint ? tmpkey.getBitcoinAddressCompressed() : tmpkey.getBitcoinAddress();
			checksum = Bitcoin.Util.dsha256(base58AddrText);

			if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
				callback(new Error("Incorrect Passphrase"));
				return;
			}

			callback(tmpkey.getBitcoinPrivateKeyByteArray(), isCompPoint);
		};

		if (!isECMult) {
			var addresshash = hex.slice(3, 7);
			Crypto.Scrypt(passphrase, addresshash, 16384, 8, 8, 64, function(derivedBytes) {
				var k = derivedBytes.slice(32, 32+32);
				decrypted = Crypto.AES.decrypt(hex.slice(7, 7+32), k, AES_opts);
				for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
				verifyHashAndReturn();
			});
		} else {
			var ownerentropy = hex.slice(7, 7+8);
			var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
			Crypto.Scrypt(passphrase, ownersalt, 16384, 8, 8, 32, function(prefactorA) {
				var passfactor;
				if (!hasLotSeq) {
					passfactor = prefactorA;
				} else {
					var prefactorB = prefactorA.concat(ownerentropy);
					passfactor = Bitcoin.Util.dsha256(prefactorB);
				}
				var kp = new Bitcoin.ECKey(passfactor);
				var passpoint = kp.getPubCompressed();

				var encryptedpart2 = hex.slice(23, 23+16);

				var addresshashplusownerentropy = hex.slice(3, 3+12);
				Crypto.Scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64, function(derived) {
					var k = derived.slice(32);

					var unencryptedpart2 = Crypto.AES.decrypt(encryptedpart2, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart2[i] ^= derived[i+16]; }

					var encryptedpart1 = hex.slice(15, 15+8).concat(unencryptedpart2.slice(0, 0+8));
					var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }

					var seedb = unencryptedpart1.slice(0, 0+16).concat(unencryptedpart2.slice(8, 8+8));


					var factorb = Bitcoin.Util.dsha256(seedb);

					var ps = EllipticCurve.getSECCurveByName("secp256k1");
					var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ps.getN());

					decrypted = privateKey.toByteArrayUnsigned();
					verifyHashAndReturn();
				});
			});
		}

	},
	GenerateIntermediatePointAsync: function(passphrase, lotNum, sequenceNum, callback) {
		var noNumbers = lotNum === null || sequenceNum === null;
		var rng = new SecureRandom();
		var ownerEntropy, ownerSalt;

		if(noNumbers) {
			ownerSalt = ownerEntropy = new Array(8);
			rng.nextBytes(ownerEntropy);
		}
		else {
			// 1) generate 4 random bytes
			var ownerSalt = Array(4);

			rng.nextBytes(ownerSalt);

			// 2)  Encode the lot and sequence numbers as a 4 byte quantity (big-endian):
			// lotnumber * 4096 + sequencenumber. Call these four bytes lotsequence.
			var lotSequence = BigInteger(4096*lotNum + sequenceNum).toByteArrayUnsigned();

			// 3) Concatenate ownersalt + lotsequence and call this ownerentropy.
			var ownerEntropy = ownerSalt.concat(lotSequence);
		}

		// 4) Derive a key from the passphrase using scrypt
		Crypto.Scrypt(passphrase, ownerSalt, 16384, 8, 8, 32, function(prefactor) {
			// Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
			var passfactorBytes = noNumbers? prefactor : Bitcoin.Util.dsha256(prefactor.concat(ownerEntropy));
			var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);

			// 5) Compute the elliptic curve point G * passfactor, and convert the result to compressed notation (33 bytes)
			var ellipticCurve = EllipticCurve.getSECCurveByName("secp256k1");
			var passpoint = ellipticCurve.getG().multiply(passfactor).getEncoded(1);

			// 6) Convey ownersalt and passpoint to the party generating the keys, along with a checksum to ensure integrity.
			// magic bytes "2C E9 B3 E1 FF 39 E2 51" followed by ownerentropy, and then passpoint
			var magicBytes = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];
			if(noNumbers) magicBytes[7] = 0x53;

			var intermediate = magicBytes.concat(ownerEntropy).concat(passpoint);

			// base58check encode
			intermediate = intermediate.concat(Bitcoin.Util.dsha256(intermediate).slice(0,4));

			callback(Bitcoin.Base58.encode(intermediate));
		});
	},
	PrivateKeyToEncryptedKeyAsync: function (base58Key, passphrase, compressed, callback) {
		var privKeyBytes = null;
	    if (/^5[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$/.test(base58Key)) {
	      privKeyBytes = Bitcoin.Base58.decode(base58Key);
	      privKeyBytes.shift();
	      privKeyBytes = privKeyBytes.slice(0, privKeyBytes.length - 4);
	    } else if (/^[LK][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}$/.test(base58Key)) {
	      privKeyBytes = Bitcoin.Base58.decode(base58Key);
	      privKeyBytes.shift();
	      privKeyBytes.pop();
	      privKeyBytes = privKeyBytes.slice(0, privKeyBytes.length - 4);
	    }

		var privKey = new Bitcoin.ECKey(privKeyBytes);
		var address = compressed? privKey.getBitcoinAddressCompressed() : privKey.getBitcoinAddress();

		// compute sha256(sha256(privKey)) and take first 4 bytes
		var salt = Bitcoin.Util.dsha256(address).slice(0, 4);

		// derive key using scrypt
		var AES_opts = {mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true};

		Crypto.Scrypt(passphrase, salt, 16384, 8, 8, 64, function(derivedBytes) {
			for(var i = 0; i < 32; ++i) {
				privKeyBytes[i] ^= derivedBytes[i];
			}

			// 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
			var flagByte = compressed? 0xe0 : 0xc0;
			var encryptedKey = [ 0x01, 0x42, flagByte ].concat(salt);

			var encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), AES_opts));

			encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0,4));

			callback(Bitcoin.Base58.encode(encryptedKey), address);
		});
	},
	GenerateECAddressAsync: function(intermediate, compressed, callback) {
		// decode IPS
		var x = Bitcoin.Base58.decode(intermediate);

		var noNumbers = (x[7] === 0x53);
		var ownerEntropy = x.slice(8, 8+8);
		var passpoint = x.slice(16, 16+33);

		// 1) Set flagbyte.
		// set bit 0x20 for compressed key
		// set bit 0x04 if ownerentropy contains a value for lotsequence
		var flagByte = (compressed? 0x20 : 0x00) | (noNumbers? 0x00 : 0x04);

		// 2) Generate 24 random bytes, call this seedb.
		var seedB = new Array(24);
		var rng = new SecureRandom();
		rng.nextBytes(seedB);

		// Take SHA256(SHA256(seedb)) to yield 32 bytes, call this factorb.
		var factorB = Bitcoin.Util.dsha256(seedB);

		// 3) ECMultiply passpoint by factorb. Use the resulting EC point as a public key and hash it into a Bitcoin
		// address using either compressed or uncompressed public key methodology (specify which methodology is used
		// inside flagbyte). This is the generated Bitcoin address, call it generatedaddress.
		var curve = EllipticCurve.getSECCurveByName("secp256k1");
		var ec = curve.getCurve();
		var generatedPoint = ec.decodePointHex(Crypto.util.bytesToHex(passpoint).toString().toUpperCase());
		var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(compressed);
		var generatedAddress = (new Bitcoin.Address(Bitcoin.Util.sha256ripe160(generatedBytes))).toString();

		// 4) Take the first four bytes of SHA256(SHA256(generatedaddress)) and call it addresshash.
		var addressHash = Bitcoin.Util.dsha256(generatedAddress).slice(0,4);

		// 5) Now we will encrypt seedb. Derive a second key from passpoint using scrypt
		Crypto.Scrypt(passpoint, addressHash.concat(ownerEntropy), 1024, 1, 1, 64, function(derivedBytes) {
			
			// 6) Do AES256Encrypt(seedb[0...15]] xor derivedhalf1[0...15], derivedhalf2), call the 16-byte result encryptedpart1
			for(var i = 0; i < 16; ++i) {
				seedB[i] ^= derivedBytes[i];
			}
			var AES_opts = {mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true};
			var encryptedPart1 = Crypto.AES.encrypt(seedB.slice(0,16), derivedBytes.slice(32), AES_opts);

			// 7) Do AES256Encrypt((encryptedpart1[8...15] + seedb[16...23]) xor derivedhalf1[16...31], derivedhalf2), call the 16-byte result encryptedseedb.
			var message2 = encryptedPart1.slice(8, 8+8).concat(seedB.slice(16, 16+8));
			for(var i = 0; i < 16; ++i) {
				message2[i] ^= derivedBytes[i+16];
			}
			var encryptedSeedB = Crypto.AES.encrypt(message2, derivedBytes.slice(32), AES_opts);

			// 0x01 0x43 + flagbyte + addresshash + ownerentropy + encryptedpart1[0...7] + encryptedpart2
			var encryptedKey = [ 0x01, 0x43, flagByte ].concat(addressHash).concat(ownerEntropy).concat(encryptedPart1.slice(0,8)).concat(encryptedSeedB);

			// base58check encode
			encryptedKey = encryptedKey.concat(Bitcoin.Util.dsha256(encryptedKey).slice(0,4));

			// Confirmation Code

			// 1) ECMultiply factorb by G, call the result pointb. The result is 33 bytes.
			var pointb = curve.getG().multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(1);

			// 2) he first byte is 0x02 or 0x03. XOR it by (derivedhalf2[31] & 0x01), call the resulting byte pointbprefix.
			var pointbprefix = pointb[0] ^ (derivedBytes[63] & 0x01);

			// 3) Do AES256Encrypt(pointb[1...16] xor derivedhalf1[0...15], derivedhalf2) and call the result pointbx1.
			for(var i = 0; i < 16; ++i) {
				pointb[i + 1] ^= derivedBytes[i];
			}
			var pointbx1 = Crypto.AES.encrypt(pointb.slice(1,17), derivedBytes.slice(32), AES_opts);
			
			// 4) Do AES256Encrypt(pointb[17...32] xor derivedhalf1[16...31], derivedhalf2) and call the result pointbx2.
			for(var i = 16; i < 32; ++i) {
				pointb[i + 1] ^= derivedBytes[i];
			}
			var pointbx2 = Crypto.AES.encrypt(pointb.slice(17,33), derivedBytes.slice(32), AES_opts);

			var encryptedpointb = [ pointbprefix ].concat(pointbx1).concat(pointbx2);

			var confirmCode = [ 0x64, 0x3B, 0xF6, 0xA8, 0x9A, flagByte ].concat(addressHash).concat(ownerEntropy).concat(encryptedpointb);

			confirmCode = confirmCode.concat(Bitcoin.Util.dsha256(confirmCode).slice(0,4));

			callback(Bitcoin.Base58.encode(confirmCode), generatedAddress, Bitcoin.Base58.encode(encryptedKey));
		});
	},
	ValidateConfirmationAsync: function(confirmation, passphrase, callback) {
		var bytes = Bitcoin.Base58.decode(confirmation);
		
		// Get the flag byte.
    	// This gives access to IsCompressedPoint and LotSequencePresent
		var flagByte = bytes[5];
		
		// Get the address hash.
		var addressHash = bytes.slice(6, 10);

		// Get the owner entropy.  (This gives access to LotNumber and SequenceNumber when applicable)
		var ownerEntropy = bytes.slice(10, 18);

		// Get encryptedpointb
		var encryptedpointb = bytes.slice(18, 51);

		var compressed = (flagByte & 0x20) == 0x20;
		var lotSequencePresent = (flagByte & 0x04) == 0x04;
		var ownerSalt = ownerEntropy.slice(0, lotSequencePresent ? 4 : 8)

		Crypto.Scrypt(passphrase, ownerSalt, 16384, 8, 8, 32, function(prefactor) {
			// Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
			var passfactorBytes = !lotSequencePresent? prefactor : Bitcoin.Util.dsha256(prefactor.concat(ownerEntropy));
			var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);

			var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
			var curve = ecparams.getCurve();
			var passpoint = ecparams.getG().multiply(passfactor).getEncoded(1);

			var addresshashplusownerentropy = addressHash.concat(ownerEntropy);

			Crypto.Scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64, function(derivedBytes) 
			{
				var AES_opts = {mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true};
				var unencryptedpubkey = [];

	            // recover the 0x02 or 0x03 prefix
	            unencryptedpubkey[0] = encryptedpointb[0] ^ (derivedBytes[63] & 0x01);

				decrypted1 = Crypto.AES.decrypt(encryptedpointb.slice(1,17), derivedBytes.slice(32), AES_opts);
				decrypted2 = Crypto.AES.decrypt(encryptedpointb.slice(17,33), derivedBytes.slice(32), AES_opts);
				decrypted = unencryptedpubkey.concat(decrypted1).concat(decrypted2)

				for (var x = 0; x < 32; x++) { 
					decrypted[x+1] ^= derivedBytes[x];
				}

				var curve = EllipticCurve.getSECCurveByName("secp256k1");
				var ec = curve.getCurve();
				var generatedPoint = ec.decodePointHex(Crypto.util.bytesToHex(decrypted).toString().toUpperCase());
				var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(passfactor)).getEncoded(compressed);
				var generatedAddress = (new Bitcoin.Address(Bitcoin.Util.sha256ripe160(generatedBytes))).toString();

				var generatedAddressHash = Bitcoin.Util.dsha256(generatedAddress).slice(0,4);

				var valid = true;
				for (var i = 0; i < 4; i++) {
					if (addressHash[i] != generatedAddressHash[i]) {
						valid = false;
					}
				}
				
				callback(valid, generatedAddress);
			});
		});
	}
};
