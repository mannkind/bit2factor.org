$(function() {
	$('body').click(SecureRandom.seedTime).keypress(SecureRandom.seedTime);
  $('form').submit(function(e) { e.preventDefault(); });

	var disableButtons = function(item) { item.parent().children('button').attr('disabled', 'disabled'); };
	var enableButtons = function(item) { item.parent().children('button').attr('disabled', null); };
	var enableSpinner = function(item) { 
    	item.button('loading');
	};
	var disableSpinner = function(item) { 
    	item.button('reset');
	};

	$('#rec-genint-gen').click(function(e) {
		e.preventDefault();

		$this = $(this);
		$target = $(e.target);
		disableButtons($this);
		enableSpinner($target);

		var passphrase = $('#rec-genint-passphrase');

		if (passphrase.val().length <= 0) {
			passphrase.popover({ content: 'The passphrase is invalid' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		Bitcoin.BIP38.GenerateIntermediatePointAsync(passphrase.val(), null, null, function(intermediate) {
			$('#rec-genint-intermediate').val(intermediate);
			enableButtons($this);
			disableSpinner($target);
		});
	});

	$('#rec-decenc-decrypt').click(function(e) {
		e.preventDefault();

		$this = $(this);
		$target = $(e.target);
		disableButtons($this);
		enableSpinner($target);
		
		var encryptedKey = $('#rec-decenc-privatekey');
		var passphrase = $('#rec-decenc-passphrase');

		if (passphrase.val().length <= 0) {
			passphrase.popover({ content: 'The passphrase is invalid' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		if (!Bitcoin.BIP38.isBIP38Format(encryptedKey.val())) {
			encryptedKey.popover({ content: 'Invalid encrypted key' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		Bitcoin.BIP38.EncryptedKeyToByteArrayAsync(encryptedKey.val(), passphrase.val(), function(privateKeyByteArray) {
			if (privateKeyByteArray != null && privateKeyByteArray.length > 0) {
				$('#rec-decenc-wif').val(new Bitcoin.ECKey(privateKeyByteArray).getBitcoinWalletImportFormat());	
			} else {
				$('#rec-decenc-wif').val('Invalid encrypted key or passphrase');	
			}
			
			enableButtons($this);
			disableSpinner($target);
        });
	});

	$('#send-gencon-enc').click(function(e) {
		e.preventDefault();

		$this = $(this);
		$target = $(e.target);
		disableButtons($this);
		enableSpinner($target);

		var intermediate = $('#send-gencon-intermediate');

		if (intermediate.val().length <= 0 || intermediate.val().substr(0, 10) != 'passphrase') { 
			intermediate.popover({ content: 'Invalid intermediate code' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		try {
			Bitcoin.BIP38.GenerateECAddressAsync(intermediate.val(), false, function(confirmationCode, generatedAddress, encryptedKey) {
				$('#send-gencon-address').val(generatedAddress);
				$('#send-gencon-privatekey').val(encryptedKey);
				$('#send-gencon-confirmation').val(confirmationCode);
				enableButtons($this);
				disableSpinner($target);
			});
		} catch (e) {
			$('#send-gencon-address').val('Invalid intermediate code');
			$('#send-gencon-privatekey').val('Invalid intermediate code');
			$('#send-gencon-confirmation').val('Invalid intermediate code');
			enableButtons($this);
			disableSpinner($target);
		}
	});

	$('#rec-vercon-verify').click(function(e) {
		e.preventDefault();

		$this = $(this);
		$target = $(e.target);
		disableButtons($this);
		enableSpinner($target);

		var modal = $('#rec-vercon-modal');
		var verification = $('#rec-vercon-verification');
		var confirmation = $('#rec-vercon-confirmation');
		var passphrase = $('#rec-vercon-passphrase');

		if (passphrase.val().length <= 0) {
			passphrase.popover({ content: 'The passphrase is invalid' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		if (confirmation.val().length <= 0 || confirmation.val().substr(0, 6) != 'cfrm38') {
			confirmation.popover({ content: 'The confirmation code is invalid' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		} 

		try {
	        Bitcoin.BIP38.ValidateConfirmationAsync(confirmation.val(), passphrase.val(), function(isValid, generatedAddress) {
	            if (!isValid) {
		            verification.text('The passphrase or confirmation code is invalid');
	            } else {
					verification.text('The address ' + generatedAddress + ' is associated with your passphrase');
	        	}
	        	modal.modal('show');
				enableButtons($this);
				disableSpinner($target);
	        });
    	} catch (e) {
    		verification.text('The passphrase or confirmation code is invalid');
    		modal.modal('show');
    		enableButtons($this);
			disableSpinner($target);
    	}
	});

	$('#encgen-encrypt').click(function(e) {
		e.preventDefault();

		$this = $(this);
		$target = $(e.target);
		disableButtons($this);
		enableSpinner($target);

		var passphrase = $('#encgen-passphrase');
		
		if (passphrase.val().length <= 0) {
			passphrase.popover({ content: 'Invalid passphrase' }).popover('show');
			enableButtons($this);
			disableSpinner($target);
			return;
		}

		Bitcoin.BIP38.GenerateIntermediatePointAsync(passphrase.val(), null, null, function(intermediate) {
			Bitcoin.BIP38.GenerateECAddressAsync(intermediate, false, function(confirmationCode, generatedAddress, encryptedKey) {
				$('#encgen-address').val(generatedAddress);
				$('#encgen-privkey').val(encryptedKey);
				enableButtons($this);
				disableSpinner($target);
			});
		});
	});



	/**
	 * Testing Code
	 */
	var hash;hash={};window.location.hash.replace(/[#&]+([^=&]+)=([^&]*)/g,function(g,h,i){return hash[h]=i});
	if (hash['runtests'] == 'true') {
		console.log('Running tests...');

		function runSerialized(functions, onComplete) {
			onComplete = onComplete || function() {};

			if(functions.length === 0) onComplete();
			else {
				// run the first function, and make it call this
				// function when finished with the rest of the list
				var f = functions.shift();
				f(function() { runSerialized(functions, onComplete); } );
			}
		}

		function forSerialized(initial, max, whatToDo, onComplete) {
			onComplete = onComplete || function() {};

			if(initial === max) { onComplete(); }
			else {
				// same idea as runSerialized
				whatToDo(initial, function() { forSerialized(++initial, max, whatToDo, onComplete); });
			}
		}

		function foreachSerialized(collection, whatToDo, onComplete) {
			var keys = [];
			for(var name in collection) {
				keys.push(name);
			}
			forSerialized(0, keys.length, function(i, callback) {
				whatToDo(keys[i], callback);
			}, onComplete);
		}



		var tests = 
		[
			["6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg","TestingOneTwoThree","5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"],
			["6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq","Satoshi","5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5"],
			["6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo","TestingOneTwoThree","L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP"],
			["6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7","Satoshi","KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7"],
			["6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX","TestingOneTwoThree","5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2"],
			["6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd","Satoshi","5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH"],
			["6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j","MOLON LABE","5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", "cfrm38V8aXBn7JWA1ESmFMUn6erxeBGZGAxJPY4e36S9QWkzZKtaVqLNMgnifETYw7BPwWC9aPD"],
			["6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",Crypto.charenc.UTF8.bytesToString([206,156,206,159,206,155,206,169,206,157,32,206,155,206,145,206,146,206,149]), "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D", "cfrm38V8G4qq2ywYEFfWLD5Cc6msj9UwsG2Mj4Z6QdGJAFQpdatZLavkgRd1i4iBMdRngDqDs51"]
		];

		var decryptTest = function(test, i, onComplete) {
			Bitcoin.BIP38.EncryptedKeyToByteArrayAsync(test[0], test[1], function(privBytes) {
				if (privBytes.constructor == Error) {
					console.log('fail testBip38Decrypt #'+i+', error: '+privBytes.message);
				} else {
					var btcKey = new Bitcoin.ECKey(privBytes);
					var wif = !test[2].substr(0,1).match(/[LK]/) ? btcKey.getBitcoinWalletImportFormat() : btcKey.getBitcoinWalletImportFormatCompressed();
					if (wif != test[2]) {
						console.log("fail testBip38Decrypt #"+i);
					} else {
						console.log('pass testBip38Decrypt #'+i);
					}
				}
				onComplete();
			});
		}
		var encryptTest = function(test, compressed, i, onComplete) {
			Bitcoin.BIP38.PrivateKeyToEncryptedKeyAsync(test[2], test[1], compressed,  function(encryptedKey) {
				if(encryptedKey === test[0]) {
					console.log('pass testBip38Encrypt #'+i);
				} else {
					console.log('fail testBip38Encrypt #' + i);
					console.log('testBip38Encrypt fail #%d: expected %s\nreceived %s', i, test[0], encryptedKey);
				}
				onComplete();
			});
		}
		// test randomly generated encryption-decryption cycle
		var cycleTest = function(i, compress, onComplete) {
			// create new private key
			var privKey = (new Bitcoin.ECKey(false)).getBitcoinWalletImportFormat();

			// encrypt private key
			Bitcoin.BIP38.PrivateKeyToEncryptedKeyAsync(privKey, 'testing', compress, function(encryptedKey) {
				// decrypt encryptedKey
				Bitcoin.BIP38.EncryptedKeyToByteArrayAsync(encryptedKey, 'testing', function(decryptedBytes) {
					var decryptedKey = (new Bitcoin.ECKey(decryptedBytes)).getBitcoinWalletImportFormat();

					if(decryptedKey === privKey) {
						console.log('pass cycleBip38 test #' + i);
					}
					else {
						console.log('fail cycleBip38 test: ' + privKey);
						console.log('cycleBip38 fail: private key: %s\nencrypted key: %s\ndecrypted key: %s',
							    privKey, encryptedKey, decryptedKey);
					}
					onComplete();
				});
			});
		}

		// intermediate test - create some encrypted keys from an intermediate
		// then decrypt them to check that the private keys are recoverable
		var intermediateTest = function(onComplete) {
			var pass = Math.random().toString(36).substr(2);
			Bitcoin.BIP38.GenerateIntermediatePointAsync(pass, null, null, function(intermediatePoint) {
				Bitcoin.BIP38.GenerateECAddressAsync(intermediatePoint, false, function(confirmation, address, encryptedKey) {
					Bitcoin.BIP38.EncryptedKeyToByteArrayAsync(encryptedKey, pass, function(privBytes) {
						if (privBytes.constructor == Error) {
							console.log('fail testBip38Intermediate, error: '+privBytes.message);
						} else {
							var btcKey = new Bitcoin.ECKey(privBytes);
							var btcAddress = btcKey.getBitcoinAddress();
							if(address !== btcKey.getBitcoinAddress()) {
								console.log("fail testBip38Intermediate");
							} else {
								console.log('pass testBip38Intermediate');
							}
						}
						onComplete();
					});
				});
			});
		}

		var confirmationTest = function(test, i, onComplete) {
			if (typeof test[3] != 'undefined') { 
				Bitcoin.BIP38.ValidateConfirmationAsync(test[3], test[1], function(isValid, generatedAddress) {
					if (isValid) {
						console.log('pass testBip38confirmation #' + i);
					} else {
						console.log('fail testBip38confirmation #' + i);
					}
					onComplete();
				});
			} else {
				onComplete();
			}
		}

		// running each test uses a lot of memory, which isn't freed
		// immediately, so give the VM a little time to reclaim memory
		function waitThenCall(callback) {
			return function() { setTimeout(callback, 1000); }
		}

		runSerialized([
			function(cb) {
				forSerialized(0, 4, function(i, callback) {
					// only first 4 test vectors are not EC-multiply,
					// compression param false for i = 1,2 and true for i = 3,4
					encryptTest(tests[i], i >= 2, i, waitThenCall(callback));
				}, waitThenCall(cb));
			},
			function(cb) {
				forSerialized(6, 8, function(i, callback) {
					confirmationTest(tests[i], i, waitThenCall(callback));
				}, waitThenCall(cb));
			},
			function(cb) {
				forSerialized(0, tests.length, function(i, callback) {
					decryptTest(tests[i], i, waitThenCall(callback));
				}, waitThenCall(cb));
			},
			function(cb) {
				forSerialized(0, 2, function(i, callback) {
					cycleTest(i, i % 2? true : false, waitThenCall(callback));
				}, waitThenCall(cb));
			},
			function(cb) {
				forSerialized(0,5,function(i, callback) {
					intermediateTest(waitThenCall(callback));
				}, cb);
			}
		], function() { console.log('... done running tests'); });

	}
});
