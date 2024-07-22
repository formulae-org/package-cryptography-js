/*
Fōrmulæ cryptography package. Module for reduction.
Copyright (C) 2015-2023 Laurence R. Ugalde

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

'use strict';

export class Cryptography extends Formulae.ReductionPackage {};

//////////////////////////////////////////
// Algorithm options for Key generation //
//////////////////////////////////////////

// number to Uint8Array

Cryptography.nToUint8Array = n => {
	let dataView = new DataView(new ArrayBuffer(8), 0);
	dataView.setBigUint64(0, BigInt(n));
	return new Uint8Array(dataView.buffer);
};

Cryptography._65537 = new Uint8Array([1, 0, 1]);

Cryptography.RSAOptions = class extends CanonicalOptions {
	constructor(name) {
		super();
		this.name           = name;
		this.modulusLength  = 2048;
		this.publicExponent = Cryptography._65537;
		//this.hash           = "SHA-256";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "modulus length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || i <= 0) {
					ReductionManager.setInError(value, "Value must be a positive integer number");
					return false;
				}
				
				this.modulusLength = i;
				return true;
			}
			
			case "public exponent": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || !(i == 3 || i === 65537)) {
					ReductionManager.setInError(value, "Value must be 3 or 65,537");
					return false;
				}
				
				this.publicExponent = Cryptography.nToUint8Array(i);
				return true;
			}
			
			case "hash": {
				let algorithmTag = value.getTag();
				
				if (!algorithmTag.startsWith("Cryptography.Algorithm.Hashing")) {
					ReductionManager.setInError(value, "Invalid hash algorithm");
					return false;
				}
				
				this.hash = algorithmTag.substring(31);
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.hash === undefined) {
			ReductionManager.setInError(expression, "Option ´Hash' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.EllipticCurveOptions = class extends CanonicalOptions {
	constructor(name) {
		super();
		this.name = name;
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "named curve": {
				if (!(
					value.getTag() === "String.String" &&
					[ "P-256", "P-384", "P-521" ].includes(value.get("Value"))
				)) {
					ReductionManager.setInError(value, 'Value must be one of the strings "P-256", "P-384" or "P-521"');
					return false;
				}
				
				this.namedCurve = value.get("Value");
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.namedCurve === undefined) {
			ReductionManager.setInError(expression, "Option ´Named curve' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.AESOptions = class extends CanonicalOptions {
	constructor(name) {
		super();
		this.name = name;
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || !(i === 128 || i === 192 || i === 256)) {
					ReductionManager.setInError(value, "Value must on of the numbers 128, 192 or 256");
					return false;
				}
				
				this.length = i;
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.length === undefined) {
			ReductionManager.setInError(expression, "Option ´Length' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.HMACOptions = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "HMAC";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "hash": {
				let algorithmTag = value.getTag();
				
				if (!algorithmTag.startsWith("Cryptography.Algorithm.Hashing")) {
					ReductionManager.setInError(value, "Invalid hash algorithm");
					return false;
				}
				
				this.hash = algorithmTag.substring(31);
				return true;
			}
			
			case "length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || i <= 0) {
					ReductionManager.setInError(value, "Value must be a positive integer number");
					return false;
				}
				
				this.length = i;
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.hash === undefined) {
			ReductionManager.setInError(expression, "Option ´Hash' is required");
			return false;
		}
		
		return true;
	}
}

//////////////////////////////////////////////////
// Generation of asymmetric keys for encryption //
//////////////////////////////////////////////////

Cryptography.generateAsymmetricKeysForEncryption = async (generateKey, session) => {
	// algorithm
	
	let algorithmTag = generateKey.children[0].getTag();
	
	// options
	
	let optionsExpr = generateKey.children[1];
	let options;
	
	switch (algorithmTag) {
		case "Cryptography.Algorithm.AsymmetricEncryption.RSA-OAEP":
			options = new Cryptography.RSAOptions(algorithmTag.substr(44));
			console.log(options);
			break;
		
		default:
			ReductionManager.setInError(generateKey.children[0], "Invalid algorithm");
			throw new ReductionError();
	}
	
	options.checkOptions(generateKey, optionsExpr);
	
	// Ok
	
	let keyPair = await window.crypto.subtle.generateKey(
		options,
		true, // extractable
		[ "encrypt", "decrypt" ],
	);
	
	let result = Formulae.createExpression("List.List");
	
	let privateKey = Formulae.createExpression("Cryptography.Key.PrivateKey");
	privateKey.set("Value", keyPair.privateKey);
	
	let publicKey = Formulae.createExpression("Cryptography.Key.PublicKey");
	publicKey.set("Value", keyPair.publicKey);
	
	result.addChild(privateKey);
	result.addChild(publicKey);
	
	generateKey.replaceBy(result);
	return true;
};

////////////////////////////////////////////////
// Generation of symmetric key for encryption //
////////////////////////////////////////////////

Cryptography.generateSymmetricKeyForEncryption = async (generateKey, session) => {
	// algorithm
	
	let algorithmTag = generateKey.children[0].getTag();
	
	// options
	
	let optionsExpr = generateKey.children[1];
	let options;
	
	switch (algorithmTag) {
		case "Cryptography.Algorithm.SymmetricEncryption.AES-CTR":
		case "Cryptography.Algorithm.SymmetricEncryption.AES-CBC":
		case "Cryptography.Algorithm.SymmetricEncryption.AES-GCM":
			options = new Cryptography.AESOptions(algorithmTag.substr(43));
			break;
		
		default:
			ReductionManager.setInError(generateKey.children[0], "Invalid algorithm");
			throw new ReductionError();
	}
	
	options.checkOptions(generateKey, optionsExpr);
	
	// Ok
	
	let key = await window.crypto.subtle.generateKey(
		options,
		true, // extractable
		[ "encrypt", "decrypt" ],
	);
	
	let secretKey = Formulae.createExpression("Cryptography.Key.SecretKey");
	secretKey.set("Value", key);
	
	generateKey.replaceBy(secretKey);
	return true;
};

////////////////////////////////////
// Generation of keys for signing //
////////////////////////////////////

Cryptography.generateAsymmetricKeysForSigning = async (generateKey, session) => {
	// algorithm
	
	let algorithmTag = generateKey.children[0].getTag();
	
	// options
	
	let optionsExpr = generateKey.children[1];
	let options;
	
	switch (algorithmTag) {
		case "Cryptography.Algorithm.Signing.RSASSA-PKCS1-v1_5":
		case "Cryptography.Algorithm.Signing.RSA-PSS":
			options = new Cryptography.RSAOptions(algorithmTag.substr(31));
			break;
		
		case "Cryptography.Algorithm.Signing.ECDSA":
			options = new Cryptography.EllipticCurveOptions(algorithmTag.substr(31));
			break;
		
		case "Cryptography.Algorithm.Signing.HMAC":
			options = new Cryptography.HMACOptions();
			break;
		
		default:
			ReductionManager.setInError(generateKey.children[0], "Invalid algorithm");
			throw new ReductionError();
	}
	
	options.checkOptions(generateKey, optionsExpr);
	
	// Ok
	
	let keyPair = await window.crypto.subtle.generateKey(
		options,
		true, // extractable
		[ "sign", "verify" ],
	);
	
	let result = Formulae.createExpression("List.List");
	
	let privateKey = Formulae.createExpression("Cryptography.Key.PrivateKey");
	privateKey.set("Value", keyPair.privateKey);
	
	let publicKey = Formulae.createExpression("Cryptography.Key.PublicKey");
	publicKey.set("Value", keyPair.publicKey);
	
	result.addChild(privateKey);
	result.addChild(publicKey);
	
	generateKey.replaceBy(result);
	return true;
};

/////////////
// Hashing //
/////////////

Cryptography.hash = async (digest, session) => {
	// algorithm
	
	let algorithm = digest.children[1];
	let algorithmTag = algorithm.getTag();
	
	if (!algorithmTag.startsWith("Cryptography.Algorithm.Hashing.")) {
		ReductionManager.setInError(algorithm, "Invalid algorithm");
		throw new ReductionError();
	}
	
	// source
	
	let source = digest.children[0];
	let data;
	
	switch (source.getTag()) {
		case "Data.ByteBuffer":
			data = source.get("Value");
			break;
		
		case "FileSystem.File":
			data = await new Promise((resolve, reject) => {
				let fileReader = new FileReader();
				fileReader.onload = () => {
					resolve(fileReader.result);
				};
				fileReader.onerror = reject;
				fileReader.readAsArrayBuffer(source.get("Value"));
			});
			break;
		
		default:
			ReductionManager.setInError(source, "Value must be a byte buffer or a file");
			throw new ReductionError();
	}
	
	// Ok
	
	let hash = await crypto.subtle.digest(
		algorithmTag.substring(31),
		data
	);
	
	let result = Formulae.createExpression("Data.ByteBuffer");
	result.set("Value", hash);
	
	digest.replaceBy(result);
	return true;
};

/////////////////////////////
// Encription / decription //
/////////////////////////////

Cryptography.RSA_OAEP_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "RSA-OAEP";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "label": {
				if (value.getTag() !== "Data.ByteBuffer") {
					ReductionManager.setInError(value, "Value must be a byte buffer");
					return false;
				}
				
				this.label = value.get("Value");
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
}

Cryptography.AES_CTR_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "AES-CTR";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "counter": {
				if (value.getTag() !== "Data.ByteBuffer" || value.get("Value").byteLength !== 16) {
					ReductionManager.setInError(value, "Value must be a byte buffer of 16 bytes");
					return false;
				}
				
				this.counter = value.get("Value");
				return true;
			}
			
			case "length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || i < 0 || i > 128) {
					ReductionManager.setInError(value, "Value must be a number between 0 and 128");
					return false;
				}
				
				this.length = i;
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		let missing = [];
		
		if (this.counter === undefined) {
			missing.push("Counter");
		}
		
		if (this.length === undefined) {
			missing.push("Length");
		}
		
		if (missing.length > 0) {
			ReductionManager.setInError(
				expression,
				"The following options [" + missing.forEach(option => "'" + option + "'").join(",") + "] are required"
			);
			return false;
		}
		
		return true;
	}
}

Cryptography.AES_CBC_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "AES-CBC";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "initialization vector": {
				if (value.getTag() !== "Data.ByteBuffer" || value.get("Value").byteLength !== 16) {
					ReductionManager.setInError(value, "Value must be a byte buffer of 16 bytes");
					return false;
				}
				
				this.initializationVector = value.get("Value");
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.hash === initializationVector) {
			ReductionManager.setInError(expression, "Option ´Initialization vector' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.AES_GCM_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "AES-GCM";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "initialization vector": {
				if (value.getTag() !== "Data.ByteBuffer") {
					ReductionManager.setInError(value, "Value must be a byte buffer");
					return false;
				}
				
				this.initializationVector = value.get("Value");
				return true;
			}
			
			case "additional data": {
				if (value.getTag() !== "Data.ByteBuffer") {
					ReductionManager.setInError(value, "Value must be a byte buffer");
					return false;
				}
				
				this.additionalData = value.get("Value");
				return true;
			}
			case "tag length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || !([ 32, 64, 96, 104, 112, 120, 128].contains(i))) {
					ReductionManager.setInError(value, "Value must be one of the following numbers: 32, 64, 96, 104, 112, 120, 128");
					return false;
				}
				
				this.tagLength = i;
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.hash === initializationVector) {
			ReductionManager.setInError(expression, "Option ´Initialization vector' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.encrypt = async (encrypt, session) => {
	// key
	
	let key = encrypt.children[1];
	if (!(key.getTag() === "Cryptography.Key.PublicKey" || key.getTag() === "Cryptography.Key.SecretKey")) {
		ReductionManager.setInError(key, "Value is not a key for encryption");
		throw new ReductionError();
	}
	key = key.get("Value");
	
	// options
	
	let optionsExpr = encrypt.children[2];
	let options;
	
	switch (key.algorithm.name) {
		case "RSA-OAEP":
			options = new Cryptography.RSA_OAEP_Options();
			break;
		
		case "AES-CTR":
			options = new Cryptography.AES_CTR_Options();
			break;
		
		case "AES-CBC":
			options = new Cryptography.AES_CBC_Options();
			break;
		
		case "AES-GCM":
			options = new Cryptography.AES_GCM_Options();
			break;
	}
	
	options.checkOptions(encrypt, optionsExpr);
	
	// plain text
	
	let plain = encrypt.children[0];
	let data;
	
	switch (plain.getTag()) {
		case "Data.ByteBuffer":
			data = plain.get("Value");
			break;
			
		case "FileSystem.File":
			data = await new Promise(
				(resolve, reject) => {
					let fileReader = new FileReader();
					fileReader.onload = () => {
						resolve(fileReader.result);
					};
					fileReader.onerror = reject;
					fileReader.readAsArrayBuffer(plain.get("Value"));
				}
			);
			break;
		
		default:
			ReductionManager.setInError(key, "Plain data must be a byte buffer or a file");
			throw new ReductionError();
	}
	
	// Ok
	
	let cipher = await crypto.subtle.encrypt(
		options,
		key,
		data
	);
	
	let result = Formulae.createExpression("Data.ByteBuffer");
	result.set("Value", cipher);
	
	encrypt.replaceBy(result);
	return true;
};

Cryptography.decrypt = async (decrypt, session) => {
	// key
	
	let key = decrypt.children[1];
	if (!(key.getTag() === "Cryptography.Key.PrivateKey" || key.getTag() === "Cryptography.Key.SecretKey")) {
		ReductionManager.setInError(key, "Value is not a key for encryption");
		throw new ReductionError();
	}
	key = key.get("Value");
	
	
	// options
	
	let optionsExpr = decrypt.children[2];
	let options;
	
	switch (key.algorithm.name) {
		case "RSA-OAEP":
			options = new Cryptography.RSA_OAEP_Options();
			break;
		
		case "AES-CTR":
			options = new Cryptography.AES_CTR_Options();
			break;
		
		case "AES-CBC":
			options = new Cryptography.AES_CBC_Options();
			break;
		
		case "AES-GCM":
			options = new Cryptography.AES_GCM_Options();
			break;
	}
	
	options.checkOptions(decrypt, optionsExpr);
	
	// cipher text
	
	let cipher = decrypt.children[0];
	let data;
	
	switch (cipher.getTag()) {
		case "Data.ByteBuffer":
			data = cipher.get("Value");
			break;
			
		case "FileSystem.File":
			data = await new Promise((resolve, reject) => {
				let fileReader = new FileReader();
				fileReader.onload = () => {
					resolve(fileReader.result);
				};
				fileReader.onerror = reject;
				fileReader.readAsArrayBuffer(cipher.get("Value"));
			});
			break;
			
		default:
			ReductionManager.setInError(key, "Cipher data must be a byte buffer or a file");
			throw new ReductionError();
	}
	
	// Ok
	
	let plain = await crypto.subtle.decrypt(
		options,
		key,
		data
	);
	
	let result = Formulae.createExpression("Data.ByteBuffer");
	result.set("Value", plain);
	
	decrypt.replaceBy(result);
	return true;
};

/////////////////////////
// Signing / Verifying //
/////////////////////////

Cryptography.RSA_PSS_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "RSA-PSS";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "salt length": {
				let i = CanonicalArithmetic.getInteger(value);
				if (i === undefined || i < 0) {
					ReductionManager.setInError(value, "Value must be a non-negative number");
					return false;
				}
				
				this.saltLength = i;
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.saltLength === initializationVector) {
			ReductionManager.setInError(expression, "Option ´Salt length' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.ECDSA_Options = class extends CanonicalOptions {
	constructor() {
		super();
		this.name = "ECDSA";
	}
	
	checkOption(expression, option) {
		let name = option.children[0].get("Value").toLowerCase();
		let value = option.children[1];
		
		switch (name) {
			case "hash": {
				if (!value.getTag().startsWith("Cryptography.Algorithm.Hashing.")) {
					ReductionManager.setInError(value, "Invalid algorithm");
					throw new ReductionError();
				}
				
				this.hash = value.getTag().substring(31);
				return true;
			}
		}
		
		ReductionManager.setInError(option.children[0], "Unknown option");
		return false;
	}
	
	finalCheck(expression) {
		if (this.hash === initializationVector) {
			ReductionManager.setInError(expression, "Option ´Hash' is required");
			return false;
		}
		
		return true;
	}
}

Cryptography.sign = async (sign, session) => {
	// key
	
	let key = sign.children[1];
	if (key.getTag() !== "Cryptography.Key.PrivateKey") {
		ReductionManager.setInError(key, "Value is not a key for signing");
		throw new ReductionError();
	}
	key = key.get("Value");
	
	// options
	
	let optionsExpr = sign.children[2];
	let options;
	
	switch (key.algorithm.name) {
		case "RSASSA-PKCS1-v1_5":
			if (optionsExpr !== undefined) {
				ReductionManager.setInError(optionsExpr, "No options required");
				throw new ReductionError();
			}
			options = { "name": "RSASSA-PKCS1-v1_5" };
			break;
		
		case "RSA-PSS":
			options = new Cryptography.RSA_PSS_Options();
			options.checkOptions(sign, optionsExpr);
			break;
		
		case "ECDSA":
			options = new Cryptography.ECDSA_Options();
			options.checkOptions(sign, optionsExpr);
			break;
		
		case "HMAC":
			if (optionsExpr !== undefined) {
				ReductionManager.setInError(optionsExpr, "No options required");
				throw new ReductionError();
			}
			options = { "name": "HMAC" };
			break;
	}
	
	// data
	
	let dataExpr = sign.children[0];
	let data = null;
	
	switch (dataExpr.getTag()) {
		case "Data.ByteBuffer":
			data = dataExpr.get("Value");
			break;
		
		case "FileSystem.File":
			data = await new Promise((resolve, reject) => {
				let fileReader = new FileReader();
				fileReader.onload = () => {
					resolve(fileReader.result);
				};
				fileReader.onerror = reject;
				fileReader.readAsArrayBuffer(dataExpr.get("Value"));
			});
			break;
		
		default:
			ReductionManager.setInError(dataExpr, "Plain data must be a byte buffer or a file");
			throw new ReductionError();
	}
	
	let signature = await crypto.subtle.sign(
		options,
		key,
		data
	);
	
	// Ok
	
	let result = Formulae.createExpression("Data.ByteBuffer");
	result.set("Value", signature);
	sign.replaceBy(result);
	
	return true;
};

Cryptography.verify = async (verify, session) => {
	// key
	
	let key = verify.children[2];
	if (key.getTag() !== "Cryptography.Key.PublicKey") {
		ReductionManager.setInError(key, "Value is not a key for verifying");
		throw new ReductionError();
	}
	key = key.get("Value");
	
	// options
	
	let optionsExpr = verify.children[2];
	let options;
	
	switch (key.algorithm.name) {
		case "RSASSA-PKCS1-v1_5":
			if (optionsExpr !== undefined) {
				ReductionManager.setInError(optionsExpr, "No options required");
				throw new ReductionError();
			}
			options = { "name": "RSASSA-PKCS1-v1_5" };
			break;
		
		case "RSA-PSS":
			options = new Cryptography.RSA_PSS_Options();
			options.checkOptions(sign, optionsExpr);
			break;
		
		case "ECDSA":
			options = new Cryptography.ECDSA_Options();
			options.checkOptions(sign, optionsExpr);
			break;
		
		case "HMAC":
			if (optionsExpr !== undefined) {
				ReductionManager.setInError(optionsExpr, "No options required");
				throw new ReductionError();
			}
			options = { "name": "HMAC" };
			break;
	}
	
	// data
	
	let dataExpr = verify.children[0];
	let data = null;
	
	switch (dataExpr.getTag()) {
		case "Data.ByteBuffer":
			data = dataExpr.get("Value");
			break;
		
		case "FileSystem.File":
			data = await new Promise((resolve, reject) => {
				let fileReader = new FileReader();
				fileReader.onload = () => {
					resolve(fileReader.result);
				};
				fileReader.onerror = reject;
				fileReader.readAsArrayBuffer(dataExpr.get("Value"));
			});
			break;
		
		default:
			ReductionManager.setInError(dataExpr, "Cipher data must be a byte buffer or a file");
			throw new ReductionError();
	}
	
	// signature
	
	let signatureExpr = verify.children[1];
	let signature = null;
	
	switch (signatureExpr.getTag()) {
		case "Data.ByteBuffer":
			signature = signatureExpr.get("Value");
			break;
		
		default:
			ReductionManager.setInError(signatureExpr, "Signature must be a byte buffer");
			throw new ReductionError();
	}
	
	let v = await crypto.subtle.verify(
		options,
		key,
		signature,
		data
	);
	let result = Formulae.createExpression(v ? "Logic.True" : "Logic.False");
	
	verify.replaceBy(result);
	return true;
};

Cryptography.random = async (random, session) => {
	let n = CanonicalArithmetic.getInteger(random.children[0]);
	if (n === undefined || n < 0) {
		ReductionManager.setInError(random.children[0], "Invalid number of bytes");
		throw new ReductionError();
	};
	
	let uInt8Array = new Uint8Array(n);
	
	self.crypto.getRandomValues(uInt8Array)
	
	let result = Formulae.createExpression("Data.ByteBuffer");
	result.set("Value",  uInt8Array.buffer);
	
	random.replaceBy(result);
	return true;
};

Cryptography.setReducers = () => {
	ReductionManager.addReducer("Cryptography.Key.GenerateAsymmetricKeysForEncryption", Cryptography.generateAsymmetricKeysForEncryption, "Cryptography.generateAsymmetricKeysForEncryption");
	ReductionManager.addReducer("Cryptography.Key.GenerateSymmetricKeyForEncryption",   Cryptography.generateSymmetricKeyForEncryption,   "Cryptography.generateSymmetricKeyForEncryption");
	ReductionManager.addReducer("Cryptography.Key.GenerateAsymmetricKeysForSigning",    Cryptography.generateAsymmetricKeysForSigning,    "Cryptography.generateAsymmetricKeysForSigning");
	
	ReductionManager.addReducer("Cryptography.Encryption.Encrypt", Cryptography.encrypt, "Cryptography.encrypt");
	ReductionManager.addReducer("Cryptography.Encryption.Decrypt", Cryptography.decrypt, "Cryptography.decrypt");
	
	ReductionManager.addReducer("Cryptography.Hashing.Hash", Cryptography.hash, "Cryptography.hash");
	
	ReductionManager.addReducer("Cryptography.Signing.Sign",   Cryptography.sign,   "Cryptography.sign");
	ReductionManager.addReducer("Cryptography.Signing.Verify", Cryptography.verify, "Cryptography.verify");
	
	ReductionManager.addReducer("Cryptography.Random", Cryptography.random, "Cryptography.random");
};
