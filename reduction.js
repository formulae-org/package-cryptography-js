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

Cryptography.generateAsymmetricKeysForEncryption = async (generateKey, session) => {
	let keyPair = await window.crypto.subtle.generateKey(
		{
			name: "RSA-OAEP",
			modulusLength: 4096,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		[ "encrypt", "decrypt" ],
	);
	
	let result = Formulae.createExpression("List.List");
	
	let privateKey = Formulae.createExpression("Cryptography.Key.PrivateKey");
	privateKey.set("Value", keyPair.privateKey);
	//privateKey.set("Type", keyPair.privateKey.type);
	//privateKey.set("Usage", keyPair.privateKey.usages[0]);
	
	let publicKey = Formulae.createExpression("Cryptography.Key.PublicKey");
	publicKey.set("Value", keyPair.publicKey);
	//publicKey.set("Type", keyPair.publicKey.type);
	//publicKey.set("Usage", keyPair.publicKey.usages[0]);
	
	result.addChild(privateKey);
	result.addChild(publicKey);
	
	generateKey.replaceBy(result);
	return true;
};

Cryptography.generateAsymmetricKeysForSigning = async (generateKey, session) => {
	let keyPair = await window.crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 4096,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		[ "sign", "verify" ],
	);
	
	let result = Formulae.createExpression("List.List");
	
	let privateKey = Formulae.createExpression("Cryptography.Key.PrivateKey");
	privateKey.set("Value", keyPair.privateKey);
	//privateKey.set("Type", keyPair.privateKey.type);
	//privateKey.set("Usage", keyPair.privateKey.usages[0]);
	
	let publicKey = Formulae.createExpression("Cryptography.Key.PublicKey");
	publicKey.set("Value", keyPair.publicKey);
	//publicKey.set("Type", keyPair.publicKey.type);
	//publicKey.set("Usage", keyPair.publicKey.usages[0]);
	
	result.addChild(privateKey);
	result.addChild(publicKey);
	
	generateKey.replaceBy(result);
	return true;
};

Cryptography.hash = async (digest, session) => {
	let source = digest.children[0];
	
	let algorithm = digest.children[1];
	let algorithmTag = algorithm.getTag();
	
	if (!algorithmTag.startsWith("Cryptography.Hashing.Algorithm.")) {
		ReductionManager.setInError(algorithm, "Invalid algorithm");
		throw new ReductionError();
	}
	let algorithmName = algorithmTag.substring(31);
	
	let sourceTag = source.getTag();
	let data = null;

	switch (sourceTag) {
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
	}	
	
	if (data !== null) {
		let hash = await crypto.subtle.digest(algorithmName, data);
		
		let result = Formulae.createExpression("Data.ByteBuffer");
		result.set("Value", hash);
		digest.replaceBy(result);
		
		return true;
	}
	
	return false;
};

Cryptography.encrypt = async (encrypt, session) => {
	let plain = encrypt.children[0];
	
	let key = encrypt.children[1];
	if (key.getTag() !== "Cryptography.Key.PublicKey") return false;
	key = key.get("Value");
	
	let data = null;
	
	switch (plain.getTag()) {
		case "Data.ByteBuffer":
			data = plain.get("Value");
			break;
			
		case "FileSystem.File":
			data = await new Promise((resolve, reject) => {
				let fileReader = new FileReader();
				fileReader.onload = () => {
					resolve(fileReader.result);
				};
				fileReader.onerror = reject;
				fileReader.readAsArrayBuffer(plain.get("Value"));
			});
			break;
	}	
	
	if (data !== null) {
		let cipher = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, data);
		let result = Formulae.createExpression("Data.ByteBuffer");
		result.set("Value", cipher);
		encrypt.replaceBy(result);
		
		return true;
	}
	
	return false;
};

Cryptography.decrypt = async (decrypt, session) => {
	let cipher = decrypt.children[0];
	
	let key = decrypt.children[1];
	if (key.getTag() !== "Cryptography.Key.PrivateKey") return false;
	key = key.get("Value");
	
	let data = null;
	
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
	}	
	
	if (data !== null) {
		let plain = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, data);
		
		let result = Formulae.createExpression("Data.ByteBuffer");
		result.set("Value", plain);
		decrypt.replaceBy(result);
		
		return true;
	}
	
	return false;
};

Cryptography.sign = async (sign, session) => {
	let dataExpr = sign.children[0];
	
	let key = sign.children[1];
	if (key.getTag() !== "Cryptography.Key.PrivateKey") return false;
	key = key.get("Value");
	
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
	}	
	
	if (data !== null) {
		let signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, data);
		
		let result = Formulae.createExpression("Data.ByteBuffer");
		result.set("Value", signature);
		sign.replaceBy(result);
		
		return true;
	}
	
	return false;
};

Cryptography.verify = async (verify, session) => {
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
	}	
	
	let signatureExpr = verify.children[1];
	let signature = null;
	
	switch (signatureExpr.getTag()) {
		case "Data.ByteBuffer":
			signature = signatureExpr.get("Value");
			break;
	}	
	
	let key = verify.children[2];
	if (key.getTag() !== "Cryptography.Key.PublicKey") return false;
	key = key.get("Value");
	
	if (data !== null && signature !== null) {
		let v = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, data);
		let result = Formulae.createExpression(v ? "Logic.True" : "Logic.False");
		
		verify.replaceBy(result);
		return true;
	}
	
	return false;
};

Cryptography.setReducers = () => {
	ReductionManager.addReducer("Cryptography.Key.GenerateAsymmetricKeysForEncryption", Cryptography.generateAsymmetricKeysForEncryption, "Cryptography.generateAsymmetricKeysForEncryption");
	ReductionManager.addReducer("Cryptography.Key.GenerateAsymmetricKeysForSigning",    Cryptography.generateAsymmetricKeysForSigning,    "Cryptography.generateAsymmetricKeysForSigning");
	
	ReductionManager.addReducer("Cryptography.Encryption.Encrypt", Cryptography.encrypt, "Cryptography.encrypt");
	ReductionManager.addReducer("Cryptography.Encryption.Decrypt", Cryptography.decrypt, "Cryptography.decrypt");
	
	ReductionManager.addReducer("Cryptography.Hashing.Hash", Cryptography.hash, "Cryptography.hash");
	
	ReductionManager.addReducer("Cryptography.Signing.Sign",   Cryptography.sign,   "Cryptography.sign");
	ReductionManager.addReducer("Cryptography.Signing.Verify", Cryptography.verify, "Cryptography.verify");
};
