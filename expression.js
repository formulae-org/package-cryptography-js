/*
Fōrmulæ cryptography package. Module for expression definition & visualization.
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

export class Cryptography extends Formulae.ExpressionPackage {};

Cryptography.Key = class extends Expression.Literal {
	set(name, value) {
		switch (name) {
			case "Value":
				this.key = value;
				return;
			/*
			case "Type":
				this.type = value;
				return;
			
			case "Algorithm":
				this.algorithm = algorithm;
				return;
			*/
		}
		
		super.set(name, value);
	}
	
	get(name) {
		switch (name) {
			case "Value":
				return this.key;
			/*
			case "Type":
				return this.type;
			
			case "Usage":
				return this.usage;
			*/
		}
		
		return super.get(name);
	}
	
	getSerializationNames() {
		return [ "Value", "Type", "Algorithm", "Parameter" ];
	}
	
	async getSerializationStrings() {
		let value;
		
		/*
		switch (this.type) {
			case "secret":
				str = (await window.crypto.subtle.exportKey("jwk", this.key)).stringify();
				break;
			
			case "private":
				{
					let arrayBuffer = await window.crypto.subtle.exportKey("pkcs8", this.key);
					str = Utils.bytesToBase64(new Uint8Array(arrayBuffer));
				}
				break;
			
			case "public":
				{
					let arrayBuffer = await window.crypto.subtle.exportKey("spki", this.key);
					str = Utils.bytesToBase64(new Uint8Array(arrayBuffer));
				}
				break;
		}
		*/
		
		switch (this.key.algorithm.name) {
			case "RSA-OAEP":          // encryption
			case "RSASSA-PKCS1-v1_5": // signing
			case "RSA-PSS":           // signing
				{
					let arrayBuffer;
					
					if (this.key.type === "private") {
						arrayBuffer = await window.crypto.subtle.exportKey("pkcs8", this.key);
					}
					else { // public
						arrayBuffer = await window.crypto.subtle.exportKey("spki", this.key);
					}
					
					return [
						Utils.bytesToBase64(new Uint8Array(arrayBuffer)), // value
						this.key.type,                                    // type
						this.key.algorithm.name,                          // algorithm
						this.key.algorithm.hash.name                      // parameter
					];
				}
			
			case "AES-CTR":
			case "AES-CBC":
			case "AES-GCM":
				{
					let arrayBuffer = await window.crypto.subtle.exportKey("raw", this.key);
					return [
						Utils.bytesToBase64(new Uint8Array(arrayBuffer)), // value
						this.key.type,                                    // type
						this.key.algorithm.name,                          // algorithm
						this.key.algorithm.length.toString()              // parameter
					];
				}
		}
	}
	
	setSerializationStrings(strings, promises) {
		let type  = strings[1];
		let algorithmName = strings[2];
		let parameter = strings[3];
		
		let format;
		let keyData;
		let algorithm;
		let keyUsages;
		
		/*
		switch (this.type) {
			case "secret":
				format = "jwk";
				keyData = JSON.parse(strings[0]);
				algorithm = null;
				keyUsages = null;
				break;
			
			case "private":
				format = "pkcs8";
				keyData = Utils.base64ToBytes(strings[0]);
				algorithm = { name:"RSA-OAEP", hash: "SHA-256" };
				keyUsages = [ "decrypt" ];
				break;
			
			case "public":
				format = "spki";
				keyData = Utils.base64ToBytes(strings[0]);
				algorithm = { name:"RSA-OAEP", hash: "SHA-256" };
				keyUsages = [ "encrypt" ];
				break;
		}
		*/
		
		switch (algorithmName) {
			case "RSA-OAEP":          // encryption
			case "RSASSA-PKCS1-v1_5": // signing
			case "RSA-PSS":           // signing
				{
					if (type == "private") {
						format = "pkcs8";
						keyData = Utils.base64ToBytes(strings[0]);
						algorithm = { name: algorithmName, hash: parameter };
						keyUsages = [ algorithmName == "RSA-OAEP" ? "decrypt" : "sign" ];
					}
					else { // public
						format = "spki";
						keyData = Utils.base64ToBytes(strings[0]);
						algorithm = { name: algorithmName, hash: parameter };
						keyUsages = [ algorithmName == "RSA-OAEP" ? "encrypt" : "verify" ];
					}
				}
				break;
			
			case "AES-CTR":
			case "AES-CBC":
			case "AES-GCM":
				{
					format = "raw";
					keyData = Utils.base64ToBytes(strings[0]);
					algorithm = { name: algorithmName, length: Number(parameter) };
					keyUsages = [ "encrypt", "decrypt" ];
				}
				break;
		}
		
		let promise = window.crypto.subtle.importKey(
			format,
			keyData,
			algorithm,
			true, // extactable
			keyUsages
		);
		
		promise.then(key => this.key = key);
		
		promises.push(promise);
	}
	
	getLiteral() {
		return "<" + this.key.type + " - " + this.key.usages.join(", ") + ">";
	}
}

Cryptography.setExpressions = function(module) {
	[ "Secret", "Private", "Public" ].forEach(
		tag => Formulae.setExpression(
			module,
			"Cryptography.Key." + tag + "Key",
			{
				clazz:      Cryptography.Key,
				getTag:     () => "Cryptography.Key." + tag + "Key",
				getName:    () => Cryptography.messages["nameKey" + tag],
			}
		)
	);
	
	// Operations
	
	[
		[ "Key",        "GenerateAsymmetricKeysForEncryption", 1, 2 ],
		[ "Key",        "GenerateSymmetricKeyForEncryption",   1, 2 ],
		[ "Key",        "GenerateAsymmetricKeysForSigning",    1, 2 ],
		[ "Encryption", "Encrypt",                             2, 3 ],
		[ "Encryption", "Decrypt",                             2, 3 ],
		[ "Hashing",    "Hash",                                2, 2 ],
		[ "Signing",    "Sign",                                2, 3 ],
		[ "Signing",    "Verify",                              3, 4 ],
	].forEach(
		row => Formulae.setExpression(
			module,
			"Cryptography." + row[0] + "." + row[1],
			{
				clazz:        Expression.Function,
				getTag:       () => "Cryptography." + row[0] + "." + row[1],
				getMnemonic:  () => Cryptography.messages["mnemonic" + row[1]],
				getName:      () => Cryptography.messages["name" + row[1]],
				getChildName: index => Cryptography.messages["children" + row[1]][index],
				min:          row[2],
				max:          row[3]
			}
		)
	);
	
	Formulae.setExpression(
		module,
		"Cryptography.Random",
		{
			clazz:        Expression.Function,
			getTag:       () => "Cryptography.Random",
			getMnemonic:  () => Cryptography.messages.mnemonicRandom,
			getName:      () => Cryptography.messages.nameRandom,
			getChildName: index => Cryptography.messages.childRandom,
			min:          1,
			max:          1
		}
	);
	
	// Algorithms
	
	[
		[ "Hashing", "SHA-1"   ],
		[ "Hashing", "SHA-256" ],
		[ "Hashing", "SHA-384" ],
		[ "Hashing", "SHA-512" ],
		[ "AsymmetricEncryption", "RSA-OAEP" ],
		[ "SymmetricEncryption", "AES-CTR" ],
		[ "SymmetricEncryption", "AES-CBC" ],
		[ "SymmetricEncryption", "AES-GCM" ],
		[ "Signing", "RSASSA-PKCS1-v1_5" ],
		[ "Signing", "RSA-PSS"           ],
		[ "Signing", "ECDSA"             ],
		[ "Signing", "HMAC"              ],
	].forEach(
		row => Formulae.setExpression(
			module,
			"Cryptography.Algorithm." + row[0] + "." + row[1],
			{
				clazz:      Expression.LabelExpression,
				getTag:     () => "Cryptography.Algorithm." + row[0] + "." + row[1],
				getLabel:   () => row[1],
				getName:    () => "yyy"
			}
		)
	);
};
