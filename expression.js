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
		return [ "Value", "Type", "Algorithm" ];
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
			case "RSA-OAEP":
			case "RSASSA-PKCS1-v1_5": {
				let arrayBuffer;
				
				if (this.key.type === "private") {
					arrayBuffer = await window.crypto.subtle.exportKey("pkcs8", this.key);
				}
				else {
					arrayBuffer = await window.crypto.subtle.exportKey("spki", this.key);
				}
				
				return [ Utils.bytesToBase64(new Uint8Array(arrayBuffer)), this.key.type, this.key.algorithm.name ];
			}
		}
	}
	
	setSerializationStrings(strings, promises) {
		let type  = strings[1];
		let algorithmName = strings[2];
		
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
			case "RSA-OAEP":
			case "RSASSA-PKCS1-v1_5": {
				if (type == "private") {
					format = "pkcs8";
					keyData = Utils.base64ToBytes(strings[0]);
					algorithm = { name: algorithmName, hash: "SHA-256" };
					keyUsages = [ algorithmName == "RSA-OAEP" ? "decrypt" : "sign" ];
				}
				else {
					format = "spki";
					keyData = Utils.base64ToBytes(strings[0]);
					algorithm = { name: algorithmName, hash: "SHA-256" };
					keyUsages = [ algorithmName == "RSA-OAEP" ? "encrypt" : "verify" ];
				}
			}
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
		return "<" + this.key.type + " - " + this.key.usages + ">";
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
	
	[
		[ "Key",        "GenerateAsymmetricKeysForEncryption", 1, 1 ],
		[ "Key",        "GenerateAsymmetricKeysForSigning",    1, 1 ],
		[ "Encryption", "Encrypt",                             2, 2 ],
		[ "Encryption", "Decrypt",                             2, 2 ],
		[ "Hashing",    "Hash",                                2, 2 ],
		[ "Signing",    "Sign",                                2, 2 ],
		[ "Signing",    "Verify",                              3, 3 ],
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
	
	[ "SHA-1", "SHA-256", "SHA-384", "SHA-512" ].forEach(
		tag => Formulae.setExpression(
			module,
			"Cryptography.Hashing.Algorithm." + tag,
			{
				clazz:      Expression.LabelExpression,
				getTag:     () => "Cryptography.Hashing.Algorithm." + tag,
				getLabel:   () => tag,
				getName:    () => "yyy"
			}
		)
	);
};
