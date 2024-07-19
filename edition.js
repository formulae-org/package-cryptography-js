/*
Fōrmulæ cryptography package. Module for edition.
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

export class Cryptography extends Formulae.EditionPackage {};

Cryptography.setEditions = function() {
	[
		"GenerateAsymmetricKeysForEncryption",
		"GenerateSymmetricKeyForEncryption",
		"GenerateAsymmetricKeysForSigning"
	].forEach(
		tag => Formulae.addEdition(
			this.messages.pathKey,
			null,
			this.messages["leaf" + tag],
			() => Expression.wrapperEdition("Cryptography.Key." + tag)
		)
	);
	
	// Operations
	
	[
		[ "Encryption", "Encrypt", 2 ],
		[ "Encryption", "Decrypt", 2 ],
		[ "Hashing",    "Hash",    2 ],
		[ "Signing",    "Sign",    2 ],
		[ "Signing",    "Verify",  3 ],
	].forEach(
		row => Formulae.addEdition(
			this.messages["path" + row[0]],
			null,
			this.messages["leaf" + row[1]],
			() => Expression.multipleEdition("Cryptography." + row[0] + "." + row[1], row[2], 0)
		)
	);
	
	Formulae.addEdition(
		this.messages.pathRandom,
		null,
		this.messages.leafRandom,
		() => Expression.multipleEdition("Cryptography.Random", 1, 0)
	);
	
	// Algorithms
	
	[	
		[ "Hashing", "Hashing", "SHA-1"   ],
		[ "Hashing", "Hashing", "SHA-256" ],
		[ "Hashing", "Hashing", "SHA-384" ],
		[ "Hashing", "Hashing", "SHA-512" ],
		[ "Asymmetric encryption", "AsymmetricEncryption", "RSA-OAEP" ],
		[ "SymmetricEncryption", "SymmetricEncryption", "AES-CTR" ],
		[ "SymmetricEncryption", "SymmetricEncryption", "AES-CBC" ],
		[ "SymmetricEncryption", "SymmetricEncryption", "AES-GCM" ],
		[ "Signing", "Signing", "RSASSA-PKCS1-v1_5" ],
		[ "Signing", "Signing", "RSA-PSS"           ],
		[ "Signing", "Signing", "ECDSA"             ],
		[ "Signing", "Signing", "HMAC"              ],

	].forEach(
		row => Formulae.addEdition(
		"Cryptography.Algorithm." + row[0],
		null,
		row[2],
		() => Expression.replacingEdition("Cryptography.Algorithm." + row[1] + "." + row[2])
	));
};

