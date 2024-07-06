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
		"GenerateAsymmetricKeysForSigning"
	].forEach(
		tag => Formulae.addEdition(
			this.messages.pathKey,
			null,
			this.messages["leaf" + tag],
			() => Expression.wrapperEdition("Cryptography.Key." + tag)
		)
	);
	
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
	
	[ "SHA-1", "SHA-256", "SHA-384", "SHA-512" ].forEach(tag => Formulae.addEdition(
		"Cryptography.Hashing.Algorithm",
		null,
		tag,
		() => Expression.replacingEdition("Cryptography.Hashing.Algorithm." + tag)
	));
};

