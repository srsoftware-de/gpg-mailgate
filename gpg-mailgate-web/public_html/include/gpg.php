<?php
/*

	gpg-mailgate

	This file is part of the gpg-mailgate source code.

	gpg-mailgate is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	gpg-mailgate source code is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.

*/

//uses gpg to verify that a key belongs to a given email address
function verifyPGPKey($content, $email) {
	global $config;

	//allow blank "keys" if this is set
	//this means that encryption for $email will be disabled by the cron if it
	// was enabled originally
	if($config['pgpverify_allowblank'] && trim($content) == '') {
		return true;
	}

	require_once("Crypt/GPG.php");

	//try to create a random subdirectory of $config['pgpverify_tmpdir']
	do {
		$path = $config['pgpverify_tmpdir'] . '/' . uid(16);
	} while(file_exists($path));

	$result = @mkdir($path);

	if($result === false) {
		if($config['debug']) {
			die("Failed to create directory [" . $path . "] for PGP verification.");
		} else {
			return false;
		}
	}

	$gpg = new Crypt_GPG(array('homedir' => $path));

	//import the key to our GPG temp directory
	try {
		$gpg->importKey($content);
	} catch(Crypt_GPG_NoDataException $e) {
		//user supplied an invalid key!
		recursiveDelete($path);
		return false;
	}

	//verify the email address matches
	$keys = $gpg->getKeys();

	if(count($keys) != 1) {
		if($config['debug']) {
			die("Error in PGP verification: key count is " . count($keys) . "!");
		} else {
			recursiveDelete($path);
			return false;
		}
	}

	$userIds = $keys[0]->getUserIds();

	if(count($userIds) != 1 || strtolower($userIds[0]->getEmail()) != strtolower($email)) {
		recursiveDelete($path);
		return false;
	}

	recursiveDelete($path);
	return true;
}

?>
