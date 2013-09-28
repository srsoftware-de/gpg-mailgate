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

//returns true on success or error message on failure
function requestPGP($email, $key) {
	require_once(includePath() . "/lock.php");
	global $config;

	if(!checkLock('requestpgp')) {
		return "please wait a bit before trying again";
	}

	if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		return "invalid email address";
	}

	if(strlen($email) > 256 || strlen($key) > 1024 * 32) {
		return "email address or key too long";
	}

	if(!isAscii($key)) {
		return "only keys encoded with ASCII armor are accepted (gpg --armor)";
	}

	//housekeeping
	databaseQuery("DELETE FROM gpgmw_keys WHERE time < DATE_SUB(NOW(), INTERVAL 48 HOUR) AND confirm != '' AND status = 0");

	//if we already have an unaccepted key for this user, only replace if one day has elapsed since the last request
	// this may prevent spam
	$result = databaseQuery("SELECT HOUR(TIMEDIFF(time, NOW())), id FROM gpgmw_keys WHERE email = ? AND status = 0", array($email));

	if($row = $result->fetch()) {
		if($row[0] < 24) {
			return "there is already a key in the queue for this email address; please wait twenty-four hours between submitting keys, or confirm the previous key and then resubmit";
		} else {
			databaseQuery('DELETE FROM gpgmw_keys WHERE id = ?', array($row[1]));
		}
	}

	//if PGP key verification is enabled, do it
	if($config['pgpverify_enable']) {
		require_once(includePath() . "/gpg.php");

		if(!verifyPGPKey($key, $email)) {
			return "your key does not appear to be valid (ensure ASCII armor is enabled and that the email address entered matches the email address of the key)";
		}
	}

	//well, it looks good, let's submit it
	lockAction('requestpgp');
	$confirm = uid(32);
	$result = gpgmw_mail($config['email_subject_requestpgp'], "Please confirm your email address to complete the submission process. You can do so by clicking the link below\n\n{$config['site_url']}/confirm.php?email=" . urlencode($email) . "&confirm=$confirm\n\nThanks,\ngpg-mailgate-web", $email);

	if(!$result) {
		return "failed to send email";
	}

	databaseQuery("INSERT INTO gpgmw_keys (email, publickey, confirm) VALUES (?, ?, ?)", array($email, $key, $confirm));
	return true;
}

//returns false on failure or true on success
function confirmPGP($email, $confirm) {
	require_once(includePath() . "/lock.php");

	if(!lockAction('confirmpgp')) {
		return "try again later";
	}

	$result = databaseQuery("SELECT id FROM gpgmw_keys WHERE confirm = ? AND email = ?", array($confirm, $email));

	if($row = $result->fetch()) {
		databaseQuery("UPDATE gpgmw_keys SET confirm = '' WHERE id = ?", array($row[0]));
		return true;
	}

	return false;
}

?>
