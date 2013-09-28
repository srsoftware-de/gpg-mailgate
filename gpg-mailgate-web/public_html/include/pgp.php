<?php
/*

	gpg-mailgate

	This file is part of the gpg-mailgate source code.

	gpg-mailgate is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	gpg-mailgate source code is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.

*/

//returns true on success or error message on failure
function requestPGP($email, $key) {
	require_once(includePath() . "/lock.php");
	global $config, $lang;

	if(!checkLock('requestpgp')) {
		return $lang['submit_error_trylater'];
	}

	if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		return $lang['submit_error_bademail'];
	}

	if(strlen($email) > 256 || strlen($key) > 1024 * 32) {
		return $lang['submit_error_toolong'];
	}

	if(!isAscii($key)) {
		return $lang['submit_error_nonascii'];
	}

	//housekeeping
	databaseQuery("DELETE FROM gpgmw_keys WHERE time < DATE_SUB(NOW(), INTERVAL 48 HOUR) AND confirm != '' AND status = 0");

	//if we already have an unaccepted key for this user, only replace if one day has elapsed since the last request
	// this may prevent spam
	$result = databaseQuery("SELECT HOUR(TIMEDIFF(time, NOW())), id FROM gpgmw_keys WHERE email = ? AND status = 0", array($email));

	if($row = $result->fetch()) {
		if($row[0] < 24) {
			return $lang['submit_error_alreadyqueue'];
		} else {
			databaseQuery('DELETE FROM gpgmw_keys WHERE id = ?', array($row[1]));
		}
	}

	//if PGP key verification is enabled, do it
	if($config['pgpverify_enable']) {
		require_once(includePath() . "/gpg.php");

		if(!verifyPGPKey($key, $email)) {
			return $lang['submit_error_badkey'];
		}
	}

	//well, it looks good, let's submit it
	lockAction('requestpgp');
	$confirm = uid(32);
	$confirm_link = "{$config['site_url']}/confirm.php?email=" . urlencode($email) . "&confirm=$confirm";
	$result = gpgmw_mail($config['email_subject_requestpgp'], sprintf($lang['mail_confirm'], $confirm_link), $email);

	if(!$result) {
		return $lang['submit_error_emailfail'];
	}

	databaseQuery("INSERT INTO gpgmw_keys (email, publickey, confirm) VALUES (?, ?, ?)", array($email, $key, $confirm));
	return true;
}

//returns false on failure or true on success
function confirmPGP($email, $confirm) {
	require_once(includePath() . "/lock.php");

	if(!lockAction('confirmpgp')) {
		return false;
	}

	$result = databaseQuery("SELECT id FROM gpgmw_keys WHERE confirm = ? AND email = ?", array($confirm, $email));

	if($row = $result->fetch()) {
		databaseQuery("UPDATE gpgmw_keys SET confirm = '' WHERE id = ?", array($row[0]));
		return true;
	}

	return false;
}

?>
