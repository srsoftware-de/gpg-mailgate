<?php
/*

	gpg-mailgate

	This file is part of the gpg-mailgate source code.

	gpg-mailgate is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	gpg-mailgate source code is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.

*/

$lang = array();

$lang['home_text'] = 'Use the form below to submit an ASCII-armored PGP public key. After submission, you will receive an email asking you to confirm your email address. Once confirmation is completed, mail sent to your email address via our mail server will be encrypted with your PGP public key.';
$lang['home_footer'] = '<a href="https://github.com/uakfdotb/gpg-mailgate">gpg-mailgate and gpg-mailgate-web</a> are released under the <a href="https://www.gnu.org/licenses/lgpl-3.0.txt">GNU LGPL</a>.';
$lang['home_emaildesc'] = 'Your email address (must match key)';
$lang['home_keydesc'] = 'ASCII-armored PGP public key';
$lang['home_submitkey'] = 'Submit key';

$lang['submit_success'] = 'Key submission successful. Please check your email to confirm your email address.';
$lang['submit_error_trylater'] = 'Error: please wait a bit before trying again.';
$lang['submit_error_bademail'] = 'Error: invalid email address.';
$lang['submit_error_toolong'] = 'Error: email address or key too long.';
$lang['submit_error_nonascii'] = 'Error: only keys encoded with ASCII armor are accepted (gpg --armor).';
$lang['submit_error_alreadyqueue'] = 'Error: there is already a key in the queue for this email address; please wait twenty-four hours between submitting keys, or confirm the previous key and then resubmit.';
$lang['submit_error_badkey'] = 'Error: your key does not appear to be valid (ensure ASCII armor is enabled and that the email address entered matches the email address of the key).';
$lang['submit_error_emailfail'] = 'Error: failed to send email.';
$lang['submit_error_bademail'] = 'Error: invalid email address.';
$lang['submit_error_bademail'] = 'Error: invalid email address.';

$lang['confirm_success'] = 'Your email address has been confirmed successfully. Within a few minutes, emails from our mail server to you should be encrypted with your PGP public key.';
$lang['confirm_fail_general'] = 'Error: failed to confirm any email address. You may have already confirmed the address, or you may have the wrong confirmation key.';

$lang['mail_confirm'] = "Please confirm your email address to complete the submission process. You can do so by clicking the link below\n\n%s\n\nThanks,\ngpg-mailgate-web";

?>
