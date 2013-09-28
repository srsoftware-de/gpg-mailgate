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

require_once("include/config.php");
require_once("include/common.php");
require_once("include/dbconnect.php");
require_once("include/pgp.php");

if(isset($_REQUEST['email']) && isset($_REQUEST['confirm'])) {
	$result = confirmPGP($_REQUEST['email'], $_REQUEST['confirm']);

	if($result === true) {
		get_page("home", array('message' => 'Your email address has been confirmed successfully. Within a few minutes, emails from our mail server to you should be encrypted with your PGP public key.'));
	} else {
		get_page("home", array('message' => 'Error: failed to confirm any email address. You may have already confirmed the address, or you may have the wrong confirmation key.'));
	}
} else {
	get_page("home");
}

?>
