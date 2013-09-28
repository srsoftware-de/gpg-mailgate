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
require_once("include/language.php");
require_once("include/common.php");
require_once("include/dbconnect.php");
require_once("include/pgp.php");

if(isset($_POST['email']) && isset($_POST['key'])) {
	$result = requestPGP($_POST['email'], $_POST['key']);

	if($result === true) {
		get_page("home", array('message' => $lang['submit_success']));
	} else {
		get_page("home", array('message' => $result));
	}
} else {
	get_page("home");
}

?>
