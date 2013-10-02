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

function dieDatabaseError($ex = NULL) {
	global $config;

	if($ex == NULL) {
		$pre = "Encountered database error.";
	} else {
		$pre = "Encountered database error: " . $ex->getMessage() . ".";
	}

	die($pre . " If this is unexpected, consider <a href=\"mailto:{$config['email_web']}\">reporting it to our web team</a>. Otherwise, <a href=\"/\">click here to return to the home page.</a>");
}

try {
	$database = new PDO('mysql:host=' . $config['db_host'] . ';dbname=' . $config['db_name'], $config['db_username'], $config['db_password'], array(PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $ex) {
	dieDatabaseError($ex);
}

function databaseQuery($command, $array = array(), $assoc = false) {
	global $database;

	if(!is_array($array)) {
		dieDatabaseError();
	}

	try {
		$query = $database->prepare($command);

		if(!$query) {
			print_r($database->errorInfo());
			dieDatabaseError();
		}

		//set fetch mode depending on parameter
		if($assoc) {
			$query->setFetchMode(PDO::FETCH_ASSOC);
		} else {
			$query->setFetchMode(PDO::FETCH_NUM);
		}

		$success = $query->execute($array);

		if(!$success) {
			print_r($query->errorInfo());
			dieDatabaseError();
		}

		return $query;
	} catch(PDOException $ex) {
		dieDatabaseError($ex);
	}
}

?>
