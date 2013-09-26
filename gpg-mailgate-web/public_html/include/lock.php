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

//lock.php is basic spam-submit prevention
//lock_time_initial, lock_time_overload, lock_count_overload, lock_time_reset, and lock_time_max should be defined in $config

//returns boolean: true=proceed, false=lock up; the difference between this and lockAction is that this can be used for repeated tasks, like admin
// then, only if action was unsuccessful would lockAction be called
function checkLock($action) {
	global $config;
	$lock_time_initial = $config['lock_time_initial'];
	$lock_time_overload = $config['lock_time_overload'];
	$lock_count_overload = $config['lock_count_overload'];
	$lock_time_reset = $config['lock_time_reset'];
	$lock_time_max = $config['lock_time_max'];

	if(!isset($lock_time_initial[$action])) {
		return true; //well we can't do anything...
	}

	$ip = $_SERVER['REMOTE_ADDR'];

	$result = databaseQuery("SELECT id, time, num FROM gpgmw_locks WHERE ip = ? AND action = ?", array($ip, $action), true);
	if($row = $result->fetch()) {
		$id = $row['id'];
		$time = $row['time'];
		$count = $row['num']; //>=0 count means it's a regular initial lock; -1 count means overload lock

		if($count >= 0) {
			if(time() <= $time + $lock_time_initial[$action]) {
				return false;
			}
		} else {
			if(time() <= $time + $lock_time_overload[$action]) {
				return false;
			}
		}
	}

	return true;
}

//returns boolean: true=proceed, false=lock up
function lockAction($action) {
	global $config;
	$lock_time_initial = $config['lock_time_initial'];
	$lock_time_overload = $config['lock_time_overload'];
	$lock_count_overload = $config['lock_count_overload'];
	$lock_time_reset = $config['lock_time_reset'];
	$lock_time_max = $config['lock_time_max'];

	if(!isset($lock_time_initial[$action])) {
		return true; //well we can't do anything...
	}

	$ip = $_SERVER['REMOTE_ADDR'];
	$replace_id = -1;

	//first find records with ip/action
	$result = databaseQuery("SELECT id, time, num FROM gpgmw_locks WHERE ip = ? AND action = ?", array($ip, $action), true);
	if($row = $result->fetch()) {
		$id = $row['id'];
		$time = $row['time'];
		$count = $row['num']; //>=0 count means it's a regular initial lock; -1 count means overload lock

		if($count >= 0) {
			if(time() <= $time + $lock_time_initial[$action]) {
				return false;
			} else if(time() > $time + $lock_time_reset) {
				//this entry is old, but use it to replace
				$replace_id = $id;
			} else {
				//increase the count; maybe initiate an OVERLOAD
				$count = $count + 1;
				if($count >= $lock_count_overload[$action]) {
					databaseQuery("UPDATE gpgmw_locks SET num = '-1', time = ? WHERE ip = ?", array(time(), $ip));
					return false;
				} else {
					databaseQuery("UPDATE gpgmw_locks SET num = ?, time = ? WHERE ip = ?", array($count, time(), $ip));
				}
			}
		} else {
			if(time() <= $time + $lock_time_overload[$action]) {
				return false;
			} else {
				//their overload is over, so this entry is old
				$replace_id = $id;
			}
		}
	} else {
		databaseQuery("INSERT INTO gpgmw_locks (ip, time, action, num) VALUES (?, ?, ?, '1')", array($ip, time(), $action));
	}

	if($replace_id != -1) {
		databaseQuery("UPDATE gpgmw_locks SET num = '1', time = ? WHERE id = ?", array(time(), $replace_id));
	}

	//some housekeeping
	$delete_time = time() - $lock_time_max;
	databaseQuery("DELETE FROM gpgmw_locks WHERE time <= ?", array($delete_time));

	return true;
}

?>
