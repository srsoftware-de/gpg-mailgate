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
?>

<h1><?= $config['site_title'] ?></h1>

<? if(!empty($message)) { ?>
<p><b><i><?= htmlspecialchars($message) ?></i></b></p>
<? } ?>

<p>Use the form below to submit an ASCII-armored PGP public key. After submission, you will receive an email asking you to confirm your email address. Once confirmation is completed, mail sent to your email address via our mail server will be encrypted with your PGP public key.</p>

<form method="POST">
<table>
<tr>
	<td>Your email address (must match key)</td>
	<td><input type="text" name="email" /></td>
</tr>
<tr>
	<td>ASCII-armored PGP public key</td>
	<td><textarea name="key" rows="10" cols="80"></textarea></td>
</tr>
</table>
<input type="submit" value="Submit key" />
</form>

<p><a href="https://github.com/uakfdotb/gpg-mailgate">gpg-mailgate and gpg-mailgate-web</a> are released under the <a href="https://www.gnu.org/licenses/lgpl-3.0.txt">GNU LGPL</a>.</p>
