#!/usr/bin/python

#
#	gpg-mailgate
#
#	This file is part of the gpg-mailgate source code.
#
#	gpg-mailgate is free software: you can redistribute it and/or modify
#	it under the terms of the GNU Lesser General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	gpg-mailgate source code is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU Lesser General Public License for more details.
#
#	You should have received a copy of the GNU Lesser General Public License
#	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.
#

from ConfigParser import RawConfigParser
import GnuPG
import MySQLdb

def appendLog(msg):
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		log = open(cfg['logging']['file'], 'a')
		log.write(msg + "\n")
		log.close()

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

if cfg.has_key('database') and cfg['database'].has_key('enabled') and cfg['database']['enabled'] == 'yes' and cfg['database'].has_key('name') and cfg['database'].has_key('host') and cfg['database'].has_key('username') and cfg['database'].has_key('password'):
	connection = MySQLdb.connect(host = cfg['database']['host'], user = cfg['database']['username'], passwd = cfg['database']['password'], db = cfg['database']['name'], port = 3306)
	cursor = connection.cursor()

	# import keys
	cursor.execute("SELECT publickey, id, email FROM gpgmw_keys WHERE status = 0 AND confirm = '' LIMIT 100")
	result_set = cursor.fetchall()

	for row in result_set:
		# delete any other public keys associated with this confirmed email address
		cursor.execute("DELETE FROM gpgmw_keys WHERE email = %s AND id != %s", (row[2], row[1],))
		GnuPG.delete_key(cfg['gpg']['keyhome'], row[2])
		appendLog('Deleted key for <' + row[2] + '> via import request')

		if row[0].strip(): # we have this so that user can submit blank key to remove any encryption
			if GnuPG.confirm_key(row[0], row[2]):
				GnuPG.add_key(cfg['gpg']['keyhome'], row[0]) # import the key to gpg
				cursor.execute("UPDATE gpgmw_keys SET status = 1 WHERE id = %s", (row[1],)) # mark key as accepted
				appendLog('Imported key from <' + row[2] + '>')
			else:
				cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],)) # delete key
				appendLog('Import confirmation failed for <' + row[2] + '>')
		else:
			# delete key so we don't continue processing it
			cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],))

		connection.commit()

	# delete keys
	cursor.execute("SELECT email, id FROM gpgmw_keys WHERE status = 2 LIMIT 100")
	result_set = cursor.fetchall()

	for row in result_set:
		GnuPG.delete_key(cfg['gpg']['keyhome'], row[0])
		cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],))
		appendLog('Deleted key for <' + row[0] + '>')
		connection.commit()
else:
	print "Warning: doing nothing since database settings are not configured!"
