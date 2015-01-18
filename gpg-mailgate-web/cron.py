#!/usr/bin/python

#
#	gpg-mailgate
#
#	This file is part of the gpg-mailgate source code.
#
#	gpg-mailgate is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	gpg-mailgate source code is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.
#

from ConfigParser import RawConfigParser
import GnuPG
import MySQLdb
import smtplib
from email.MIMEText import MIMEText

def appendLog(msg):
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		log = open(cfg['logging']['file'], 'a')
		log.write(msg + "\n")
		log.close()

def send_msg( mailsubject, mailbody, recipients = None ):
	msg = MIMEText(mailbody)
	msg["From"] = cfg['smime']['register_email']
	msg["To"] = recipients
	msg["Subject"] = mailsubject
	
	relay = ("127.0.0.1", 10028)
	smtp = smtplib.SMTP(relay[0], relay[1])
	smtp.sendmail( cfg['smime']['register_email'], recipients, msg.as_string() )

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
				send_msg( "PGP key registration successful", "Your PGP key has been imported successfully. Don't be worried if this mail is not encrypted. The following mails will be encrypted.", row[2] )
			else:
				cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],)) # delete key
				appendLog('Import confirmation failed for <' + row[2] + '>')
				send_msg( "PGP key registration failed", "Your PGP key could not be validated. Please try again with a valid key.", row[2] )
		else:
			# delete key so we don't continue processing it
			cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],))
			send_msg( "PGP key deleted", "Your PGP key has been deleted from our gateway. From now on you will receive mails from us unencrypted.", row[2])

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
