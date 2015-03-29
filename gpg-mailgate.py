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
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
import email
import email.message
import re
import GnuPG
import smtplib
import sys
import syslog
import traceback
import email.utils
import os
import copy

# imports for S/MIME
from M2Crypto import BIO, Rand, SMIME, X509
from email.mime.message import MIMEMessage

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

def log(msg):
	if 'logging' in cfg and 'file' in cfg['logging']:
		if cfg['logging'].get('file') == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

verbose = 'logging' in cfg and 'verbose' in cfg['logging'] and cfg['logging'].get('verbose') == 'yes'

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )
from_addr = raw_message['From']
to_addrs = sys.argv[1:]

def gpg_encrypt( raw_message, recipients ):

	if not get_bool_from_cfg('gpg', 'keyhome'):
		log("No valid entry for gpg keyhome. Encryption aborted.")
		return recipients

	keys = GnuPG.public_keys( cfg['gpg']['keyhome'] )
	for fingerprint in keys:
		keys[fingerprint] = sanitize_case_sense(keys[fingerprint])

	gpg_to = list()
	ungpg_to = list()

	for to in recipients:

		# Check if recipient is in keymap
		if get_bool_from_cfg('keymap', to):
			log("Keymap has key '%s'" % cfg['keymap'][to])
			# Check we've got a matching key!
			if cfg['keymap'][to] in keys:
				gpg_to.append( (to, cfg['keymap'][to]) )
				continue
			else:
				log("Key '%s' in keymap not found in keyring for email address '%s'." % (cfg['keymap'][to], to))

		if to in keys.values() and not get_bool_from_cfg('default', 'keymap_only', 'yes'):
			gpg_to.append( (to, to) )
		else:
			if verbose:
				log("Recipient (%s) not in PGP domain list." % to)
			ungpg_to.append(to)

	if gpg_to != list():
		log("Encrypting email to: %s" % ' '.join( map(lambda x: x[0], gpg_to) ))

		gpg_to_smtp_mime = list()
		gpg_to_cmdline_mime = list()

		gpg_to_smtp_inline = list()
		gpg_to_cmdline_inline = list()

		for rcpt in gpg_to:
			if get_bool_from_cfg('pgp_style', rcpt[0], 'mime'):
				gpg_to_smtp_mime.append(rcpt[0])
				gpg_to_cmdline_mime.extend(rcpt[1].split(','))
			elif get_bool_from_cfg('pgp_style', rcpt[0], 'inline'):
				gpg_to_smtp_inline.append(rcpt[0])
				gpg_to_cmdline_inline.extend(rcpt[1].split(','))
			else:
				# Log message only if an unknown style is defined
				if get_bool_from_cfg('pgp_style', rcpt[0]):
					log("Style %s for recipient %s is not known. Use default as fallback." % (cfg['pgp_style'][rcpt[0]], rcpt[0]))

				if get_bool_from_cfg('default', 'mime_conversion', 'yes'):
					gpg_to_smtp_mime.append(rcpt[0])
					gpg_to_cmdline_mime.extend(rcpt[1].split(','))
				else:
					gpg_to_smtp_inline.append(rcpt[0])
					gpg_to_cmdline_inline.extend(rcpt[1].split(','))

		if gpg_to_smtp_mime != list():
			raw_message_mime = copy.deepcopy(raw_message)

			if get_bool_from_cfg('default', 'add_header', 'yes'):
				raw_message_mime['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

			encrypted_payloads = encrypt_all_payloads_mime( raw_message_mime, gpg_to_cmdline_mime )
			raw_message_mime.set_payload( encrypted_payloads )

			send_msg( raw_message_mime.as_string(), gpg_to_smtp_mime )

		if gpg_to_smtp_inline != list():
			raw_message_inline = copy.deepcopy(raw_message)

			if get_bool_from_cfg('default', 'add_header', 'yes'):
				raw_message_inline['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

			encrypted_payloads = encrypt_all_payloads_inline( raw_message_inline, gpg_to_cmdline_inline )
			raw_message_inline.set_payload( encrypted_payloads )

			send_msg( raw_message_inline.as_string(), gpg_to_smtp_inline )

	return ungpg_to

def encrypt_all_payloads_inline( message, gpg_to_cmdline ):

	encrypted_payloads = list()
	if type( message.get_payload() ) == str:
		return encrypt_payload( message, gpg_to_cmdline ).get_payload()

	for payload in message.get_payload():
		if( type( payload.get_payload() ) == list ):
			encrypted_payloads.extend( encrypt_all_payloads_inline( payload, gpg_to_cmdline ) )
		else:
			encrypted_payloads.append( encrypt_payload( payload, gpg_to_cmdline ) )

	return encrypted_payloads

def encrypt_all_payloads_mime( message, gpg_to_cmdline ):

	# Convert a plain text email into PGP/MIME attachment style.  Modeled after enigmail.
	submsg1 = email.message.Message()
	submsg1.set_payload("Version: 1\n")
	submsg1.set_type("application/pgp-encrypted")
	submsg1.set_param('PGP/MIME version identification', "", 'Content-Description' )

	submsg2 = email.message.Message()
	submsg2.set_type("application/octet-stream")
	submsg2.set_param('name', "encrypted.asc")
	submsg2.set_param('OpenPGP encrypted message', "", 'Content-Description' )
	submsg2.set_param('inline', "",                'Content-Disposition' )
	submsg2.set_param('filename', "encrypted.asc", 'Content-Disposition' )

	if type ( message.get_payload() ) == str:
		# WTF!  It seems to swallow the first line.  Not sure why.  Perhaps
		# it's skipping an imaginary blank line someplace. (ie skipping a header)
		# Workaround it here by prepending a blank line.
		# This happens only on text only messages.
		submsg2.set_payload("\n" + message.get_payload())
	else:
		processed_payloads = generate_message_from_payloads(message)
		submsg2.set_payload(processed_payloads.as_string())

	message.preamble = "This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)"

	# Use this just to generate a MIME boundary string.
	junk_msg = MIMEMultipart()
	junk_str = junk_msg.as_string()  # WTF!  Without this, get_boundary() will return 'None'!
	boundary = junk_msg.get_boundary()

    # This also modifies the boundary in the body of the message, ie it gets parsed.
	if message.has_key('Content-Type'):
		message.replace_header('Content-Type', "multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary)
	else:
		message['Content-Type'] = "multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary

	return [ submsg1, encrypt_payload(submsg2, gpg_to_cmdline) ]

def encrypt_payload( payload, gpg_to_cmdline ):

	raw_payload = payload.get_payload(decode=True)
	if "-----BEGIN PGP MESSAGE-----" in raw_payload and "-----END PGP MESSAGE-----" in raw_payload:
		if verbose:
			log("Message is already pgp encrypted. No nested encryption needed.")
		return payload

	# No check is needed for cfg['gpg']['keyhome'] as this is already done in method gpg_encrypt
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset() )
	gpg.update( raw_payload )
	encrypted_data, returncode = gpg.encrypt()
	if verbose:
		log("Return code from encryption=%d (0 indicates success)." % returncode)
	if returncode != 0:
		log("Encrytion failed with return code %d. Encryption aborted." % returncode)
		return payload

	payload.set_payload( encrypted_data )
	isAttachment = payload.get_param( 'attachment', None, 'Content-Disposition' ) is not None

	if isAttachment:
		filename = payload.get_filename()
		if filename:
			pgpFilename = filename + ".pgp"
			if not (payload.get('Content-Disposition') is None):
				payload.set_param( 'filename', pgpFilename, 'Content-Disposition' )
			if not (payload.get('Content-Type') is None) and not (payload.get_param( 'name' ) is None):
				payload.set_param( 'name', pgpFilename )
	if not (payload.get('Content-Transfer-Encoding') is None):
		payload.replace_header( 'Content-Transfer-Encoding', "7bit" )

	return payload

def smime_encrypt( raw_message, recipients ):
	
	if not get_bool_from_cfg('smime', 'cert_path'):
		log("No valid path for S/MIME certs found in config file. S/MIME encryption aborted.")
		return recipients

	cert_path = cfg['smime']['cert_path']+"/"
	s = SMIME.SMIME()
	sk = X509.X509_Stack()
	smime_to = list()
	unsmime_to = list()

	for addr in recipients:
		cert_and_email = get_cert_for_email(addr, cert_path)

		if not (cert_and_email is None):
			(to_cert, normal_email) = cert_and_email
			if verbose:
				log("Found cert " + to_cert + " for " + addr + ": " + normal_email)
			smime_to.append(addr)
			x509 = X509.load_cert(to_cert, format=X509.FORMAT_PEM)
			sk.push(x509)
		else:
			unsmime_to.append(addr)

	if smime_to != list():
		s.set_x509_stack(sk)
		s.set_cipher(SMIME.Cipher('aes_192_cbc'))
		p7 = s.encrypt( BIO.MemoryBuffer( raw_message.as_string() ) )
		# Output p7 in mail-friendly format.
		out = BIO.MemoryBuffer()
		out.write('From: ' + from_addr + '\n')
		out.write('To: ' + raw_message['To'] + '\n')
		if raw_message['Cc']:
			out.write('Cc: ' + raw_message['Cc'] + '\n')
		if raw_message['Bcc']:
			out.write('Bcc: ' + raw_message['Bcc'] + '\n')
		if raw_message['Subject']:
			out.write('Subject: '+ raw_message['Subject'] + '\n')

		if get_bool_from_cfg('default', 'add_header', 'yes'):
			out.write('X-GPG-Mailgate: Encrypted by GPG Mailgate\n')

		s.write(out, p7)

		if verbose:
			log("Sending message from " + from_addr + " to " + str(smime_to))

		send_msg(out.read(), smime_to)
	if unsmime_to != list():
		if verbose:
			log("Unable to find valid S/MIME certificates for " + str(unsmime_to))

	return unsmime_to

def get_cert_for_email( to_addr, cert_path ):

	files_in_directory = os.listdir(cert_path)
	for filename in files_in_directory:
		file_path = os.path.join(cert_path, filename)
		if not os.path.isfile(file_path):
			continue

		if get_bool_from_cfg('default', 'mail_case_insensitive', 'yes'):
			if filename.lower() == to_addr:
				return (file_path, to_addr)
		else:
			if filename == to_addr:
				return (file_path, to_addr)
	# support foo+ignore@bar.com -> foo@bar.com
	multi_email = re.match('^([^\+]+)\+([^@]+)@(.*)$', to_addr)
	if multi_email:
		fixed_up_email = "%s@%s" % (multi_email.group(1), multi_email.group(3))
		if verbose:
			log("Multi-email %s converted to %s" % (to_addr, fixed_up_email))
		return get_cert_for_email(fixed_up_email)

	return None

def get_bool_from_cfg( section, key = None, evaluation = None ):

	if not (key is None) and not (evaluation is None):
		return section in cfg and cfg[section].get(key) == evaluation

	elif not (key is None) and (evaluation is None):
		return section in cfg and not (cfg[section].get(key) is None)

	else:
		return section in cfg

def sanitize_case_sense( address ):

	if get_bool_from_cfg('default', 'mail_case_insensitive', 'yes'):
		address = address.lower()
	else:
		splitted_address = address.split('@')
		address = splitted_address[0] + '@' + splitted_address[1].lower()

	return address

def generate_message_from_payloads( payloads, submsg = None ):

	if submsg == None:
		submsg = email.mime.multipart.MIMEMultipart(payloads.get_content_subtype())

	for payload in payloads.get_payload():
		if( type( payload.get_payload() ) == list ):
			submsg.attach(attach_payload_list_to_message(payload, email.mime.multipart.MIMEMultipart(payload.get_content_subtype())))
		else:
			submsg.attach(payload)

	return submsg

def get_first_payload( payloads ):

	if payloads.is_multipart():
		return get_first_payload(payloads.get_payload(0))
	else:
		return payloads

def send_msg( message, recipients ):

	recipients = filter(None, recipients)
	if recipients:
		if not (get_bool_from_cfg('relay', 'host') and get_bool_from_cfg('relay', 'port')):
			log("Missing settings for relay. Sending email aborted.")
			return None
		log("Sending email to: <%s>" % '> <'.join( recipients ))
		relay = (cfg['relay']['host'], int(cfg['relay']['port']))
		smtp = smtplib.SMTP(relay[0], relay[1])
		smtp.sendmail( from_addr, recipients, message )
	else:
		log("No recipient found")

def sort_recipients( raw_message, from_addr, to_addrs ):

	recipients_left = list()
	for recipient in to_addrs:
		recipients_left.append(sanitize_case_sense(recipient))

	# There is no need for nested encryption
	first_payload = get_first_payload(raw_message)
	if first_payload.get_content_type() == 'application/pkcs7-mime':
		if verbose:
			log("Message is already encrypted with S/MIME. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	first_payload = first_payload.get_payload(decode=True)
	if "-----BEGIN PGP MESSAGE-----" in first_payload and "-----END PGP MESSAGE-----" in first_payload:
		if verbose:
			log("Message is already encrypted as PGP/INLINE. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	if raw_message.get_content_type() == 'multipart/encrypted':
		if verbose:
			log("Message is already encrypted. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	# Encrypt mails for recipients with known PGP keys
	recipients_left = gpg_encrypt(raw_message, recipients_left)
	if recipients_left == list():
		return

	# Encrypt mails for recipients with known S/MIME certificate
	recipients_left = smime_encrypt(raw_message, recipients_left)
	if recipients_left == list():
		return

	# Send out mail to recipients which are left
	send_msg(raw_message.as_string(), recipients_left)


# Let's start
sort_recipients(raw_message, from_addr, to_addrs)
