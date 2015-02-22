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
	if cfg.has_key('logging') and cfg['logging'].has_key('file'):
		if cfg['logging']['file'] == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

verbose = cfg.has_key('logging') and cfg['logging'].has_key('verbose') and cfg['logging']['verbose'] == 'yes'

CERT_PATH = cfg['smime']['cert_path']+"/"

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )
from_addr = raw_message['From']
to_addrs = sys.argv[1:]

def send_msg( message, recipients = None ):
	if recipients == None:
		recipients = to_addrs
	recipients = filter(None, recipients)
	if recipients:
		log("Sending email to: <%s>" % '> <'.join( recipients ))
		relay = (cfg['relay']['host'], int(cfg['relay']['port']))
		smtp = smtplib.SMTP(relay[0], relay[1])
		smtp.sendmail( from_addr, recipients, message )
	else:
		log("No recipient found");

def encrypt_payload( payload, gpg_to_cmdline ):
	raw_payload = payload.get_payload(decode=True)
	if "-----BEGIN PGP MESSAGE-----" in raw_payload and "-----END PGP MESSAGE-----" in raw_payload:
		return payload
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset() )
	gpg.update( raw_payload )
	encrypted_data, returncode = gpg.encrypt()
	if verbose:
		log("Return code from encryption=%d (0 indicates success)." % returncode)
	payload.set_payload( encrypted_data )
	isAttachment = payload.get_param( 'attachment', None, 'Content-Disposition' ) is not None
	if isAttachment:
		filename = payload.get_filename()
		if filename:
			pgpFilename = filename + ".pgp"
			if payload.get('Content-Disposition') is not None:
				payload.set_param( 'filename', pgpFilename, 'Content-Disposition' )
			if payload.get('Content-Type') is not None:
				if payload.get_param( 'name' ) is not None:
					payload.set_param( 'name', pgpFilename )
	if payload.get('Content-Transfer-Encoding') is not None:
		payload.replace_header( 'Content-Transfer-Encoding', "7bit" )
	return payload

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

def generate_attachment_pgp(message, submsg = None):
	if submsg == None:
		submsg = email.message.Message()
		submsg.set_type("multipart/mixed")
		submsg.set_param('inline', "", 'Content-Disposition' )

	for payload in message.get_payload():
		if( type( payload.get_payload() ) == list ):
			submsg.attach(generate_attachment_pgp(payload, submsg))
		else:
			submsg.attach(payload)
	return submsg

def encrypt_all_payloads_attachment_style( message, gpg_to_cmdline ):
	encrypted_payloads = list()
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
		submsg2.set_payload(generate_attachment_pgp(message).as_string())

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

# This method is not referenced
def get_msg( message ):
	if not message.is_multipart():
		return message.get_payload()
	return '\n\n'.join( [str(m) for m in message.get_payload()] )
	
def get_cert_for_email(to_addr):
	files_in_directory = os.listdir(CERT_PATH)
	for filename in files_in_directory:
		file_path = os.path.join(CERT_PATH, filename)
		if not os.path.isfile(file_path): continue
		if cfg['default'].has_key('mail_case_sensitive') and cfg['default']['mail_case_sensitive'] == 'yes':
			if filename == to_addr: return (file_path, to_addr)
		else:
			if filename.lower() == to_addr: return (file_path, to_addr)
	# support foo+ignore@bar.com -> foo@bar.com
	multi_email = re.match('^([^\+]+)\+([^@]+)@(.*)$', to_addr)
	if multi_email:
		fixed_up_email = "%s@%s" % (multi_email.group(1), multi_email.group(3))
		log("Multi-email %s converted to %s" % (to_addr, fixed_up_email))
		return get_cert_for_email(fixed_up_email)
	return None
	
def to_smime_handler( raw_message, recipients = None ):
	if recipients == None:
		recipients = to_addrs
	s = SMIME.SMIME()
	sk = X509.X509_Stack()
	normalized_recipient = []
	unsmime_to = list(recipients)
	for addr in recipients:
		addr_addr = email.utils.parseaddr(addr)[1]
		
		if cfg['default'].has_key('mail_case_sensitive') and cfg['default']['mail_case_sensitive'] == 'yes':
			splitted_addr_addr = addr_addr.split('@')
			addr_addr = splitted_addr_addr[0] + '@' + splitted_addr_addr[1].lower()
		else:
			addr_addr = addr_addr.lower()
		
		cert_and_email = get_cert_for_email(addr_addr)
		if cert_and_email:
			(to_cert, normal_email) = cert_and_email
			unsmime_to.remove(addr)
			log("Found cert " + to_cert + " for " + addr + ": " + normal_email)
			normalized_recipient.append((email.utils.parseaddr(addr)[0], normal_email))
			x509 = X509.load_cert(to_cert, format=X509.FORMAT_PEM)
			sk.push(x509)
	if len(normalized_recipient):
		smime_to = [email.utils.formataddr(x) for x in normalized_recipient]
		s.set_x509_stack(sk)
		s.set_cipher(SMIME.Cipher('aes_192_cbc'))
		p7 = s.encrypt( BIO.MemoryBuffer(raw_message.as_string()) )
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
		if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
			out.write('X-GPG-Mailgate: Encrypted by GPG Mailgate\n')
		s.write(out, p7)
		log("Sending message from " + from_addr + " to " + str(smime_to))
		raw_msg = out.read()
		send_msg(raw_msg, smime_to)
	if len(unsmime_to):
		log("Unable to find valid S/MIME certificates for " + str(unsmime_to))
		send_msg(raw_message.as_string(), unsmime_to)
	return None


keys = GnuPG.public_keys( cfg['gpg']['keyhome'] )
if cfg['default'].has_key('mail_case_sensitive') and cfg['default']['mail_case_sensitive'] == 'yes':
	for fingerprint in keys:
		splitted_address = keys[fingerprint].split('@')
		keys[fingerprint] = splitted_address[0] + '@' + splitted_address[1].lower()
else:
	for fingerprint in keys:	
		keys[fingerprint] = keys[fingerprint].lower()

gpg_to = list()
ungpg_to = list()

for to in to_addrs:
	if cfg['default'].has_key('mail_case_sensitive') and cfg['default']['mail_case_sensitive'] == 'yes':
		splitted_to = to.split('@')
		to = splitted_to[0] + '@' + splitted_to[1].lower()
	else:	
		to = to.lower()

	if to in keys.values() and not ( cfg['default'].has_key('keymap_only') and cfg['default']['keymap_only'] == 'yes'  ):
		gpg_to.append( (to, to) )
	elif cfg.has_key('keymap') and cfg['keymap'].has_key(to):
		log("Keymap has key '%s'" % cfg['keymap'][to] )
		# Check we've got a matching key!  If not, decline to attempt encryption.
		if not keys.has_key(cfg['keymap'][to]):
			log("Key '%s' in keymap not found in keyring for email address '%s'.  Won't encrypt." % (cfg['keymap'][to], to))
			ungpg_to.append(to)
		else:
			gpg_to.append( (to, cfg['keymap'][to]) )
	else:
		if verbose:
			log("Recipient (%s) not in PGP domain list." % to)
		ungpg_to.append(to)

if gpg_to == list():
	if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
		raw_message['X-GPG-Mailgate'] = 'Not encrypted, public key not found'
	if verbose:
		log("No PGP encrypted recipients.")
	to_smime_handler( raw_message )
	exit()

if ungpg_to != list():
	to_smime_handler( raw_message, ungpg_to )

log("Encrypting email to: %s" % ' '.join( map(lambda x: x[0], gpg_to) ))

if cfg['default'].has_key('add_header') and cfg['default']['add_header'] == 'yes':
	raw_message['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

gpg_to_smtp_mime = list()
gpg_to_cmdline_mime = list()

gpg_to_smtp_inline = list()
gpg_to_cmdline_inline = list()
for rcpt in gpg_to:
	if cfg.has_key('pgp_style') and cfg['pgp_style'].has_key(rcpt[0]):
		if cfg['pgp_style'][rcpt[0]] == 'mime':
			gpg_to_smtp_mime.append(rcpt[0])
			gpg_to_cmdline_mime.extend(rcpt[1].split(','))
		elif cfg['pgp_style'][rcpt[0]] == 'inline':
			gpg_to_smtp_inline.append(rcpt[0])
			gpg_to_cmdline_inline.extend(rcpt[1].split(','))
		else:
			log("Style %s for recipient %s is not known. Use default as fallback." % (cfg['pgp_style'][rcpt[0]], rcpt[0]))
			if cfg['default'].has_key('mime_conversion') and cfg['default']['mime_conversion'] == 'yes':
				gpg_to_smtp_mime.append(rcpt[0])
				gpg_to_cmdline_mime.extend(rcpt[1].split(','))
			else:
				gpg_to_smtp_inline.append(rcpt[0])
				gpg_to_cmdline_inline.extend(rcpt[1].split(','))
	elif cfg['default'].has_key('mime_conversion') and cfg['default']['mime_conversion'] == 'yes':
		gpg_to_smtp_mime.append(rcpt[0])
		gpg_to_cmdline_mime.extend(rcpt[1].split(','))
	else:
		gpg_to_smtp_inline.append(rcpt[0])
		gpg_to_cmdline_inline.extend(rcpt[1].split(','))

if gpg_to_smtp_mime != list():

	raw_message_mime = copy.deepcopy(raw_message)
	encrypted_payloads = encrypt_all_payloads_attachment_style( raw_message_mime, gpg_to_cmdline_mime )
	raw_message_mime.set_payload( encrypted_payloads )

	send_msg( raw_message_mime.as_string(), gpg_to_smtp_mime )
if gpg_to_smtp_inline != list():

	encrypted_payloads = encrypt_all_payloads_inline( raw_message, gpg_to_cmdline_inline )
	raw_message.set_payload( encrypted_payloads )

	send_msg( raw_message.as_string(), gpg_to_smtp_inline )