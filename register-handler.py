#!/usr/bin/python

from ConfigParser import RawConfigParser
import email, os, smtplib, sys, traceback, markdown, syslog, requests
from M2Crypto import BIO, Rand, SMIME, X509

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

CERT_PATH = cfg['smime']['cert_path']+"/"

def send_msg( message, from_addr, recipients = None ):
    relay = ("127.0.0.1", 10028)
    smtp = smtplib.SMTP(relay[0], relay[1])
    smtp.sendmail( from_addr, recipients, message.as_string() )

if __name__ == "__main__":
#	try:
		# Read e-mail from stdin
		raw = sys.stdin.read()
		register_msg = email.message_from_string( raw )
		from_addr = email.utils.parseaddr(register_msg['From'])[1]

		sign_part = None
		for msg_part in register_msg.walk():
			if msg_part.get_content_type().lower() == "application/pkcs7-signature" or msg_part.get_content_type().lower() == "application/x-pkcs7-signature":
				sign_type = 'smime';
				sign_part = msg_part
				break
			elif msg_part.get_content_type().lower() == "application/pgp-keys":
				sign_type = 'pgp';
				sign_part = msg_part
				break

		if sign_part == None:
			log("Unable to find PKCS7 signature or public PGP key in registration email")

			failure_msg = file( cfg['smime']['mail_templates'] + "/registrationError.md").read()
			msg = MIMEMultipart("alternative")
			msg["From"] = cfg['smime']['register_email']
			msg["To"] = from_addr
			msg["Subject"] = "S/MIME / OpenPGP registration failed"

			msg.attach(MIMEText(failure_msg, 'plain'))
			msg.attach(MIMEText(markdown.markdown(failure_msg), 'html'))

			send_msg(msg, cfg['smime']['register_email'], [from_addr])
			sys.exit(0)
		
		if sign_type == 'smime':
			raw_sig = sign_part.get_payload().replace("\n","")
			# re-wrap signature so that it fits base64 standards
			cooked_sig = '\n'.join(raw_sig[pos:pos+76] for pos in xrange(0, len(raw_sig), 76))
			
			# now, wrap the signature in a PKCS7 block
			sig = """
-----BEGIN PKCS7-----
%s
-----END PKCS7-----
		""" % cooked_sig

			# and load it into an SMIME p7 object through the BIO I/O buffer:
			buf = BIO.MemoryBuffer(sig)
			p7 = SMIME.load_pkcs7_bio(buf)

			sk = X509.X509_Stack()
			signers = p7.get0_signers(sk)
			signing_cert = signers[0]

			signing_cert.save(os.path.join(CERT_PATH, from_addr))
			
		elif sign_type == 'pgp':
			 # send POST to localost on port 11371 which points to our HTTP registration page
			sig = sign_part.get_payload()
			payload = {'email': from_addr, 'key': sig}
			r = requests.post("http://127.0.0.1:11371", data=payload)

		# format in user-specific data
		success_msg = file(cfg['smime']['mail_templates']+"/registrationSuccess.md").read()
		success_msg = success_msg.replace("[:FROMADDRESS:]",from_addr)

		msg = MIMEMultipart("alternative")
		msg["From"] = cfg['smime']['register_email']
		msg["To"] = from_addr
		msg["Subject"] = "S/MIME / OpenPGP key registration succeeded"

		msg.attach(MIMEText(success_msg, 'plain'))
		msg.attach(MIMEText(markdown.markdown(success_msg), 'html'))

		log("Registration succeeded")
		send_msg(msg, cfg['smime']['register_email'], [from_addr])
#	except:
#		log("Registration exception")
#		sys.exit(0)
