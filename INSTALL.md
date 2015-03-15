 1. Ensure that GPG is installed and configured. Also make sure public keys for
    all of your potential recipients are available in the GPG home directory
    used for `keyhome` in step 2.

 2. Configure `/etc/gpg-mailgate.conf` based on the provided
    `gpg-mailgate.conf.sample`

 3. Install some python dependencies `apt-get install python-m2crypto python-markdown python-requests python-mysqldb` (for linux distributions based on Debian. If you have a non Debian based distribution, the install command might be different)

 4. Place `gpg-mailgate.py` and `register-handler.py` in `/usr/local/bin/`

 5. Make sure that `gpg-mailgate.py` and `register-handler.py` are executable

        chmod u+x /usr/local/bin/gpg-mailgate.py
        chmod u+x /usr/local/bin/register-handler.py
        chown nobody:nogroup /usr/local/bin/gpg-mailgate.py
        chown nobody:nogroup /usr/local/bin/register-handler.py
 
 6. Place the GnuPG directory in `/usr/local/lib/python2.7/dist-packages` (replace 2.7 with your
    Python version)
 
 7. Add the following to the end of `/etc/postfix/master.cf`

        gpg-mailgate    unix    -   n   n   -   -   pipe
            flags= user=nobody argv=/usr/local/bin/gpg-mailgate.py ${recipient}

        127.0.0.1:10028 inet    n   -   n   -   10  smtpd
            -o content_filter=
            -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
            -o smtpd_helo_restrictions=
            -o smtpd_client_restrictions=
            -o smtpd_sender_restrictions=
            -o smtpd_recipient_restrictions=permit_mynetworks,reject
            -o mynetworks=127.0.0.0/8
            -o smtpd_authorized_xforward_hosts=127.0.0.0/8

 8. Add the following to `/etc/postfix/main.cf`

        content_filter = gpg-mailgate
        
 9. Add `register:	|/usr/local/bin/register-handler.py` to `/etc/aliases`
 
 10. Update postfix's alias database with `postalias /etc/aliases`

 11. Restart postfix.

 12. Setup a place to store public keys and certificates with these example commands:

        usermod -d /var/gpg nobody

    - If you encounter any errors when using this command you might need to kill active processes from nobody

        mkdir -p /var/gpg/.gnupg
        mkdir -p /var/smime/certs
        chown -R nobody /var/gpg
        chown -R nobody /var/smime
        chmod 700 /var/gpg/.gnupg
        sudo -u nobody /usr/bin/gpg --homedir=/var/gpg/.gnupg --import /some/public.key

    - Replace `/some/public.key` with the location of a public key
    - `/some/public.key` can be deleted after importation
    - Confirm that it's working: `sudo -u nobody /usr/bin/gpg --list-keys --homedir=/var/gpg/.gnupg`

 13. Create directories for storing email templates:

        mkdir -p /var/gpgmailgate/register_templates
		mkdir -p /var/gpgmailgate/cron_templates
		chown -R nobody /var/gpgmailgate

    - Place the corresponding directories from this project in the created ones 
    - Edit them if you want to

 14. [Install gpg-mailgate-web] (gpg-mailgate-web/README)
 