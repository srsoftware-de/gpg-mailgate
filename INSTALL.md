 1. Ensure that GPG is installed and configured. Also make sure public keys for
    all of your potential recipients are available in the GPG home directory
    used for `keyhome` in step 2.

 2. Configure `/etc/gpg-mailgate.conf` based on the provided
    `gpg-mailgate.conf.sample`

 3. install some python dependencies `apt-get install python-m2crypto python-markdown`

 4. Place `gpg-mailgate.py` and `register-handler.py` in `/usr/local/bin/`
 
 5. Place the GnuPG directory in `/usr/local/lib/python2.7/dist-packages` (replace 2.7 with your
    Python version)
 
 6. Add the following to the end of `/etc/postfix/master.cf`

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

 7. Add the following to `/etc/postfix/main.cf`

        content_filter = gpg-mailgate
        
 8. Add `register:	|/usr/local/bin/register_handler.py` to `/etc/aliases`

 9. Place `passthrough_emails.cf` in `/etc/postfix` and change the domain of the email address in the file

 10. Restart postfix.

 11. create a dedicated user to store the public keys with these example commands:

        usermod -d /var/gpg nobody
        mkdir -p /var/gpg/.gnupg
        mkdir -p /var/smime/certs
        mkdir -p /var/smime/templates
        chown -R nobody /var/gpg
        chown -R nobody /var/smime
        chmod 700 /var/gpg/.gnupg
        sudo -u nobody /usr/bin/gpg --import /some/public.key --homedir=/var/gpg/.gnupg

    - Replace `/some/public.key` with the location of a public key
    - `/some/public.key` can be deleted after importation
    - Confirm that it's working: `sudo -u nobody /usr/bin/gpg --list-keys --homedir=/var/gpg/.gnupg`
