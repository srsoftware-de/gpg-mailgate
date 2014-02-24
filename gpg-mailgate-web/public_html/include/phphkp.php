<?php

/*
 *
 * HKP Keyserver Interface for submitting public keys
 * to the gpg-mailgate-web database directly from
 * an OpenPGP client
 *
 * loosely based on ElTramo's phkp code
 * http://el-tramo.be/software/phkp
 *
 * 2014 by Kiritan Flux
 *
 * Licensed under the GNU General Public License.
 *
 * check the README for necessary prerequisites
 *
 */

//! OpenPGP client command
$PGP_COMMAND="gpg";

//! A dir where the PHP script has write access
$PGP_HOME="/var/www/vhosts/mailflux.net/.phkp";

//! The maximum size (in characters) of a submitted key.
//! Set to '0' to disable receiving of keys, and '-1' for no limit.
$MAX_KEYSIZE=102400;


if (ereg("/pks\/add",$_SERVER['REQUEST_URI']))
{
  if ($MAX_KEYSIZE == -1 || strlen($_POST['keytext']) <= $MAX_KEYSIZE)
  {
    //write key into temporary file
    file_put_contents( "$PGP_HOME/tmp", $_POST['keytext'] );
    //run gpg --with-fingerprint to retreive information about the key from the keyfile
    $result = shell_exec("$PGP_COMMAND --homedir $PGP_HOME --with-fingerprint $PGP_HOME/tmp");
    //extract email addresses from the information
    $pattern = '/[a-z0-9_\-\+]+@[a-z0-9\-]+\.([a-z]{2,3})(?:\.[a-z]{2})?/i';
    preg_match_all($pattern, $result, $matches);
    //for each email address assigned to the key, put intformation into the DB and send confirmation emails
    foreach($matches[0] as $match)
    {
      //echo $match.': '.$_POST['keytext'];
      requestPGP($match, $_POST['keytext']);
    }
  }
  else
  {
    header("HTTP/1.0 403 Forbidden");
  }
}

?>
