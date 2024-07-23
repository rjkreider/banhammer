<?php
$database = 'fail2ban.db';
$table = 'fail2ban';

// Opens a connection to an SQLite3 database
$link = new SQLite3($database);
if (!$link) {
    die('Not connected: ' . $link->lastErrorMsg());
}
?>

