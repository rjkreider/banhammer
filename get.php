<?php
#SECURITY
//header("Access-Control-Allow-Origin: ".$webServer);
header("Strict-Transport-Security: max-age = 63072000; includeSubDomains; preload");
header("X-Frame-Options: NEVER");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block"); //for old browser
//header("Content-Security-Policy: default-src 'self'; img-src *;script-src 'unsafe-inline'");
header("Content-Security-Policy: block-all-mixed-content");
header("Referrer-Policy: same-origin");
header("Permissions-Policy: geolocation=(),midi=(),microphone=(),camera=(),autoplay=()");

header("Content-type: application/json");

require("dbinfo.php");

function get_stats() {
    global $table;
    $xx = array();

    $xx['totalip'] = getdataset("SELECT COUNT(DISTINCT ip) as count FROM $table");
    $xx['ipban'] = getdataset("SELECT COUNT(DISTINCT ip) as count FROM $table WHERE ban=1");
    $xx['totalcountry'] = getdataset("SELECT COUNT(DISTINCT country) as count FROM $table");

    foreach(getdataset("SELECT code3, country, code, COUNT(id) as count FROM $table GROUP BY country") as $c) {
        $xx['totalpercountry'][$c['code3']] = $c;
    }

    $xx['protos'] = getdataset("SELECT name, COUNT(name) as count FROM $table GROUP BY name");
    $xx['totals'] = getdataset("SELECT code, country, COUNT(*) as count FROM $table GROUP BY country ORDER BY count DESC LIMIT 5");
    $xx['last'] = getdataset("SELECT code, country, MAX(datetime(timestamp,'localtime')) as timestamp FROM $table GROUP BY country ORDER BY timestamp DESC LIMIT 5");
    $xx['lastips'] = getdataset("SELECT ip, code, country, datetime(timestamp,'localtime') as timestamp, id FROM $table ORDER BY timestamp DESC LIMIT 30");

    return $xx;
}

function get_markers() {
    global $link;
    global $table;
    $query = "SELECT 
    id, 
    name, 
    protocol, 
    ports, 
    GROUP_CONCAT(id || ':' || ip, ',') as ips, 
    COUNT(id) as count, 
    longitude, 
    latitude, 
    code, 
    code3, 
    country, 
    city, 
    MAX(datetime(timestamp, 'localtime')) as timestamp, 
    MAX(ban) as ban 
FROM 
    $table 
GROUP BY 
    longitude, 
    latitude, 
    ban 
ORDER BY 
    id ASC;";
    $result = $link->query($query);
    if (!$result) {
        die('Invalid query: ' . $link->lastErrorMsg());
    }

    $rows = array();
    while ($r = $result->fetchArray(SQLITE3_ASSOC)) {
        $rows[] = $r;
    }

    return $rows;
}

function getdataset($query) {
    global $link;
    $result = $link->query($query);
    if (!$result) {
        die('Invalid query: ' . $link->lastErrorMsg());
    }

    $rows = array();
    while ($r = $result->fetchArray(SQLITE3_ASSOC)) {
        $rows[] = $r;
    }

    return $rows;
}

function get_banned_whois() {
    global $table;
    if (isset($_GET['ip']) && is_numeric($_GET['ip']) && intval($_GET['ip']) > 0) {
        $query = 'SELECT ip FROM ' . $table . ' WHERE id=' . intval($_GET['ip']);
        $data = getdataset($query);
        if (sizeof($data) != 1) {
            return ["exit_code" => 3, "message" => "IP not found"];
        } else {
            require_once('lib/whois.php');
            $ip = $data[0]['ip'];
            return ['ip' => $ip, 'whois' => get_whois($ip)];
        }
    } else {
        return ["exit_code" => 2, "message" => "No ip id"];
    }
}

$return = null;
if (isset($_GET['action']) && $_GET['action'] == 'markers') {
    $return = get_markers();
} elseif (isset($_GET['action']) && $_GET['action'] == 'stats') {
    $return = get_stats();
} elseif (isset($_GET['action']) && $_GET['action'] == 'whois') {
    $return = get_banned_whois();
} else {
    $return = ["exit_code" => 1, "message" => "No action"];
}

echo json_encode($return);
$link->close();
?>


