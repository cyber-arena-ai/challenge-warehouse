<?php

$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
if (preg_match('#(?:^|/)\.#', $uri)) {
    http_response_code(404);
    echo "Not found\n";
    return true;
}

chdir('/srv/challenge/horizont');
return require '/srv/challenge/horizont/server.php';
