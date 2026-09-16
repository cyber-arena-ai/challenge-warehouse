<?php

$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
if (preg_match('#(?:^|/)\.#', $uri)) {
    http_response_code(404);
    echo "Not found\n";
    return true;
}

$runtime = '/srv/runtime/horizont/current';
chdir($runtime);
return require $runtime . '/server.php';
