<?php
$_SERVER['SERVER_NAME'] = 'localhost';
$_SERVER['HTTP_USER_AGENT'] = 'arena-bootstrap';
chdir('/srv/challenge/navigate');
require_once('cfg/globals.php');
define('NAVIGATE_URL', NAVIGATE_PARENT.NAVIGATE_FOLDER);
require_once('cfg/common.php');
global $DB, $user, $website;
$DB = new database();
if(!$DB->connect()) { fwrite(STDERR, $DB->get_last_error()); exit(1); }

function ensure_arena_user($credentials, $profile) {
    global $DB;
    $existing = $DB->query_single('id', 'nv_users', 'username = "'.$credentials['username'].'"');
    if(!empty($existing)) { return; }
    $account = new user();
    $account->id = 0;
    $account->username = $credentials['username'];
    $account->set_password($credentials['password']);
    $account->email = $credentials['username'].'@arena.invalid';
    $account->profile = $profile;
    $account->skin = 'cupertino';
    $account->language = 'en';
    $account->blocked = 0;
    $account->timezone = 'UTC';
    $account->date_format = 'Y-m-d H:i';
    $account->decimal_separator = '.';
    $account->thousands_separator = '';
    $account->attempts = 0;
    $account->cookie_hash = '';
    $account->activation_key = '';
    $account->insert();
}

$admin = json_decode(file_get_contents('/run/navigate/admin.json'), true);
$checker = json_decode(file_get_contents('/run/navigate/checker.json'), true);
if(!$admin || !$checker) { fwrite(STDERR, "credential bootstrap unavailable\n"); exit(1); }
ensure_arena_user($admin, 1);
ensure_arena_user($checker, 2);
$user = new user();
$admin_id = $DB->query_single('id', 'nv_users', 'username = "'.$admin['username'].'"');
$user->load($admin_id);
$website = new website();
$website->create_default();
$website->load();
$website->protocol = 'http://';
$website->subdomain = '';
$website->domain = gethostname();
$website->folder = '';
$website->save();
?>
