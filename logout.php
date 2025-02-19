<?php header('Location:'.(parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) == $_SERVER['HTTP_HOST'] ? $_SERVER['HTTP_REFERER'] : '/'));
if(isset($_COOKIE[$session_name = session_name()])) {
  session_start();
  session_destroy();
  setcookie($session_name, "", 1, '/');
}
