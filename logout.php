<?php

// Redirect to referer if same host.
header('Location:'.(parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) == $_SERVER['HTTP_HOST'] ? $_SERVER['HTTP_REFERER'] : '/'));

// Only destroy session if session cookie is set.
if(isset($_COOKIE[session_name()])) {
  session_start();
  session_destroy();
  setcookie(session_name(), "", 1, '/'); // Delete cookie
}
