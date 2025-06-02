<?php
require_once __DIR__ . '/../includes/security.php';
init_secure_session();

$loggedInUser = $_SESSION['username'] ?? null;
$requestedUser = $_GET['username'] ?? null;

if (!$requestedUser) {
    if ($loggedInUser) {
        header("Location: /profile/" . urlencode($loggedInUser));
        exit();
    } else {
        header("Location: /login");
        exit();
    }
}

if ($loggedInUser === $requestedUser) {
    include(__DIR__ . '/profile.php');
} else {
    include(__DIR__ . '/profile_public.php');
}