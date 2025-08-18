<?php
require_once __DIR__ . '/../includes/security.php';
$securityHelper = new SecurityHelper();
$securityHelper->initSecureSession();

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