<?php
require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . "/..");
$dotenv->load();

function makeCurlRequest($endpoint, $method = 'GET', $headers = [], $postFields = null)
{
    $baseUrl = rtrim($_ENV['PROXMOX_BASE_URL'], '/');
    $url = $baseUrl . '/' . ltrim($endpoint, '/');

    $ch = curl_init($url);
    $defaultOptions = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_HTTPHEADER => $headers
    ];

    if ($method === 'POST') {
        if ($postFields !== null) {
            $defaultOptions[CURLOPT_POST] = true;
            $defaultOptions[CURLOPT_POSTFIELDS] = $postFields;
        } else {
            $defaultOptions[CURLOPT_CUSTOMREQUEST] = 'POST';
        }
    } elseif (in_array($method, ['DELETE', 'PUT', 'GET'])) {
        $defaultOptions[CURLOPT_CUSTOMREQUEST] = $method;
    }

    curl_setopt_array($ch, $defaultOptions);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false) {
        curl_close($ch);
        return false;
    }

    curl_close($ch);

    return ['response' => $response, 'http_code' => $httpCode];
}
