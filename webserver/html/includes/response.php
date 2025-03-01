<?php
function jsonResponse($success, $message = "", $data = [], $httpStatus = 200)
{
    http_response_code($httpStatus);

    header('Content-Type: application/json');
    echo json_encode([
        "success" => $success,
        "message" => $message,
        "data" => $data
    ]);
}
