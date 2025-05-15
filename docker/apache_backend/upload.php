<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        http_response_code(400);
        echo "File upload error: " . $file['error'] . "\n";
        exit;
    }

    http_response_code(200);
    echo "File received: " . htmlspecialchars($file['name']) . "\n";
} else {
    http_response_code(400);
    echo "Invalid request.\n";
}
?>