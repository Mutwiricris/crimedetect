<?php

// Add this block to your Laravel config/services.php
// Then add the corresponding env vars to your .env file.

return [
    // ... your other services ...

    'crime_detection' => [
        'url'     => env('CRIME_DETECT_URL', 'http://localhost:8000'),
        'api_key' => env('CRIME_DETECT_KEY', 'devkey'),
        'timeout' => env('CRIME_DETECT_TIMEOUT', 10),
    ],
];
