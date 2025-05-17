<?php
function encrypt($data, $passphrase = null)
{
    $type = gettype($data);
    if (is_array($data)) {
        $data = json_encode($data);
    } elseif (is_object($data)) {
        throw new Exception("Objects are not supported for encryption.");
    }

    $passphrase = $passphrase ?? config("crypto/passphrase");
    $secret_key = hash('sha256', $passphrase, true);
    $iv_length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($iv_length);

    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $secret_key, 0, $iv);
    if ($encrypted === false) {
        throw new Exception("Encryption failed: " . openssl_error_string());
    }

    $json = new stdClass();
    $json->iv = base64_encode($iv);
    $json->data = $encrypted;
    $json->type = $type;

    return base64_encode(json_encode($json));
}

function decrypt($token, $passphrase = null)
{
    $json = base64_decode($token);
    if ($json === false) {
        throw new Exception("Invalid token encoding.");
    }

    $json = json_decode($json);
    if ($json === null || !isset($json->iv, $json->data, $json->type)) {
        throw new Exception("Invalid token structure.");
    }

    $passphrase = $passphrase ?? config("crypto/passphrase");
    $secret_key = hash('sha256', $passphrase, true);
    $iv = base64_decode($json->iv);
    $encrypted_data = base64_decode($json->data);

    if ($iv === false || $encrypted_data === false) {
        throw new Exception("IV or data decoding failed.");
    }

    $decrypted = openssl_decrypt(
        $encrypted_data,
        'aes-256-cbc',
        $secret_key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($decrypted === false) {
        throw new Exception("Decryption failed: " . openssl_error_string());
    }

    $type = $json->type;
    if ($type === 'array') {
        $decrypted = json_decode($decrypted, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("JSON decode error: " . json_last_error_msg());
        }
    } elseif ($type === 'NULL' && $decrypted === '') {
        $decrypted = null;
    } else {
        settype($decrypted, $type);
    }

    return $decrypted;
}
