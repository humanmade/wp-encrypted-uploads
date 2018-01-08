<?php
/**
 * Plugin name: Encrypted Uploads
 * Description: Allow encryption of uploads with real-time decryption based on user capabilities
 * Author: Human Made Limited
 * Version: 0.1
 */

namespace HM\EncryptedUploads;

if ( ! defined( 'ENCRYPTED_UPLOADS_CIPHER_KEY' ) ) {
	define( 'ENCRYPTED_UPLOADS_CIPHER_KEY', SECURE_AUTH_KEY );
};

if ( ! defined( 'ENCRYPTED_UPLOADS_CIPHER_METHOD' ) ) {
	define( 'ENCRYPTED_UPLOADS_CIPHER_METHOD', 'AES128' );
};

if ( ! defined( 'ENCRYPTED_UPLOADS_ENDPOINT' ) ) {
	define( 'ENCRYPTED_UPLOADS_ENDPOINT', 'decrypt' );
};

require_once __DIR__ . '/namespace.php';

register_activation_hook( __FILE__, __NAMESPACE__ . '\\refresh_rewrite_rules' );
