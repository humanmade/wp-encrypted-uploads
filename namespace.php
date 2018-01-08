<?php

namespace HM\EncryptedUploads;

/**
 * Add a checkbox in the upload window to encrypt the file being uploaded.
 *
 * @action post-upload-ui
 */
function post_upload_ui_encryption() {
	printf(
		'<label for="upload_encrypted"><input type="checkbox" name="upload_encrypted" id="upload_encrypted"> %s</label>',
		esc_html__( 'Encrypt', 'encrypted-uploads' )
	);
}

add_action( 'post-upload-ui', __NAMESPACE__ . '\\post_upload_ui_encryption', 10 );

/**
 * Add the Javascript handling of the encryption checkbox / params.
 *
 * Note: Needed to use a global var because the checkbox is cleared in post-edit add-media modal by that time.
 *
 * @action wp_enqueue_media
 */
function encrypted_footer_script() {
	$script = <<<SCRIPT
	(function($){
		window.ENCRYPTED_UPLOADS_ACTIVATED = false;
		wp.Uploader.prototype.init = _.wrap( wp.Uploader.prototype.init, function( fn ){
			fn.call( this );
			this.uploader.bind('BeforeUpload', function(up, file){
				up.setOption(
					'multipart_params',
					$.extend( 
						up.getOption( 'multipart_params' ),
						{ encrypted: window.ENCRYPTED_UPLOADS_ACTIVATED }
					)
				);
				// Reset the global var so it reflects the checkbox status ( which is diff according to current screen )
				window.ENCRYPTED_UPLOADS_ACTIVATED = $( '#upload_encrypted' ).is( ':checked' );
			} );
		} );
		
		$(document).on( 'click', '#upload_encrypted', function(){
			window.ENCRYPTED_UPLOADS_ACTIVATED = $(this).is( ':checked' );
		});
	})(jQuery);
SCRIPT;
	wp_add_inline_script( 'media-views', $script );
}

add_action( 'wp_enqueue_media', __NAMESPACE__ . '\\encrypted_footer_script', 99 );

/**
 * Encrypt file contents via the shared cipher key.
 *
 * @param string $filepath Path to the file to encrypt.
 *
 * @return bool Whether the file was encrypted or not
 * @throws \Exception
 */
function encrypt_file( $filepath ) {

	$contents = file_get_contents( $filepath ); // @codingStandardsIgnoreLine

	if ( empty( $contents ) ) {
		return false;
	}

	if ( ! function_exists( 'openssl_encrypt' ) ) {
		throw new Exception( esc_html__( 'openssl_encrypt function does not exist, cannot proceed with encryption', 'encrypted-uploads' ) );
	}

	$iv_size = openssl_cipher_iv_length( ENCRYPTED_UPLOADS_CIPHER_METHOD );

	if ( false === $iv_size ) {
		throw new \Exception( esc_html__( 'Unsupported cipher method specified.', 'encrypted-uploads' ) );
	}

	$iv = openssl_random_pseudo_bytes( $iv_size );

	if ( false === $iv ) {
		throw new \Exception( esc_html__( 'Unsupported cipher method specified.', 'encrypted-uploads' ) );
	}

	$encrypted = openssl_encrypt( $contents, ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY, OPENSSL_RAW_DATA, $iv );

	$fp = fopen( $filepath, 'w+' ); // @codingStandardsIgnoreLine

	if ( ! $fp ) {
		return false;
	}

	$iv_salt = get_site_iv_salt();

	fwrite( $fp, $iv . $iv_salt . $encrypted ); // @codingStandardsIgnoreLine
	fclose( $fp );

	return true;
}

/**
 * Get site-specific randomly-generated IV salt
 *
 * @return mixed|string|void
 */
function get_site_iv_salt() {
	$random_iv_salt = get_option( 'encrypted-uploads-random-iv-salt' );

	if ( empty( $random_iv_salt ) ) {
		$random_iv_salt = base64_encode( openssl_random_pseudo_bytes( rand( 1, 20 ) ) );
		update_option( 'encrypted-uploads-random-iv-salt', $random_iv_salt );
	}

	return $random_iv_salt;
}

/**
 * Encrypt uploaded file through wp_handle_upload.
 *
 * @param array  $file     Array of file details
 *
 * @return mixed
 * @throws \Exception
 */
function encrypt_uploaded_file( $file ) {

	if ( ! filter_input( INPUT_POST, 'encrypted', FILTER_VALIDATE_BOOLEAN ) ) {
		return $file;
	}

	$file_path = $file['tmp_name'];
	$file_name = $file['name'];

	if ( ! file_exists( $file_path ) ) {
		$file['error'] = esc_html__( 'The specified local upload file does not exist.', 'encrypted-uploads' );

		return $file;
	}

	$ext_info = wp_check_filetype( $file_name );
	$ext      = pathinfo( $file_name, PATHINFO_EXTENSION );

	/**
	 * Filter whether we should encrypt this type of files / specific file or not.
	 *
	 * @param string $mime_type Detected mime type of the file
	 * @param string $extension File extension
	 * @param string $file_path Path to the file
	 *
	 * @return bool Whether to allow encryption or not
	 */
	if ( ! apply_filters( 'encrypted_uploads_should_encrypt', true, $ext_info['type'], $ext, $file_name, $file_path ) ) {
		$file['error'] = esc_html__( 'Encryption of this file has been disabled by site administrator.', 'encrypted-uploads' );

		return false;
	}

	try {
		$encrypted = encrypt_file( $file_path );

		if ( ! $encrypted ) {
			$file['error'] = esc_html__( 'Could not encrypt the file, possibly because of filesystem permissions.', 'encrypted-uploads' );

			return $file;
		}
	} catch ( Exception $e ) {
		$file['error'] = $e->getMessage();

		return $file;
	}

	// Mark the file as encrypted via meta data
	add_action( 'add_attachment', $fn = function ( $post_id ) use ( $file_name, $fn ) {
		$base_filename = pathinfo( $file_name, PATHINFO_FILENAME );
		if ( get_post( $post_id )->post_title !== $base_filename ) {
			return;
		}
		add_post_meta( $post_id, 'encrypted-upload', base64_encode( openssl_encrypt( $post_id, ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY, 0, SECURE_AUTH_SALT ) ) );
		remove_action( 'add_attachment', $fn );
	} );

	// Skip deep file type detection as the file is encoded
	add_filter( 'wp_check_filetype_and_ext', $fn2 = function( $args, $file, $filename, $mimes ) use ( $file_path ) {
		if ( $file !== $file_path ) {
			return $args;
		}

		$proper_filename = false;
		$wp_filetype     = wp_check_filetype( $filename, $mimes );
		$ext             = $wp_filetype['ext'];
		$type            = $wp_filetype['type'];

		remove_action( current_action(), $fn2 );
		return compact( 'ext', 'type', 'proper_filename' );
	}, 100, 4 );

	return $file;
}

add_filter( 'wp_handle_upload_prefilter', __NAMESPACE__ . '\\encrypt_uploaded_file', 1 );

/**
 * Serve the decrypted file via the decrypt endpoint.
 *
 * @param string $url     URL to the attachment file
 * @param int    $post_id Post ID of the attachment
 *
 * @return string Decryption URL of the passed attachment ID
 */
function decoded_upload_url( $url, $post_id ) {
	global $wp_query;

	$key = get_post_meta( $post_id, 'encrypted-upload', true );

	if ( ! $key ) {
		return $url;
	}

	// Skip conversion when we're on the decryption endpoint
	if ( isset( $wp_query->query_vars[ ENCRYPTED_UPLOADS_ENDPOINT ] ) ) {
		return $url;
	}

	return esc_url( home_url( ENCRYPTED_UPLOADS_ENDPOINT . '/' . $key ) );
}

add_filter( 'wp_get_attachment_url', __NAMESPACE__ . '\\decoded_upload_url', 20, 2 );

/**
 * Register the decryption endpoint.
 *
 * @action init
 */
function rewrite_endpoint() {
	add_rewrite_endpoint( ENCRYPTED_UPLOADS_ENDPOINT, EP_ROOT );
}

add_action( 'init', __NAMESPACE__ . '\\rewrite_endpoint' );

/**
 * Serve the decrypted files through our custom endpoint.
 *
 * @action template_redirect
 */
function serve_decrypted_file() {
	global $wp_query;

	if ( ! isset( $wp_query->query_vars[ ENCRYPTED_UPLOADS_ENDPOINT ] ) ) {
		return;
	}

	$post_id = absint( openssl_decrypt( base64_decode( $wp_query->query_vars[ ENCRYPTED_UPLOADS_ENDPOINT ] ), ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY, 0, SECURE_AUTH_SALT ) );

	/**
	 * Filter the capability used to check whether the current user can download/decrypt the file.
	 *
	 * @param int $post_id Attachment post ID
	 *
	 * @return string Capability to check for
	 */
	$cap = apply_filters( 'encrypted_uploads_view_cap', 'edit_post' );
	if ( ! current_user_can( $cap, $post_id ) ) {
		wp_die( esc_html__( 'You do not have permission to view this file.', 'encrypted-uploads' ) );
	}

	$url = wp_get_attachment_url( $post_id );

	if ( function_exists( 'wpcom_vip_file_get_contents' ) ) {
		$content = wpcom_vip_file_get_contents( $url, 3, 900, [ 'http_api_args' => [ 'sslverify' => false ] ] );
	} else {
		$response = wp_remote_get( $url, [ 'sslverify' => false ] ); // @codingStandardsIgnoreLine
		if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
		} elseif ( is_wp_error( $response ) ) {
			wp_die( esc_html( $response->get_error_message() ) );
		} else {
			wp_die( esc_html__( 'Could not retrieve the file.', 'encrypted-uploads' ) );
		}
	}

	$filename = pathinfo( $url, PATHINFO_BASENAME );
	$ext      = pathinfo( $url, PATHINFO_EXTENSION );
	$ext_info = wp_check_filetype( $filename );
	header( sprintf( 'Content-Type: %s; charset=utf-8', $ext_info['type'] ?: 'application/binary' ) );
	header( sprintf( 'Content-Disposition: filename=%s', get_post( $post_id )->post_title . '.' . $ext ) );

	$iv_salt = get_site_iv_salt();
	$iv_length = openssl_cipher_iv_length( ENCRYPTED_UPLOADS_CIPHER_METHOD );

	$iv = substr( $content, 0, $iv_length );
	$content = substr( $content, $iv_length + strlen( $iv_salt ) );

	echo openssl_decrypt( $content, ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY, OPENSSL_RAW_DATA, $iv ); // WPCS: xss ok
	exit;
}

add_action( 'template_redirect', __NAMESPACE__ . '\\serve_decrypted_file' );

/**
 * Flush rewrite rules, used on plugin activation hook.
 */
function refresh_rewrite_rules() {
	flush_rewrite_rules();
	do_action( 'rri_flush_rules' );
}
