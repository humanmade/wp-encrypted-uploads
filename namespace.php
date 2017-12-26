<?php

namespace HM\EncryptedUploads;

/**
 * Adds a checkbox in the upload window to encrypt the file being uploaded
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
 * Adds the Javasript handling of the encryption checkbox / params
 * Note: Needed to use a global var because the checkbox is cleared in post-edit add-media modal by that time
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
 * Encrypt file contents via the shared cipher key
 *
 * @param $filepath
 *
 * @return bool
 * @throws \Exception
 */
function encrypt_file( $filepath ) {

	$contents = file_get_contents( $filepath ); // @codingStandardsIgnoreLine

	if ( empty( $contents ) ) {
		return false;
	}

	if ( ! function_exists( 'openssl_encrypt' ) ) {
		throw new Exception( esc_html__( 'openssl_encrypt function does not exist, cannot proceed with encryption' ) );
	}

	$encrypted = openssl_encrypt( $contents, 'AES128', ENCRYPTED_UPLOADS_CIPHER_KEY );

	$fp = fopen( $filepath, 'w+' ); // @codingStandardsIgnoreLine

	if ( ! $fp ) {
		return false;
	}

	fwrite( $fp, $encrypted ); // @codingStandardsIgnoreLine
	fclose( $fp );

	return true;
}

/**
 * Encrypt uploaded file
 *
 * @param $details
 * @param $upload_type
 *
 * @return mixed
 */
function encrypt_uploaded_file( $details, $upload_type ) {

	if ( ! filter_input( INPUT_POST, 'encrypted' ) ) {
		return $details;
	}

	if ( 'upload' !== $upload_type ) {
		return $details;
	}

	if ( ! file_exists( $details['file'] ) ) {
		$details['error'] = esc_html__( 'The specified local upload file does not exist.', 'encrypted-uploads' );

		return $details;
	}

	$ext_info = wp_check_filetype( $details['file'] );

	/**
	 * Filter whether we should encrypt this type of files / specific file or not
	 *
	 * @param $mime_type
	 * @param $file_path
	 *
	 * @return bool
	 */
	if ( ! apply_filters( 'encrypted_uploads_should_encrypt', true, $ext_info['type'], $details['file'] ) ) {
		$details['error'] = esc_html__( 'Could not encrypt the file, possibly because of filesystem permissions.', 'encrypted-uploads' );

		return $details;
	}

	try {
		$encrypted = encrypt_file( $details['file'] );

		if ( ! $encrypted ) {
			$details['error'] = esc_html__( 'Could not encrypt the file, possibly because of filesystem permissions.', 'encrypted-uploads' );

			return $details;
		}
	} catch ( Exception $e ) {
		$details['error'] = $e->getMessage();

		return $details;
	}

	add_action( 'add_attachment', $fn = function ( $post_id ) use ( $details, $fn ) {
		add_post_meta( $post_id, 'encrypted-upload', openssl_encrypt( $post_id, ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY ) );
		remove_action( 'add_attachment', $fn );
	} );

	return $details;
}

add_filter( 'wp_handle_upload', __NAMESPACE__ . '\\encrypt_uploaded_file', 1, 2 );

/**
 * Serve the decrypted file via the decrypt endpoint
 *
 * @param $url
 * @param $post_id
 *
 * @return string
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
 * Register the decryption endpoint
 *
 * @action init
 */
function rewrite_endpoint() {
	add_rewrite_endpoint( ENCRYPTED_UPLOADS_ENDPOINT, EP_ROOT );
}

add_action( 'init', __NAMESPACE__ . '\\rewrite_endpoint' );

/**
 * Serve the decrypted files through our custom endpoint
 *
 * @action template_redirect
 */
function serve_decrypted_file() {
	global $wp_query;

	if ( ! isset( $wp_query->query_vars[ ENCRYPTED_UPLOADS_ENDPOINT ] ) ) {
		return;
	}

	$post_id = absint( openssl_decrypt( $wp_query->query_vars[ ENCRYPTED_UPLOADS_ENDPOINT ], ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY ) );

	/**
	 * Filter the capability used to check whether the current user can download/decrypt the file
	 *
	 * @param $post_id
	 *
	 * @return string
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

	echo openssl_decrypt( $content, ENCRYPTED_UPLOADS_CIPHER_METHOD, ENCRYPTED_UPLOADS_CIPHER_KEY ); // WPCS: xss ok
	exit;
}

add_action( 'template_redirect', __NAMESPACE__ . '\\serve_decrypted_file' );

/**
 * Flush rewrite rules, used on plugin activation hook
 */
function refresh_rewrite_rules() {
	flush_rewrite_rules();
	do_action( 'rri_flush_rules' );
}
