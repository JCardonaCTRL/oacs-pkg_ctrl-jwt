# /packages/ctrl-jwt/tcl/jwt-procs.tcl		-*-tab-width: 4-*- ex:ts=4:sw=4:
ad_library {
	JSON Web Tokens API.

	@author			Juan Tapia (juan.tapia@nexadevs.com)
	@creation-date	2013-03-17 09:41 PDT
}

namespace eval ctrl::jwt {}

ad_proc -public ctrl::jwt::cjwt_generate_token  {
	{-alg HS256} 
	{-type JWT}   
	{-key_file ""}
	{-key_password ""}
	{-payload:required}
	{-secret ""}
} {
	@param alg				the algorithm to use
	@param type				the default
	@param key_file			The absolute path to the private key for encryption. This is required if alg = RS*. 
	@param key_password		this is required if alg = RS* and key file has a password
	@param payload			the JSON format of the data
	@param secret			this is required if alg != RS*
	@return					JSON Web Token
} {

	set header_data [list [list alg $alg ""]  [list typ $type ""]]
	set header_json "\{[ctrl::json::construct_record $header_data]\}"

	#set s [ns_crypto::hmac string -digest sha256 "$secret" "[ns_base64encode $header_json]"]
	set header_base64 [ns_base64urlencode $header_json]
	
	set payload_base64 [ns_base64urlencode $payload]

	if {[string first "HS" $alg] >= 0} {
		if {$secret eq ""} {
			error "Error. For algorithm $alg the \"secret\" parameter is required"
		}
	}

	if {[string first "RS" $alg] >= 0} {
		if {$key_file eq ""} {
			error "Error. For algorithm $alg the \"key_file\" parameter is required"
		}
	}

	switch $alg {
		"HS256" {
			set signature [ns_crypto::hmac string -digest sha256 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
		}
		"HS384" {
			set signature [ns_crypto::hmac string -digest sha384 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
		}
		"HS512" {
			set signature [ns_crypto::hmac string -digest sha512 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
		}
		"RS256" {
			set signature [exec printf "%s" "${header_base64}.${payload_base64}" | \
				openssl dgst -sha256 -sign ${key_file} -binary | openssl base64 | tr -- "+/=" "-_ "]

			set signature [string map {"\n" ""} $signature ]
			set signature [string trim $signature]
		}
		"RS384" {
			set signature [exec printf "%s" "${header_base64}.${payload_base64}" | \
				openssl dgst -sha384 -sign ${key_file} -binary | openssl base64 | tr -- "+/=" "-_ "]

			set signature [string map {"\n" ""} $signature ]
			set signature [string trim $signature]
		}
		"RS512" {
			set signature [exec printf "%s" "${header_base64}.${payload_base64}" | \
				openssl dgst -sha512 -sign ${key_file} -binary | openssl base64 | tr -- "+/=" "-_ "]

			set signature [string map {"\n" ""} $signature ]
			set signature [string trim $signature]
		}
		default {

		}
	}

	set token "${header_base64}.${payload_base64}.${signature}"
	return $token
}

ad_proc -public ctrl::jwt::cjwt_generate_payload    {
	{-claim_info_list:required} 
} {

	@param claim_info_list	list of key value
	@return					return the payload in json format
} {

	set formatted_list [list]
	foreach {key value} $claim_info_list {
		if {$key in [list exp nbf iat]} {
			lappend claim_json_list [list $key $value "f"]
		} else {
			lappend claim_json_list [list $key $value ""]
		}
	}

	set payload_json "\{[ctrl::json::construct_record $claim_json_list]\}"
	return $payload_json
}


ad_proc -public ctrl::jwt::cjwt_registered_claims   {
	{-iss ""} 
	{-sub ""}
	{-aud ""}
	{-exp ""}
	{-nbf ""}
	{-iat ""}
	{-jti ""}   
	{-return_format:required}	
} {
	@param iss				issuer
	@param sub				subject
	@param aud				audience
	@param exp				expiration date. numericDate number value 
	@param nbf				not before. numericDate number value 
	@param iat				issued at. numericDate number value
	@param jti				unique identifier
	@param return_format	json -> ready to send to payload, tcl_list -> list format to add more claims before passing to ctjw_generate_payload
	@return					registered claims in the selected format
} {

	set field_list [list iss sub aud exp nbf iat jti]

	set registered_claims_list [list]
	foreach field $field_list {
		set value [set $field]
		if {$value ne ""} {
			switch $return_format {
				"json" {
					if {$field in [list exp nbf iat]} {
						if {[ad_var_type_check_number_p $value ]} {
							lappend registered_claims_list [list $field $value "f"]
						}
					} else {
						lappend registered_claims_list [list $field $value ""]
					}
				}
				"tcl_list" {
					lappend registered_claims_list $field
					lappend registered_claims_list $value
				}
				default {
					return -1
				}
			}
		}
	}

	switch $return_format {
		"json" {
			set registered_claims_json "\{[ctrl::json::construct_record $registered_claims_list]\}"
		}
		"tcl_list" {
			return $registered_claims_list
		}
		default {
			return -1
		}
	}
}



ad_proc -public ctrl::jwt::cjwt_decode_token  {
	{-jwt_token:required} 
	{-secret ""}   
	{-public_key_file ""}
} {
	@param jwt				the JSON Web Token to decode
	@param secret			the key required in HS algorithm
	@param public_key_file	the key file required in RS algorithm

	@return					JSON Web Token decoded in a tcl object
} { 

	set valid_p 1
	set invalid_code ""

	set jwt_parts [split $jwt_token "."]

	lassign $jwt_parts header_base64 payload_base64 signature

	set header_json  [ns_base64urldecode $header_base64]

	set header_json_parsed [util::json::parse $header_json]
	set header_list [util::json::object::get_values $header_json_parsed]
	set alg [util::json::object::get_value -object $header_json_parsed -attribute "alg"]

	set payload  [ns_base64urldecode $payload_base64]
	set payload_parsed [util::json::parse $payload]
	set claims_list [util::json::object::get_values $payload_parsed]


	if { [catch {set exp [util::json::object::get_value -object $payload_parsed -attribute "exp"]} fid] } {
	    set exp ""
	}

	if { [catch {set iat [util::json::object::get_value -object $payload_parsed -attribute "iat"]} fid] } {
	    set iat ""
	}

	if { [catch {set nbf [util::json::object::get_value -object $payload_parsed -attribute "nbf"]} fid] } {
	    set nbf ""
	}


	if {[string first "HS" $alg] >= 0} {

		if {$secret eq ""} {
			error "Error. For algorithm $alg the \"secret\" parameter is required"
		}
	}

	if {[string first "RS" $alg] >= 0} {

		if {$public_key_file eq ""} {
			error "Error. For algorithm $alg the \"public_key_file\" parameter is required"
		}

		# Convert from base64url to binary.
		# Check for the version and apply the correct code
		set current_version [ns_info patchlevel]
		set current_version_sort [apm_version_sortable $current_version]
		set limit_version_sort [apm_version_sortable "4.99.20"]
		if {$current_version_sort >= $limit_version_sort} {
			set signature_binary [ns_base64urldecode -binary "$signature"]
		} else {
			set signature_binary [ns_base64urldecode "$signature"]
		}

		set signature_base64 [ns_base64encode "$signature_binary"]
		
		# Create Files necesary for linux to decode
		set seconds [clock seconds]
		set random_string [ad_generate_random_string 40]
		set token_file "/tmp/token_${seconds}_${random_string}"
		set base64_file "/tmp/signature_base64_${seconds}_${random_string}"
		set binary_file "/tmp/signature_binary_${seconds}_${random_string}"

		exec printf "%s" "${header_base64}.${payload_base64}" > $token_file


		exec printf "%s" "$signature_base64" > $base64_file
		exec openssl enc -d -base64 -in $base64_file -out $binary_file
	}


	switch  $alg {
		"HS256" {
			set signature_test [ns_crypto::hmac string -digest sha256 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
			
		}
		"HS384" {
			set signature_test [ns_crypto::hmac string -digest sha384 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
			
		}
		"HS512" {
			set signature_test [ns_crypto::hmac string -digest sha512 -encoding base64url "$secret" "${header_base64}.${payload_base64}"]
			
		} 
		"RS256" {
			if { [catch {set signature_test [exec \
				openssl dgst -sha256 -verify "$public_key_file" -signature "$binary_file" $token_file]} fid] } {
			    set signature_test "Failed Verification"
			}
		}
		"RS384" {
			if { [catch {set signature_test [exec \
				openssl dgst -sha384 -verify "$public_key_file" -signature "$binary_file" $token_file]} fid] } {
			    set signature_test "Failed Verification"
			}
		}
		"RS512" {
			if { [catch {set signature_test [exec \
				openssl dgst -sha512 -verify "$public_key_file" -signature "$binary_file" $token_file]} fid] } {
			    set signature_test "Failed Verification"
			}
		}

	}

	set current_time [clock seconds]
	if {$exp ne ""} {
		if {$exp < $current_time} {
			set valid_p 0
			set invalid_code "EXP"
		}
	}

	if {$nbf ne ""} {
		if {$nbf > $current_time} {
			set valid_p 0
			set invalid_code "NYV"
		}
	}

	if {[string first "HS" $alg] >= 0} {
		if {$signature_test ne $signature} {
			set valid_p 0
			set invalid_code "INV"
		} 
	}

	if {[string first "RS" $alg] >= 0} {
		exec rm $base64_file
		exec rm $binary_file
		exec rm $token_file
		if {$signature_test ne "Verified OK"} {
			set valid_p 0
			set invalid_code "INV"
		} 
	}
	

	# Create Tcl object
	Object create jwtToken
	jwtToken set isValid $valid_p
	jwtToken set invalidCode $invalid_code 
	jwtToken set getClaimList $claims_list
	jwtToken set getHeaderList $header_list
	jwtToken set getPayload $payload
	jwtToken set getHeader $header_json
	jwtToken set getSignature $signature

	if {$exp ne ""} {
		jwtToken set expireDate $exp
	}

	if {$nbf ne ""} {
		jwtToken set validOn $nbf
	}

	if {$iat ne ""} {
		jwtToken set issuedDate $iat
	}

 
	return [jwtToken]
}


ad_proc -public ctrl::jwt::cjwt_get_algorithms   {

} {

	@return					list of available algorithms
} {

	set alg_list [list "HS256" "HS384" "HS512" "RS256" "RS384" "RS512"]

	return $alg_list
}