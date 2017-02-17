<?php
/**
 * @package   	OneAll Single Sign-On
 * @copyright 	Copyright 2011-2017 http://www.oneall.com/
 * @license   	GNU/GPL 2 or later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,USA.
 *
 * The "GNU General Public License" (GPL) is available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */

class OneAll_SingleSignOn_Helper_Data extends Mage_Core_Helper_Abstract
{
	
	const OA_USER_AGENT = 'SingleSignOn/1.0.0 Magento/1.x (+http://www.oneall.com/)';
	
	/**
	 * Generate a random email address.
	 */
	protected function create_random_email ()
	{
		$customer = Mage::getModel ('customer/customer');
		$customer->setWebsiteId (Mage::app ()->getWebsite ()->getId ());

		do
		{
			// Create a random email.
			$email = md5 (uniqid (rand (10000, 99000))) . "@example.com";

			// Try to load a customer for it
			$customer->loadByEmail ($email);
			$id = $customer->getId ();
		}
		while (! empty ($id));

		// Done
		return $email;
	}

	/**
	 * Check if the current connection is being made over https.
	 */
	public function is_https_on ()
	{
		if (! empty ($_SERVER ['SERVER_PORT']))
		{
			if (trim ($_SERVER ['SERVER_PORT']) == '443')
			{
				return true;
			}
		}

		if (! empty ($_SERVER ['HTTP_X_FORWARDED_PROTO']))
		{
			if (strtolower (trim ($_SERVER ['HTTP_X_FORWARDED_PROTO'])) == 'https')
			{
				return true;
			}
		}

		if (! empty ($_SERVER ['HTTPS']))
		{
			if (strtolower (trim ($_SERVER ['HTTPS'])) == 'on' or trim ($_SERVER ['HTTPS']) == '1')
			{
				return true;
			}
		}

		return false;
	}
	
	/**
	 * Returns the API Settings
	 */
	public function get_settings ()
	{		
		$settings = array ();
		
		$settings ['connection_handler'] = (Mage::getStoreConfig ('oneall_singlesignon/connection/handler') == 'fsockopen' ? 'fsockopen' : 'curl');
		$settings ['connection_port'] = (Mage::getStoreConfig ('oneall_singlesignon/connection/port') == 80 ? 80 : 443);
		$settings ['connection_protocol'] = ($settings ['connection_port'] == 80 ? 'http' : 'https'); 
		
		$settings ['session_lifetime'] = trim (strval(Mage::getStoreConfig ('oneall_singlesignon/settings/sessionlifetime')));
		$settings ['session_lifetime'] = ((empty ($settings ['session_lifetime']) || $settings ['session_lifetime'] < 0 ) ? 86400 : $settings ['session_lifetime']);
		
		$settings ['session_top_realm'] = trim (strval(Mage::getStoreConfig ('oneall_singlesignon/settings/sessiontoprealm')));
		$settings ['session_sub_realm'] = (empty ($settings ['session_top_realm']) ? '' : trim (strval(Mage::getStoreConfig ('oneall_singlesignon/settings/sessionsubrealm'))));
		
		$settings ['key'] = trim (strval(Mage::getStoreConfig ('oneall_singlesignon/general/key')));
		$settings ['secret'] = trim (strval(Mage::getStoreConfig ('oneall_singlesignon/general/secret')));

		$settings ['subdomain'] = trim (strval(Mage::getStoreConfig ('oneall_singlesignon/general/subdomain')));
		
		$settings ['base_url'] = $settings['subdomain'] . '.api.oneall.loc';
		$settings ['api_url'] = ($settings['connection_protocol'] . '://' . $settings ['base_url']);
		

		return $settings;
	}	
	
	/**
	 * Removes a new Single Sign-On session for the given sso_session_token
	 */
	public function api_remove_session_for_sso_session_token ($sso_session_token)
	{
		// Status
		$result_status = false;
		
		// We need the sso_session_token to remove the session
		if ( ! empty ($sso_session_token))
		{
			// Read settings
			$api_settings = $this->get_settings();
	
			// We cannot make a connection without a subdomain
			if (! empty ($api_settings['subdomain']))
			{
				// API Endpoint: http://docs.oneall.com/api/resources/sso/delete-session/
				$api_resource_url = $api_settings['api_url'] . '/sso/sessions/'.$sso_session_token.'.json?confirm_deletion=true';
				
				// API Options
				$api_options = array (
					'api_key' => $api_settings['key'],
					'api_secret' => $api_settings['secret'],
				);
				
				// Create Session
				$result = $this->do_api_request ($api_settings ['connection_handler'], $api_resource_url, 'DELETE', $api_options);
				
				// Success
				$result_status = true;
			}
		}
		
		// Error
		return $result_status;
	}
	
	
	/**
	 * Starts a new Single Sign-On session for the given identity 
	 */
	public function api_start_session_for_identity_token ($identity_token)
	{
		// The key of the new session
		$sso_session_token = null;
		
		// We need the identity_token to create the session
		if ( ! empty ($identity_token))
		{
			// Read settings
			$api_settings = $this->get_settings();
		
			// We cannot make a connection without a subdomain
			if (! empty ($api_settings['subdomain']))
			{
				//////////////////////////////////////////////////////////////////////////////////////////////////
				// Start a new Single Sign-On Session
				//////////////////////////////////////////////////////////////////////////////////////////////////
					
				// API Endpoint: http://docs.oneall.com/api/resources/sso/identity/start-session/
				$api_resource_url = $api_settings['api_url'] . '/sso/sessions/identities/'.$identity_token.'.json';
		
				// API Options
				$api_options = array (
					'api_key' => $api_settings['key'],
					'api_secret' => $api_settings['secret'],
					'api_data' => json_encode (array(
						'request' => array(
							'sso_session' => array(
								'top_realm' => $api_settings['session_top_realm'],
								'sub_realm' => $api_settings['session_sub_realm'],
								'lifetime' => $api_settings['session_lifetime']
							) 
						) 
					))
				);
				
				// Create Session
				$result = $this->do_api_request ($api_settings ['connection_handler'], $api_resource_url, 'PUT', $api_options);
			
				// Check result. 201 Returned !!!
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 201 && property_exists ($result, 'http_data'))
				{
					// Decode result
					$decoded_result = @json_decode ($result->http_data);

					// Check result
					if (is_object ($decoded_result) && isset ($decoded_result->response->result->data->sso_session))
					{
						// The key of the new Single Sign-On session
						$sso_session_token = $decoded_result->response->result->data->sso_session->sso_session_token;
					}
				}				
			}
		}
		
		// Done
		return $sso_session_token;
	}
	
	
	/**
	 * Stores a customer in the cloud storage
	 */
	public function api_add_customer_to_cloud_storage ($customer)
	{
		// The key of the user's identity stored in the cloud storage
		$identity_token = null;
		
		// Read settings
		$api_settings = $this->get_settings();

		// We cannot make a connection without a subdomain
		if (! empty ($api_settings['subdomain']))
		{
			//////////////////////////////////////////////////////////////////////////////////////////////////
			// First make sure that we don't create duplicate users
			//////////////////////////////////////////////////////////////////////////////////////////////////
			
			// API Endpoint: http://docs.oneall.com/api/resources/storage/users/lookup-user/
			$api_resource_url = $api_settings['api_url'] . '/storage/users/user/lookup.json';
			
			// API Options
			$api_options = array (
				'api_key' => $api_settings['key'],
				'api_secret' => $api_settings['secret'],
				'api_data' => json_encode (array(
					'request' => array(
						'user' => array(
							'login' => $customer->getEmail(),
						) 
					) 
				))
			);	
			
			// User Lookup
			$result = $this->do_api_request ($api_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
			
			// Check result
			if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200 and property_exists ($result, 'http_data'))
			{
				// Decode result
				$decoded_result = @json_decode ($result->http_data);

				// Check result
				if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
				{
					// The key of the user's identity stored in the cloud storage
					$identity_token = $decoded_result->response->result->data->user->identity->identity_token;
				}
			}
			
			//////////////////////////////////////////////////////////////////////////////////////////////////
			// If we have no identity_token, then a new identity needs to be added
			//////////////////////////////////////////////////////////////////////////////////////////////////
			if (empty ($identity_token))
			{			
				// API Endpoint: http://docs.oneall.com/api/resources/storage/users/create-user/
				$api_resource_url = $api_settings['api_url'] . '/storage/users.json';
	
				// API Options
				$api_options = array (
					'api_key' => $api_settings['key'],
					'api_secret' => $api_settings['secret'],
					'api_data' => json_encode (array(
						'request' => array(
							'user' => array(
								'login' => $customer->getEmail(),
								'password' => $customer->getPasswordHash(),
								//'externalid' => $customer->getEntityId(),
								'identity' => array(
									'name' => array(
										'honorificPrefix' => $customer->getPrefix(),
										'givenName' => $customer->getFirstname(),
										'middleName'  => $customer->getMiddlename(),
										'familyName' => $customer->getLastname(), 
										'honorificSuffix' => $customer->getSuffix()
									),
									'emails' => array (
										'value' => $customer->getEmail(),
										'is_verified' => $customer->getCustomerActivated()
									),
									'accounts' => array (
										'domain' => Mage::getBaseUrl(),
										'userid' => $customer->getId()
									)
								) 
							) 
						) 
					))
				);	
							
				// Add User
				$result = $this->do_api_request ($api_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
			
				// Check result
				if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200 and property_exists ($result, 'http_data'))
				{
					// Decode result
					$decoded_result = @json_decode ($result->http_data);

					// Check result
					if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
					{
						// The key of the user's identity stored in the cloud storage
						$identity_token = $decoded_result->response->result->data->user->identity->identity_token;
					}
				}
			}	
		}
		
		// Done
		return $identity_token;
	}
	
	/**
	 * Removes a new single sign-on session for the given customer
	 */
	public function remove_session_for_customer ($customer)
	{
		// Read session of this customer
		$session = Mage::getModel ('oneall_singlesignon/session')->load ($customer->getId(), 'customer_id');
		$sso_session_token = $session->sso_session_token;

		// Session found
		if ( ! empty ($sso_session_token))
		{
			// Remove Session					
			$sso_session_token = $this->api_remove_session_for_sso_session_token ($sso_session_token);
				
			// Delete Entry
			$session->delete ();
		}		
	}
	
	
	/**
	 * Opens a new single sign-on session for the given customer
	 */
	public function create_session_for_customer ($customer)
	{
		// The key of the new session
		$sso_session_token = null;
		
		// Read identity of this customer
		$user = Mage::getModel ('oneall_singlesignon/user')->load ($customer->getId(), 'customer_id');
		$identity_token = $user->identity_token;
			
		// No identity_token for this customer found
		if (empty ($identity_token))
		{
			// Generate identity_token
			$identity_token = $this->api_add_customer_to_cloud_storage ($customer);
				
			// Save identity_token
			if ( ! empty ($identity_token))
			{	
				$user->setData ('customer_id', $customer->getId ());
				$user->setData ('identity_token', $identity_token);
				$user->save ();
			}				
		}

		// Start Session
		if ( ! empty ($identity_token))
		{
			// Generate sso_session_token
			$sso_session_token = $this->api_start_session_for_identity_token ($identity_token);
				
			// Save sso_session_token
			if ( ! empty ($sso_session_token))
			{
				$session = Mage::getModel ('oneall_singlesignon/session')->load ($customer->getId(), 'customer_id');	
				$session->setData ('customer_id', $customer->getId ());
				$session->setData ('sso_session_token', $sso_session_token);
				$session->save ();
			}
		}			
		
		// Created session
		return $sso_session_token;
	}
	
	/**
	 * Check if a login is being made over SSO.
	 */
	public function check_for_sso_login ()
	{
		// Result Container
		$status = new stdClass();
		
		// Read URL parameters
		$action = strtolower (trim(strval (Mage::app ()->getRequest ()->getParam ('oa_action'))));
		$connection_token = Mage::app ()->getRequest ()->getParam ('connection_token');

		// Callback Handler
		if ($action == 'single_sign_on' and ! empty ($connection_token))
		{
			// Read settings
			$api_settings = $this->get_settings();
			
			// We cannot make a connection without a subdomain
			if (! empty ($api_settings['subdomain']))
			{
				// See: http://docs.oneall.com/api/resources/connections/read-connection-details/
				$api_resource_url = $api_settings['api_url'] . '/connections/' . $connection_token . '.json';

				// API Options
				$api_options = array (
					'api_key' => $api_settings['key'],
					'api_secret' => $api_settings['secret'],
				);
				
				// Read Details
				$result = $this->do_api_request ($api_settings ['connection_handler'], $api_resource_url, 'GET', $api_options);

				// Check result
				if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200 and property_exists ($result, 'http_data'))
				{
					// Decode result
					$decoded_result = @json_decode ($result->http_data);

					// Check result
					if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
					{
						// Extract user data.
						$data = $decoded_result->response->result->data;

						// The user_token uniquely identifies the user.
						$user_token = $data->user->user_token;

						// The identity_token uniquely identifies the social network account.
						$identity_token = $data->user->identity->identity_token;

						// Check if we have a customer for this identity_token.
						$user = Mage::getModel ('oneall_singlesignon/user')->load ($identity_token, 'identity_token');
						$customer_id = $user->customer_id;
						
						// Customer identifier found.
						if ( ! empty ($customer_id))
						{
							// Load Customer
							$customer = Mage::getModel ('customer/customer')->load ($customer_id);
							
							// Customer no longer exists.
							if (! $customer->getId ())
							{
								// Cleanup our table.
								$user->delete ();
									
								// Reset customer id
								$customer_id = null;
							}
							// Customer exists.
							else
							{
								// Login
								Mage::getSingleton ('customer/session')->loginById ($customer_id);
							
								// Update Status
								$status->action = 'existing_user_login';
								$status->identity_token = $identity_token;
								$status->customer = $customer;
								
								// Done
								return $status;
							}
						}

						// Retrieve email from identity
						if (isset ($data->user->identity->emails) && is_array ($data->user->identity->emails) && count ($data->user->identity->emails) > 0)
						{
							// Email Details.
							$email = $data->user->identity->emails [0]->value;
							$email_verified = $data->user->identity->emails [0]->is_verified;
							
							// Try to load customer.
							$customer = Mage::getModel ('customer/customer');
							$customer->setWebsiteId (Mage::app ()->getWebsite ()->getId ());
							$customer->loadByEmail ($email);
							$customer_id = $customer->getId ();
							
							// Customer identifier found.
							if ( ! empty ($customer_id))
							{
								// If the email has been verified, we can login the customer
								if ($email_verified)
								{
									// Login
									Mage::getSingleton ('customer/session')->loginById ($customer_id);
										
									// Update Status
									$status->action = 'existing_user_login';
									$status->identity_token = $identity_token;
									$status->customer = $customer;			
								}
								// If the email has not been verified, we cannot login the customer for security reasons
								else
								{
									// Update Status
									$status->action = 'existing_user_not_verified';
									$status->identity_token = $identity_token;
									$status->customer = $customer;		
								}
								
								// Done
								return $status;
							}
						}
						else
						{
							$email = $this->create_random_email ();
							$email_is_random = true;
						}

						// Create a new customer.
						$customer = Mage::getModel ('customer/customer');

						// Generate a password for the customer.
						$password = $customer->generatePassword (8);

						// First Name
						$first_name = 'unknown';
						if (! empty ($data->user->identity->name->givenName))
						{
							$first_name = $data->user->identity->name->givenName;
						}
						else if (! empty ($data->user->identity->displayName))
						{
							$names = explode (' ', $data->user->identity->displayName);
							$first_name = $names[0];
						}
						else if (! empty($data->user->identity->name->formatted))
						{
							$names = explode (' ', $data->user->identity->name->formatted);
							$first_name = $names[0];
						}
						
						// Last Name
						$last_name = 'unknown';
						if (! empty ($data->user->identity->name->familyName))
						{
							$last_name = $data->user->identity->name->familyName;
						}
						else if (!empty ($data->user->identity->displayName))
						{
							$names = explode (' ', $data->user->identity->displayName);
							if (! empty ($names[1]))
							{
								$last_name = $names[1];
							}
						}
						else if (!empty($data->user->identity->name->formatted))
						{
							$names = explode (' ', $data->user->identity->name->formatted);
							if (! empty ($names[1]))
							{
								$last_name = $names[1];
							}
						}

						$customer->setFirstname ($first_name);
						$customer->setLastname ($last_name);
						$customer->setEmail ($email);
						$customer->setPassword ($password);
						$customer->setPasswordConfirmation ($password);
						$customer->setConfirmation ($password);

						// Validate user details.
						$errors = $customer->validate ();

						// Do we have any errors?
						if (is_array ($errors) && count ($errors) > 0)
						{
							// Display Errors
							Mage::getSingleton ('core/session')->addError (implode (' ', $errors));
							
							// Done
							return 'new_user_errors';
						}

						// Save user.
						$customer->save ();
		
						// Login
						Mage::getSingleton ('customer/session')->loginById ($customer->getId ());
						
						// Update Status
						$status->action = 'new_user_login';
						$status->identity_token = $identity_token;
						$status->customer = $customer;
						
						// Done
						return $status;		
					}
				}
			}
		}

		// Update Status
		$status->action = 'no_callback_data_received';
		
		// Done
		return $status;
	}

	/**
	 * Return the list of disabled PHP functions.
	 */
	public function get_disabled_php_functions ()
	{
		$disabled_functions = trim (ini_get ('disable_functions'));
		if (strlen ($disabled_functions) == 0)
		{
			$disabled_functions = array ();
		}
		else
		{
			$disabled_functions = explode (',', $disabled_functions);
			$disabled_functions = array_map ('trim', $disabled_functions);
		}
		return $disabled_functions;
	}

	/**
	 * Send an API request by using the given handler
	 */
	public function do_api_request ($handler, $url, $method = 'GET', $options = array(), $timeout = 25)
	{
		// FSOCKOPEN
		if ($handler == 'fsockopen')
		{
			return $this->do_fsockopen_request ($url, $method, $options, $timeout);
		}
		// CURL
		else
		{
			return $this->do_curl_request ($url, $method, $options, $timeout);
		}
	}

	/**
	 * Check if fsockopen is available.
	 */
	public function is_fsockopen_available ()
	{
		// Make sure fsockopen has been loaded
		if (function_exists ('fsockopen') and function_exists ('fwrite'))
		{
			// Read the disabled functions
			$disabled_functions = $this->get_disabled_php_functions ();

			// Make sure fsockopen has not been disabled
			if (! in_array ('fsockopen', $disabled_functions) and ! in_array ('fwrite', $disabled_functions))
			{
				// Loaded and enabled
				return true;
			}
		}

		// Not loaded or disabled
		return false;
	}

	/**
	 * Check if fsockopen is enabled and can be used to connect to OneAll.
	 */
	public function is_api_connection_fsockopen_ok ($secure = true)
	{
		if ($this->is_fsockopen_available ())
		{
			$result = $this->do_fsockopen_request (($secure ? 'https' : 'http') . '://www.oneall.com/ping.html');
			if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200)
			{
				if (property_exists ($result, 'http_data'))
				{
					if (strtolower ($result->http_data) == 'ok')
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Send an fsockopen request.
	 */
	public function do_fsockopen_request ($url, $method = 'GET', $options = array(), $data = null, $timeout = 15)
	{
		// Store the result
		$result = new stdClass ();

		// Make sure that this is a valid URL
		if (($uri = parse_url ($url)) == false)
		{
			$result->http_code = - 1;
			$result->http_data = null;
			$result->http_error = 'invalid_uri';
			return $result;
		}

		// Make sure that we can handle the scheme
		switch ($uri ['scheme'])
		{
			case 'http':
				$port = (isset ($uri ['port']) ? $uri ['port'] : 80);
				$host = ($uri ['host'] . ($port != 80 ? ':' . $port : ''));
				$fp = @fsockopen ($uri ['host'], $port, $errno, $errstr, $timeout);
				break;

			case 'https':
				$port = (isset ($uri ['port']) ? $uri ['port'] : 443);
				$host = ($uri ['host'] . ($port != 443 ? ':' . $port : ''));
				$fp = @fsockopen ('ssl://' . $uri ['host'], $port, $errno, $errstr, $timeout);
				break;

			default:
				$result->http_code = - 1;
				$result->http_data = null;
				$result->http_error = 'invalid_schema';
				return $result;
				break;
		}

		// Make sure that the socket has been opened properly
		if (! $fp)
		{
			$result->http_code = - $errno;
			$result->http_data = null;
			$result->http_error = trim ($errstr);
			return $result;
		}

		// Construct the path to act on
		$path = (isset ($uri ['path']) ? $uri ['path'] : '/');
		if (isset ($uri ['query']))
		{
			$path .= '?' . $uri ['query'];
		}

		// Create HTTP request
		$defaults = array (
			'Host' => "Host: $host",
			'User-Agent' => 'User-Agent: ' . self::OA_USER_AGENT
		);

		// Enable basic authentication
		if (isset ($options ['api_key']) and isset ($options ['api_secret']))
		{
			$defaults ['Authorization'] = 'Authorization: Basic ' . base64_encode ($options ['api_key'] . ":" . $options ['api_secret']);
		}

		// Build and send request
		$request = 'GET ' . $path . " HTTP/1.0\r\n";
		$request .= implode ("\r\n", $defaults);
		$request .= "\r\n\r\n";
		fwrite ($fp, $request);

		// Fetch response
		$response = '';
		while (! feof ($fp))
		{
			$response .= fread ($fp, 1024);
		}

		// Close connection
		fclose ($fp);

		// Parse response
		list ($response_header, $response_body) = explode ("\r\n\r\n", $response, 2);

		// Parse header
		$response_header = preg_split ("/\r\n|\n|\r/", $response_header);
		list ($header_protocol, $header_code, $header_status_message) = explode (' ', trim (array_shift ($response_header)), 3);

		// Build result
		$result->http_code = $header_code;
		$result->http_data = $response_body;

		// Done
		return $result;
	}

	/**
	 * Check if cURL has been loaded and is enabled.
	 */
	public function is_curl_available ()
	{
		// Make sure cURL has been loaded.
		if (in_array ('curl', get_loaded_extensions ()) and function_exists ('curl_init') and function_exists ('curl_exec'))
		{
			// Read the disabled functions.
			$disabled_functions = $this->get_disabled_php_functions ();

			// Make sure CURL has not been disabled.
			if (! in_array ('curl_init', $disabled_functions) and ! in_array ('curl_exec', $disabled_functions))
			{
				// Loaded and enabled.
				return true;
			}
		}

		// Not loaded or disabled.
		return false;
	}

	/**
	 * Check if CURL is available and can be used to connect to OneAll
	 */
	public function is_api_connection_curl_ok ($secure = true)
	{
		// Is CURL available and enabled?
		if ($this->is_curl_available ())
		{
			// Make a request to the OneAll API.
			$result = $this->do_curl_request (($secure ? 'https' : 'http') . '://www.oneall.com/ping.html');
			if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200)
			{
				if (property_exists ($result, 'http_data'))
				{
					if (strtolower ($result->http_data) == 'ok')
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Send a CURL request.
	 */
	public function do_curl_request ($url, $method = 'GET', $options = array(), $data = null, $timeout = 15)
	{
		// Store the result
		$result = new stdClass ();

		// Send request
		$curl = curl_init ();
		curl_setopt ($curl, CURLOPT_URL, $url);
		curl_setopt ($curl, CURLOPT_HEADER, 0);
		curl_setopt ($curl, CURLOPT_TIMEOUT, $timeout);
		curl_setopt ($curl, CURLOPT_VERBOSE, 0);
		curl_setopt ($curl, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt ($curl, CURLOPT_USERAGENT, self::OA_USER_AGENT);

		// HTTP Method
		switch (strtoupper ($method))
		{
			case 'DELETE':
				curl_setopt ($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
			break;
			
			case 'PUT':
				curl_setopt ($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
			break;

			case 'POST':
				curl_setopt ($curl, CURLOPT_POST, 1);
			break;
			
			default:
				curl_setopt ($curl, CURLOPT_HTTPGET, 1);
			break;
		}

		// HTTP AUTH
		if (isset ($options ['api_key']) and isset ($options ['api_secret']))
		{
			curl_setopt ($curl, CURLOPT_USERPWD, $options ['api_key'] . ":" . $options ['api_secret']);
		}
		
		// POST Data
		if (isset ($options ['api_data']))
		{
			curl_setopt ($curl, CURLOPT_POSTFIELDS, $options ['api_data']);			
		}

		// Make request
		if (($http_data = curl_exec ($curl)) !== false)
		{
			$result->http_code = curl_getinfo ($curl, CURLINFO_HTTP_CODE);
			$result->http_data = $http_data;
			$result->http_error = null;
		}
		else
		{
			$result->http_code = - 1;
			$result->http_data = null;
			$result->http_error = curl_error ($curl);
		}

		// Done
		return $result;
	}
}
