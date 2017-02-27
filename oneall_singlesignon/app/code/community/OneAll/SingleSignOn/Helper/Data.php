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
	const USER_AGENT = 'SingleSignOn/1.0.0 Magento/1.x (+http://www.oneall.com/)';
	const ENABLE_LOGGING = true;

	/**
	 * Add a log to our log file.
	 */
	public function add_log ($contents, $level = null)
	{
		if (self::ENABLE_LOGGING)
		{
			Mage::log ($contents, $level, 'oneall_singlesignon.log');
		}
	}

	/**
	 * Return the extension settings.
	 */
	public function get_settings ()
	{
		$settings = array();
	
		// API Connection Handler.
		$settings ['connection_handler'] = (Mage::getStoreConfig ('oneall_singlesignon/connection/handler') == 'fsockopen' ? 'fsockopen' : 'curl');
		$settings ['connection_port'] = (Mage::getStoreConfig ('oneall_singlesignon/connection/port') == 80 ? 80 : 443);
		$settings ['connection_protocol'] = ($settings ['connection_port'] == 80 ? 'http' : 'https');
	
		// API Settings.
		$settings ['subdomain'] = trim (strval (Mage::getStoreConfig ('oneall_singlesignon/general/subdomain')));
		$settings ['key'] = trim (strval (Mage::getStoreConfig ('oneall_singlesignon/general/key')));
		$settings ['secret'] = trim (strval (Mage::getStoreConfig ('oneall_singlesignon/general/secret')));
	
		// Automatic Account Creation.
		$settings ['accounts_autocreate'] = (Mage::getStoreConfig ('oneall_singlesignon/accounts_create/automatic') == 0 ? false : true);
		$settings ['accounts_sendmail'] = (Mage::getStoreConfig ('oneall_singlesignon/accounts_create/sendmail') == 1 ? true : false);
	
		// Automatic Account Link.
		$settings ['accounts_autolink'] = (Mage::getStoreConfig ('oneall_singlesignon/accounts_link/automatic') == 0 ? false : true);
		$settings ['accounts_linkunverified'] = (Mage::getStoreConfig ('oneall_singlesignon/accounts_link/unverified') == 1 ? true : false);
	
		// SSO Session Settings.
		$settings ['session_lifetime'] = trim (strval (Mage::getStoreConfig ('oneall_singlesignon/settings/sessionlifetime')));
		$settings ['session_lifetime'] = ((empty ($settings ['session_lifetime']) || $settings ['session_lifetime'] < 0) ? 86400 : $settings ['session_lifetime']);
		$settings ['session_top_realm'] = trim (strval (Mage::getStoreConfig ('oneall_singlesignon/settings/sessiontoprealm')));
		$settings ['session_sub_realm'] = (empty ($settings ['session_top_realm']) ? '' : trim (strval (Mage::getStoreConfig ('oneall_singlesignon/settings/sessionsubrealm'))));
	
		// Helper Settings.
		$settings ['base_url'] = ($settings ['subdomain'] . '.api.oneall.loc');
		$settings ['api_url'] = ($settings ['connection_protocol'] . '://' . $settings ['base_url']);
	
		// Done
		return $settings;
	}
	
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
			$customer_id = $customer->getId ();
		}
		while ( !empty ($customer_id) );
		
		// Done
		return $email;
	}

	/**
	 * Hash a password.
	 */
	protected function hash_password ($password)
	{
		// Read settings.
		$ext_settings = $this->get_settings ();
			
		// We cannot make a connection without the subdomain.
		if ( ! empty ($ext_settings ['key']) && !empty ($ext_settings ['subdomain']))
		{
			return  sha1 ($ext_settings ['key'] . $password . $ext_settings ['subdomain']); 
		}
		
		// Error
		return null;
	}

	/**
	 * Remove a Single Sign-On session for the given identity_token.
	 */
	public function api_remove_session_for_identity_token ($identity_token)
	{
		// Result container.
		$status = new stdClass ();
		$status->action = null;
		$status->is_successfull = false;
	
		// We need the identity_token to remove the session.
		if (!empty ($identity_token))
		{
			// Read settings.
			$ext_settings = $this->get_settings ();
				
			// We cannot make a connection without the subdomain.
			if (!empty ($ext_settings ['subdomain']))
			{
				// API Endpoint: http://docs.oneall.com/api/resources/sso/identity/destroy-session/
				$api_resource_url = $ext_settings ['api_url'] . '/sso/sessions/identities/' . $identity_token . '.json?confirm_deletion=true';
	
				// API Options
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret']
				);
	
				// Delete Session.
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'DELETE', $api_options);
	
				// Check result.
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 200)
				{
					// Success
					$status->action = 'session_deleted';
					$status->is_successfull = true;
	
					// Add Log
					$this->add_log ('Session for identity_token [' . $identity_token . '] deleted');
				}
			}
			// Extension not setup
			else
			{
				$status->action = 'extension_not_setup';
			}
		}
	
		// Done
		return $status;
	}
	
	/**
	 * Remove a Single Sign-On session for the given sso_session_token.
	 */
	public function api_remove_session_for_sso_session_token ($sso_session_token)
	{
		// Result container.
		$status = new stdClass ();
		$status->action = null;
		$status->is_successfull = false;
		
		// We need the sso_session_token to remove the session.
		if (!empty ($sso_session_token))
		{
			// Read settings.
			$ext_settings = $this->get_settings ();
			
			// We cannot make a connection without the subdomain.
			if (!empty ($ext_settings ['subdomain']))
			{
				// API Endpoint: http://docs.oneall.com/api/resources/sso/delete-session/
				$api_resource_url = $ext_settings ['api_url'] . '/sso/sessions/' . $sso_session_token . '.json?confirm_deletion=true';
				
				// API Options
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret'] 
				);
				
				// Delete Session.
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'DELETE', $api_options);
				
				// Check result.
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 200)
				{
					// Success
					$status->action = 'session_deleted';
					$status->is_successfull = true;
				
					// Add Log
					$this->add_log ('Session for sso_session-token [' . $sso_session_token . '] deleted');
				}
			}
			// Extension not setup
			else
			{
				$status->action = 'extension_not_setup';
			}
		}
		
		// Done
		return $status;
	}

	/**
	 * Start a new Single Sign-On session for the given identity_token.
	 */
	public function api_start_session_for_identity_token ($identity_token)
	{
		// Result Container.
		$status = new stdClass ();
		$status->is_successfull = false;
		
		// We need the identity_token to create a session.
		if (!empty ($identity_token))
		{
			// Read settings.
			$ext_settings = $this->get_settings ();
			
			// We cannot make a connection without the subdomain.
			if (!empty ($ext_settings ['subdomain']))
			{
				// ////////////////////////////////////////////////////////////////////////////////////////////////
				// Start a new Single Sign-On Session
				// ////////////////////////////////////////////////////////////////////////////////////////////////
				
				// API Endpoint: http://docs.oneall.com/api/resources/sso/identity/start-session/
				$api_resource_url = $ext_settings ['api_url'] . '/sso/sessions/identities/' . $identity_token . '.json';
				
				// API Options.
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret'],
					'api_data' => @json_encode (array(
						'request' => array(
							'sso_session' => array(
								'top_realm' => $ext_settings ['session_top_realm'],
								'sub_realm' => $ext_settings ['session_sub_realm'],
								'lifetime' => $ext_settings ['session_lifetime'] 
							) 
						) 
					)) 
				);
				
				// Create Session
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'PUT', $api_options);
				
				// Check result. 201 Returned !!!
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 201 && property_exists ($result, 'http_data'))
				{
					// Decode result
					$decoded_result = @json_decode ($result->http_data);
					
					// Check result
					if (is_object ($decoded_result) && isset ($decoded_result->response->result->data->sso_session))
					{
						// Success
						$status->action = 'session_started';
						$status->sso_session_token = $decoded_result->response->result->data->sso_session->sso_session_token;
						$status->is_successfull = true;
						
						// Add Log
						$this->add_log ('[START SESSION] Session [' . $status->sso_session_token . '] started for identity [' . $identity_token . ']');
					}
				}
			}
			// Extension not setup
			else
			{
				$status->action = 'extension_not_setup';
			}
		}
		
		// Done
		return $status;
	}

	/**
	 * Update the given customer in the cloud storage.
	 */
	public function api_update_customer_cloud_storage ($user_token, $customer)
	{
		// Read settings
		$ext_settings = $this->get_settings ();
		
		// We cannot make a connection without a subdomain
		if (!empty ($ext_settings ['subdomain']))
		{
			// API Endpoint: http://docs.oneall.com/api/resources/storage/users/update-user/
			$api_resource_url = $ext_settings ['api_url'] . '/storage/users/' . $user_token . '.json';
			
			// API Options
			$api_options = array(
				'api_key' => $ext_settings ['key'],
				'api_secret' => $ext_settings ['secret'],
				'api_data' => @json_encode (array(
					'request' => array(
						'update_mode' => 'replace',
						'user' => array(
							'login' => $customer->getEmail () 
						) 
					) 
				)) 
			);
			
			// User Update
			$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
		}
	}

	/**
	 * Update the given customer's password in this cloud storage.
	 */
	public function api_update_customer_cloud_password ($customer, $password)
	{
		// Result Container.
		$status = new stdClass ();
		$status->password_updated = false;
		
		// Read settings.
		$ext_settings = $this->get_settings ();
		
		// We cannot make a connection without the subdomain.
		if (!empty ($ext_settings ['subdomain']))
		{
			// Read customer's tokens.
			$tokens = Mage::helper ('oneall_singlesignon')->get_local_storage_tokens_for_customer ($customer);
			
			// Without a token nothing can and needs to be done.
			if ($tokens->have_been_retrieved === true)
			{
				// API Endpoint: http://docs.oneall.com/api/resources/storage/users/update-user/
				$api_resource_url = $ext_settings ['api_url'] . '/storage/users/' . $tokens->user_token . '.json';
				
				// API Options.
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret'],
					'api_data' => @json_encode (array(
						'request' => array(
							'user' => array(
								'password' => $this->hash_password ($password) 
							) 
						) 
					)) 
				);
				
				// Update user.
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'PUT', $api_options);
				
				// Check result.
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 200)
				{
					// Update status.
					$status->action = 'customer_cloud_storage_password_updated';
					$status->password_updated = true;
						
					// Add Log
					$this->add_log ('Password for customer [' . $customer->getId () . '] updated in cloud storage');					
				}
			}
			// No cloud storage user
			else
			{
				$status->action = 'customer_not_in_cloud_storage';
			}
		}
		// Extension not setup
		else
		{
			$status->action = 'extension_not_setup';
		}
		
		// Done
		return $status;
	}

	/**
	 * Check if a given customer has a cloud storage account and if the given password is valid for it
	 */
	public function api_check_customer_cloud_password ($customer, $password)
	{
		// Result Container.
		$status = new stdClass ();
		$status->is_valid = false;
		
		// Read settings.
		$ext_settings = $this->get_settings ();
		
		// We cannot make a connection without the subdomain.
		if (!empty ($ext_settings ['subdomain']))
		{
			// Read customer's tokens.
			$tokens = Mage::helper ('oneall_singlesignon')->get_local_storage_tokens_for_customer ($customer);
			
			// Without a token nothing can and needs to be done.
			if ($tokens->have_been_retrieved === true)
			{
				// API Endpoint: http://docs.oneall.com/api/resources/storage/users/lookup-user/
				$api_resource_url = $ext_settings ['api_url'] . '/storage/users/user/lookup.json';
				
				// API Options.
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret'],
					'api_data' => @json_encode (array(
						'request' => array(
							'user' => array(
								'user_token' => $tokens->user_token,
								'password' => $this->hash_password ($password), 
							) 
						) 
					)) 
				);
				
				// User Lookup.
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
				
				// Check result
				if (is_object ($result) && property_exists ($result, 'http_code') && $result->http_code == 200 && property_exists ($result, 'http_data'))
				{
					// Decode result.
					$decoded_result = @json_decode ($result->http_data);
					
					// Check result.
					if (is_object ($decoded_result) && isset ($decoded_result->response->result->data->user))
					{
						$status->action = 'customer_cloud_storage_valid_password';
						$status->is_valid = true;
						
						// Add Log
						$this->add_log ('Customer [' . $customer->getId () . '] has entered correct cloud storage password for user_token [' . $tokens->user_token . ']');
					}
				}
			}
			// No cloud storage user
			else
			{
				$status->action = 'customer_not_in_cloud_storage';
				
				// Add Log
				$this->add_log ('Customer [' . $customer->getId () . '] has no cloud storage identity');
			}
		}
		// Extension not setup
		else
		{
			$status->action = 'extension_not_setup';
		}
		
		// Done
		return $status;
	}

	/**
	 * Try to login a customer using his cloud data.
	 */
	public function try_customer_cloud_login ($email, $password)
	{
		// Result Container
		$status = new stdClass ();
		$status->is_successfull = false;
		
		// Read settings.
		$ext_settings = $this->get_settings ();
		
		// We cannot make a connection without the subdomain.
		if (!empty ($ext_settings ['subdomain']))
		{
			// Try to load customer.
			$customer = Mage::getModel ('customer/customer');
			$customer->setWebsiteId (Mage::app ()->getWebsite ()->getId ());
			$customer->loadByEmail ($email);
			$customer_id = $customer->getId ();
			
			// Customer found.
			if (!empty ($customer_id))
			{
				// Read tokens of this customer.
				$user = Mage::getModel ('oneall_singlesignon/user')->load ($customer_id, 'customer_id');
				$user_token = $user->getData ('user_token');
				
				// This is a cloud user.
				if (!empty ($user_token))
				{
					// API Endpoint: http://docs.oneall.com/api/resources/storage/users/lookup-user/
					$api_resource_url = $ext_settings ['api_url'] . '/storage/users/user/lookup.json';
					
					// API Options.
					$api_options = array(
						'api_key' => $ext_settings ['key'],
						'api_secret' => $ext_settings ['secret'],
						'api_data' => @json_encode (array(
							'request' => array(
								'user' => array(
									'user_token' => $user_token,
									'password' => $this->hash_password ($password) 
								) 
							) 
						)) 
					);
					
					// User Lookup.
					$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
					
					// Check result
					if (is_object ($result) and property_exists ($result, 'http_code'))
					{
						// Wrong password entered.
						if ($result->http_code == 401)
						{
							// Add Log
							$this->add_log ('Login with [' . $email . '] failed, customer [' . $customer_id . '] has entered wrong cloud password.');
						}
						// Correct password entered.
						elseif ($result->http_code == 200)
						{
							// Decode result.
							$decoded_result = @json_decode ($result->http_data);
							
							// Check result.
							if (is_object ($decoded_result) && isset ($decoded_result->response->result->data->user))
							{
								// Add Log.
								$this->add_log ('Login with [' . $email . '] succeeded, customer [' . $customer_id . '] has user_token [' . $user_token . ']');
								
								// Login.
								Mage::getSingleton ('customer/session')->loginById ($customer_id);
								
								// Success
								$status->is_successfull = true;
							}
						}
					}
				}
				else
				{
					// Add Log
					$this->add_log ('Login with [' . $email . '] failed, customer [' . $customer_id . '] has no cloud identity.');
				}
			}
			else
			{
				// Add Log
				$this->add_log ('Login with [' . $email . '] failed, no such customer.');
			}
		}
		
		// Done
		return $status;
	}

	/**
	 * Add a customer to the cloud storage.
	 */
	public function api_add_customer_to_cloud_storage ($customer, $email = null, $password = null)
	{
		// Result Container
		$status = new stdClass ();
		$status->is_successfull = false;
		$status->identity_token = null;
		$status->user_token = null;
		
		// Read settings
		$ext_settings = $this->get_settings ();
		
		// We cannot make a connection without the subdomain.
		if (!empty ($ext_settings ['subdomain']))
		{
			// Add Log
			$this->add_log ('Adding customer [' . $customer->getId () . '] to cloud storage');
			
			// ////////////////////////////////////////////////////////////////////////////////////////////////
			// First make sure that we don't create duplicate users!
			// ////////////////////////////////////////////////////////////////////////////////////////////////
			
			// API Endpoint: http://docs.oneall.com/api/resources/storage/users/lookup-user/
			$api_resource_url = $ext_settings ['api_url'] . '/storage/users/user/lookup.json';
			
			// API Options
			$api_options = array(
				'api_key' => $ext_settings ['key'],
				'api_secret' => $ext_settings ['secret'],
				'api_data' => @json_encode (array(
					'request' => array(
						'user' => array(
							'login' => $customer->getEmail () 
						) 
					) 
				)) 
			);
			
			// User Lookup
			$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
			
			// Check result.
			if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200 and property_exists ($result, 'http_data'))
			{
				// Decode result.
				$decoded_result = @json_decode ($result->http_data);
				
				// Check data.
				if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
				{
					// Update status.
					$status->action = 'existing_user_read';
					$status->is_successfull = true;
					$status->user_token = $decoded_result->response->result->data->user->user_token;
					$status->identity_token = $decoded_result->response->result->data->user->identity->identity_token;
					
					// Add Log.
					$this->add_log ('Email [' . $customer->getEmail () . '] found in cloud storage, user_token [' . $status->user_token . '] and identity_token [' . $status->identity_token . '] assigned');
					
					// Done.
					return $status;
				}
			}
			
			// ////////////////////////////////////////////////////////////////////////////////////////////////
			// If we are getting here, then a new identity needs to be added
			// ////////////////////////////////////////////////////////////////////////////////////////////////
			
			// Customer Name.
			$customer_name = array(
				'honorificPrefix' => strval ($customer->getPrefix ()),
				'givenName' => strval ($customer->getFirstname ()),
				'middleName' => strval ($customer->getMiddlename ()),
				'familyName' => strval ($customer->getLastname ()),
				'honorificSuffix' => strval ($customer->getSuffix ()) 
			);
			
			// Customer Email.
			$customer_emails = array(
				array(
					'value' => $customer->getEmail (),
					'is_verified' => $customer->getCustomerActivated () 
				) 
			);
			
			// Customer Account.
			$customer_accounts = array(
				array(
					'domain' => Mage::getBaseUrl (),
					'userid' => $customer->getId () 
				) 
			);
			
			// Customer Addresses.
			$customer_addresses = array();
			
			// Customer Address
			foreach (array('billing', 'shipping') as $type)
			{
				$getter = 'getPrimary' . ucfirst (strtolower ($type)) . 'Address';
				$address = $customer->$getter ();
				$address_id = $address->getId ();
				
				if (!empty ($address_id))
				{
					$customer_addresses [] = array(
						'type' => $type,
						'companyName' => strval ($address->getCompany ()),
						'firstName' => strval ($address->getFirstname ()),
						'middleName' => strval ($address->getMiddlename ()),
						'lastName' => strval ($address->getLastname ()),
						'phoneNumber' => strval ($address->getTelephone ()),
						'faxNumber' => strval ($address->getFax ()),
						'streetAddress' => strval ($address->getStreet (1)),
						'complement' => strval ($address->getStreet (2)),
						'locality' => strval ($address->getCity ()),
						'region' => strval ($address->getRegion ()),
						'postalCode' => strval ($address->getPostcode ()),
						'code' => strval ($address->getCountry_id ()) 
					);
				}
			}
			
			// API Endpoint: http://docs.oneall.com/api/resources/storage/users/create-user/
			$api_resource_url = $ext_settings ['api_url'] . '/storage/users.json';
			
			// API Options.
			$api_options = array(
				'api_key' => $ext_settings ['key'],
				'api_secret' => $ext_settings ['secret'],
				'api_data' => @json_encode (array(
					'request' => array(
						'user' => array(
							'login' => $customer->getEmail (),
							'password' => $this->hash_password ($password),
							'identity' => array(
								'name' => $customer_name,
								'emails' => $customer_emails,
								'accounts' => $customer_accounts,
								'addresses' => $customer_addresses 
							) 
						) 
					) 
				)) 
			);
									
			// Add User.
			$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'POST', $api_options);
			
			// Check result. 201 Returned !!!
			if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 201 and property_exists ($result, 'http_data'))
			{
				// Decode result.
				$decoded_result = @json_decode ($result->http_data);
				
				// Check data.
				if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
				{
					// Update status.
					$status->action = 'new_user_created';
					$status->is_successfull = true;
					$status->user_token = $decoded_result->response->result->data->user->user_token;
					$status->identity_token = $decoded_result->response->result->data->user->identity->identity_token;
					
					// Add Log.
					$this->add_log ('Customer [' . $customer->getId () . '] added to cloud storage, user_token [' . $status->user_token . '] and identity_token [' . $status->identity_token . '] assigned');
					
					// Done.
					return $status;
				}
			}
		}
		
		// Error.
		return $status;
	}

	/**
	 * Remove the single sign-on session for the given customer.
	 */
	public function remove_session_for_customer ($customer)
	{
		// Result Container.
		$status = new stdClass ();
		$status->is_successfull = false;
		
		// Read the session of this customer.
		$session = Mage::getModel ('oneall_singlesignon/session')->load ($customer->getId (), 'customer_id');
		$sso_session_token = $session->getData ('sso_session_token');
		$identity_token = $session->getData ('identity_token');
		
		// Session found.
		if (!empty ($sso_session_token))
		{
			// Remove session from database.
			$session->delete ();
			
			// Remove session from cloud.
			$remove_session = $this->api_remove_session_for_identity_token ($identity_token);
			
			// Remove session from cloud (This one should not be necessary as already covered above)
			// $remove_session = $this->api_remove_session_for_sso_session_token ($sso_session_token);
						
			// Success.
			$status->is_successfull = true;
		}
		
		// Done.
		return $status;
	}

	/**
	 * Add the cloud storage tokens of a customer to the local database.
	 */
	public function add_local_storage_tokens_for_customer ($customer, $user_token, $identity_token)
	{
		// Result Container.
		$status = new stdClass ();
		$status->have_been_added = false;
		
		// Verify customer object.
		if (is_object ($customer) && $customer->getId ())
		{
			// Save customer's tokens.
			$model = Mage::getModel ('oneall_singlesignon/user')->load ($customer->getId (), 'customer_id');
			$model->setData ('customer_id', $customer->getId ());
			$model->setData ('user_token', $user_token);
			$model->setData ('identity_token', $identity_token);
			$model->save ();
			
			// Update Status.
			$status->identity_token = $model->getData ('identity_token');
			$status->user_token = $model->getData ('user_token');
			$status->have_been_added = true;
		}
		
		// Done
		return $status;
	}

	/**
	 * Return the cloud storage tokens of a customer stored in the local database.
	 */
	public function get_local_storage_tokens_for_customer ($customer)
	{
		// Result Container
		$status = new stdClass ();
		$status->have_been_retrieved = false;
		
		// Verify customer object
		if (is_object ($customer))
		{
			// Load customer's tokens.
			$model = Mage::getModel ('oneall_singlesignon/user')->load ($customer->getId (), 'customer_id');
			$customer_id = $model->getData ('customer_id');
			
			// Tokens found.
			if (!empty ($customer_id))
			{
				// Update Status.
				$status->identity_token = $model->getData ('identity_token');
				$status->user_token = $model->getData ('user_token');
				$status->have_been_retrieved = true;
			}
		}
		
		// Done
		return $status;
	}

	/**
	 * Open a new single sign-on session for the given customer
	 */
	public function create_session_for_customer ($customer, $email = null, $password = null)
	{
		// Result Container
		$status = new stdClass ();
		$status->is_successfull = false;
	
		// Read customer's tokens.
		$tokens = Mage::helper ('oneall_singlesignon')->get_local_storage_tokens_for_customer ($customer);
		
		// Customer has no tokens yet.
		if (!$tokens->have_been_retrieved)
		{
			// Add Log.
			$this->add_log ('[CREATE SESSION] Customer [' . $customer->getId () . '] has no tokens yet. Creating tokens now.');
			
			// Add customer to cloud storage.
			$add_customer = $this->api_add_customer_to_cloud_storage ($customer, $email, $password);
			
			// Customer added.
			if ($add_customer->is_successfull === true)
			{
				// Update Status
				$status->identity_token = $add_customer->identity_token;
				$status->user_token = $add_customer->user_token;
				
				// Add Log.
				$this->add_log ('[CREATE SESSION] Tokens for customer [' . $customer->getId () . '] created: user_token ['.$status->user_token.'], identity_token ['.$status->identity_token.']');
				
				// Add to database.
				$add_tokens = Mage::helper ('oneall_singlesignon')->add_local_storage_tokens_for_customer ($customer, $status->user_token, $status->identity_token);
			}
		}
		// Customer has already tokens.
		else
		{
			// Update Status.
			$status->identity_token = $tokens->identity_token;
			$status->user_token = $tokens->user_token;
			
			// Add Log.
			$this->add_log ('[CREATE SESSION] Customer [' . $customer->getId () . '] has already tokens: user_token ['.$status->user_token.'], identity_token ['.$status->identity_token.']');
		}
		
		// Start Session
		if ( ! empty ($status->identity_token))
		{
			// Add Log.
			$this->add_log ('[CREATE SESSION] Starting session for customer [' . $customer->getId () . '] with identity_token ['.$status->identity_token.']');
						
			// Start a new session.
			$start_session = $this->api_start_session_for_identity_token ($status->identity_token);
			
			// Session started.
			if ($start_session->is_successfull === true)
			{
				// Update Status
				$status->sso_session_token = $start_session->sso_session_token;
				$status->is_successfull = true;
				
				// Add Log.
				$this->add_log ('[CREATE SESSION] Session ['.$status->sso_session_token .'] for customer [' . $customer->getId () . '] started');
				
				// Create or update session data.
				$session = Mage::getModel ('oneall_singlesignon/session')->load ($customer->getId (), 'customer_id');
				$session->setData ('customer_id', $customer->getId ());
				$session->setData ('sso_session_token', $status->sso_session_token );
				$session->setData ('identity_token', $status->identity_token);
				$session->save ();
			}
		}
		
		// Created session
		return $status;
	}

	/**
	 * Check if a login is being made over SSO (Callback Handler).
	 */
	public function check_for_sso_login ()
	{
		// Result Container.
		$status = new stdClass ();
		
		// Read URL parameters.
		$action = strtolower (trim (strval (Mage::app ()->getRequest ()->getParam ('oa_action'))));
		$connection_token = Mage::app ()->getRequest ()->getParam ('connection_token');
		
		// Callback Handler.
		if ($action == 'single_sign_on' and !empty ($connection_token))
		{
			// Add Log
			$this->add_log ('[SSO Callback] Callback for connection_token [' . $connection_token . '] detected');
			
			// Read settings
			$ext_settings = $this->get_settings ();
			
			// We cannot make a connection without a subdomain
			if (!empty ($ext_settings ['subdomain']))
			{
				// See: http://docs.oneall.com/api/resources/connections/read-connection-details/
				$api_resource_url = $ext_settings ['api_url'] . '/connections/' . $connection_token . '.json';
				
				// API options.
				$api_options = array(
					'api_key' => $ext_settings ['key'],
					'api_secret' => $ext_settings ['secret'] 
				);
				
				// Read connection details.
				$result = $this->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'GET', $api_options);
				
				// Check result.
				if (is_object ($result) and property_exists ($result, 'http_code') and $result->http_code == 200 and property_exists ($result, 'http_data'))
				{
					// Decode result.
					$decoded_result = @json_decode ($result->http_data);
					
					// Check data.
					if (is_object ($decoded_result) and isset ($decoded_result->response->result->data->user))
					{
						// Extract user data.
						$data = $decoded_result->response->result->data;
						
						// The user_token uniquely identifies the user.
						$user_token = $data->user->user_token;
						
						// The identity_token uniquely identifies the user's data.
						$identity_token = $data->user->identity->identity_token;
						
						// Add Log.
						$this->add_log ('[SSO Callback] Token user_token [' . $user_token . '] / identity_token [' . $identity_token . '] retrieved or connection_token [' . $connection_token . ']');
						
						// Check if we have a customer for this user_token.
						$user = Mage::getModel ('oneall_singlesignon/user')->load ($user_token, 'user_token');
						$customer_id = $user->getData ('customer_id');
						
						// Customer found.
						if (!empty ($customer_id))
						{
							// Load customer.
							$customer = Mage::getModel ('customer/customer')->load ($customer_id);
							
							// Customer no longer exists.
							if (!$customer->getId ())
							{
								// Add Log.
								$this->add_log ('[SSO Callback] Removing orphan customer_id [' . $customer_id . '] for user_token [' . $user_token . ']');
								
								// Cleanup our table.
								$user->delete ();
								
								// Reset customer id.
								$customer_id = null;
							}
							// Customer exists.
							else
							{
								// Add Log.
								$this->add_log ('[SSO Callback] Customer [' . $customer_id . '] logged in for user_token [' . $user_token . ']');
								
								// Update (This is just to make sure that the table is always correct).
								$user->setData ('identity_token', $identity_token);
								$user->save ();
								
								// Login.
								Mage::getSingleton ('customer/session')->loginById ($customer_id);
								
								// Update status.
								$status->action = 'existing_user_login_user_token';
								$status->user_token = $user_token;
								$status->identity_token = $identity_token;
								$status->customer = $customer;
								
								// Done.
								return $status;
							}
						}
						
						// Add Log.
						$this->add_log ('[SSO Callback] No customer found for user_token [' . $user_token . ']. Trying email lookup.');						
						
						// Retrieve email from identity.
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
							if (!empty ($customer_id))
							{
								// Add Log.
								$this->add_log ('[SSO Callback] Customer [' . $customer_id . '] found for email [' . $email . ']');
								
								// Automatic Link is disabled.
								if ($ext_settings ['accounts_autolink'] == false)
								{
									// Add Log.
									$this->add_log ('[SSO Callback] Autolink disabled. Cannot link user_token [' . $user_token . '] to customer [' . $customer_id . ']');
									
									// Update Status.
									$status->action = 'existing_user_no_login_autolink_off';
									$status->customer = $customer;
								}
								// Automatic Link is enabled.
								else
								{
									// The email has been verified.
									if ($email_verified)
									{
										// Add Log.
										$this->add_log ('[SSO Callback] [Verified] Autolink enabled/Email verified. Linking user_token [' . $user_token . '] to customer [' . $customer_id . ']');
										
										// Add to database.
										$add_tokens = Mage::helper ('oneall_singlesignon')->add_local_storage_tokens_for_customer ($customer, $user_token, $identity_token);
										
										// Login.
										Mage::getSingleton ('customer/session')->loginById ($customer_id);
										
										// Update Status.
										$status->action = 'existing_user_login_email_verified';
										$status->user_token = $user_token;
										$status->identity_token = $identity_token;
										$status->customer = $customer;
									}
									// The email has NOT been verified.
									else
									{
										// We can use unverified emails.
										if ($ext_settings ['accounts_linkunverified'] == true)
										{
											// Add Log.
											$this->add_log ('[SSO Callback] [Unverified] Autolink enabled/Unverified email allowed. Linking user_token [' . $user_token . '] to customer [' . $customer_id . ']');
											
											// Add to database.
											$add_tokens = Mage::helper ('oneall_singlesignon')->add_local_storage_tokens_for_customer ($customer, $user_token, $identity_token);
											
											// Login.
											Mage::getSingleton ('customer/session')->loginById ($customer_id);
											
											// Update Status.
											$status->action = 'existing_user_login_email_unverified';
											$status->user_token = $user_token;
											$status->identity_token = $identity_token;
											$status->customer = $customer;
										}
										// We cannot use unverified emails.
										else
										{
											// Add Log.
											$this->add_log ('[SSO Callback] [Unverified] Autolink enabled/Unverified email not allowed. Cannot link user_token [' . $user_token . '] to customer [' . $customer_id . ']');
											
											// Update Status.
											$status->action = 'existing_user_no_login_autolink_off_unverified_emails';
											$status->user_token = $user_token;
											$status->identity_token = $identity_token;
											$status->customer = $customer;
										}
									}
								}
								
								// Done
								return $status;
							}
							// No customer found
							else
							{
								// Add Log
								$this->add_log ('[SSO Callback] No customer found for email [' . $email . ']');
							}
						}
						else
						{
							// Create Random email.
							$email = $this->create_random_email ();
							$email_is_random = true;
							
							// Add Log.
							$this->add_log ('[SSO Callback] Email lookup failed, identity provides no email address. Random address ['.$email.'] generated.');
						}
						
						// /////////////////////////////////////////////////////////////////////////
						// This is a new user
						// /////////////////////////////////////////////////////////////////////////
						
						// We cannot create new accounts
						if ($ext_settings ['accounts_autocreate'] === false)
						{
							// Add Log
							$this->add_log ('[SSO Callback] New user, but account creation disabled. Cannot create customer for user_token [' . $user_token . ']');
							
							// Update Status
							$status->action = 'new_user_no_login_autocreate_off';
							
							// Done
							return $status;
						}
						else
						{
							// Add Log
							$this->add_log ('[SSO Callback] New user, account creation enabled. Creating customer for user_token [' . $user_token . ']');
						}
						
						// Create a new customer.
						$customer = Mage::getModel ('customer/customer');
						
						// Generate a password for the customer.
						$password = $customer->generatePassword (8);
						
						// First Name
						$first_name = 'unknown';
						if (!empty ($data->user->identity->name->givenName))
						{
							$first_name = $data->user->identity->name->givenName;
						}
						else if (!empty ($data->user->identity->displayName))
						{
							$names = explode (' ', $data->user->identity->displayName);
							$first_name = $names [0];
						}
						else if (!empty ($data->user->identity->name->formatted))
						{
							$names = explode (' ', $data->user->identity->name->formatted);
							$first_name = $names [0];
						}
						
						// Last Name
						$last_name = 'unknown';
						if (!empty ($data->user->identity->name->familyName))
						{
							$last_name = $data->user->identity->name->familyName;
						}
						else if (!empty ($data->user->identity->displayName))
						{
							$names = explode (' ', $data->user->identity->displayName);
							if (!empty ($names [1]))
							{
								$last_name = $names [1];
							}
						}
						else if (!empty ($data->user->identity->name->formatted))
						{
							$names = explode (' ', $data->user->identity->name->formatted);
							if (!empty ($names [1]))
							{
								$last_name = $names [1];
							}
						}
						
						// Customer Details.
						$customer->setFirstname ($first_name);
						$customer->setLastname ($last_name);
						$customer->setEmail ($email);
						$customer->setPassword ($password);
						$customer->setPasswordConfirmation ($password);
						
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
						
						// Confirm (The two saves are necessary).
						$customer->setConfirmation (null);
						$customer->save ();
						
						// Add log.
						$this->add_log ('[SSO Callback] New user, customer [' . $customer->getId () . '] created for user_token [' . $user_token . ']');
						
						// Do we have any addresses?
						if (isset ($data->user->identity->addresses) && is_array ($data->user->identity->addresses))
						{
							foreach ($data->user->identity->addresses as $address)
							{
								if (isset ($address->type) && in_array ($address->type, array('billing', 'shipping')))
								{
									try
									{
										// Address Data.
										$address_data = array(
											'company' => (isset ($address->companyName) ? $address->companyName : null),
											'firstname' => (isset ($address->firstName) ? $address->firstName : $customer->getFirstname ()),
											'middlename' => (isset ($address->middleName) ? $address->middleName : $customer->getMiddlename ()),
											'lastname' => (isset ($address->lastName) ? $address->lastName : $customer->getLastname ()),
											'telephone' => (isset ($address->phoneNumber) ? $address->phoneNumber : null),
											'fax' => (isset ($address->faxNumber) ? $address->faxNumber : null),
											'street' => array(
												'0' => (isset ($address->streetAddress) ? $address->streetAddress : null),
												'1' => (isset ($address->complement) ? $address->complement : null) 
											),
											'city' => (isset ($address->locality) ? $address->locality : null),
											'region' => (isset ($address->region) ? $address->region : null),
											'postcode' => (isset ($address->postalCode) ? $address->postalCode : null),
											'country_id' => (isset ($address->code) ? $address->code : null) 
										);
										
										// Add for customer.
										$customer_address = Mage::getModel ('customer/address');
										$customer_address->setData ($address_data);
										$customer_address->setCustomerId ($customer->getId ());
										
										if ($address->type == 'billing')
										{
											$customer_address->setIsDefaultBilling (1);
										}
										else
										{
											$customer_address->setIsDefaultShipping (1);
										}
										
										$customer_address->setSaveInAddressBook (1);
										$customer_address->save ();
										
										// Add Log.
										$this->add_log ('[SSO Callback] ' . ucfirst ($address->type) . ' address [' . $customer_address->getId () . '] added for customer [' . $customer->getId () . ']');
									}
									catch (Exception $e)
									{
									}
								}
							}
						}
						
						// Send registration email?
						if ($ext_settings ['accounts_sendmail'])
						{
							// We cannot send emails to random email addresses.
							if (!$email_is_random)
							{
								// Send Email.
								$customer->sendNewAccountEmail ('registered');
								
								// Add log.
								$this->add_log ('[SSO Callback] New user, registration email send to customer [' . $customer->getId () . ']');
							}
						}
						
						// Add customer tokens to database.
						$add_tokens = Mage::helper ('oneall_singlesignon')->add_local_storage_tokens_for_customer ($customer, $user_token, $identity_token);
						
						// Login customer.
						Mage::getSingleton ('customer/session')->loginById ($customer->getId ());
						
						// Update status.
						$status->action = 'new_user_login';
						$status->identity_token = $identity_token;
						$status->customer = $customer;
						
						// Done.
						return $status;
					}
				}
			}
		}
		
		// Update status.
		$status->action = 'no_callback_data_received';
		
		// Done.
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
			$disabled_functions = array();
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
			if (!in_array ('fsockopen', $disabled_functions) and !in_array ('fwrite', $disabled_functions))
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
	public function do_fsockopen_request ($url, $method = 'GET', $options = array(), $timeout = 15)
	{
		// Store the result
		$result = new stdClass ();
		
		// Make sure that this is a valid URL
		if (($uri = parse_url ($url)) == false)
		{
			$result->http_code = -1;
			$result->http_data = null;
			$result->http_error = 'invalid_uri';
			return $result;
		}
		
		// Make sure that we can handle the scheme
		switch ($uri ['scheme'])
		{
			case 'http' :
				$port = (isset ($uri ['port']) ? $uri ['port'] : 80);
				$host = ($uri ['host'] . ($port != 80 ? ':' . $port : ''));
				$fp = @fsockopen ($uri ['host'], $port, $errno, $errstr, $timeout);
			break;
			
			case 'https' :
				$port = (isset ($uri ['port']) ? $uri ['port'] : 443);
				$host = ($uri ['host'] . ($port != 443 ? ':' . $port : ''));
				$fp = @fsockopen ('ssl://' . $uri ['host'], $port, $errno, $errstr, $timeout);
			break;
			
			default :
				$result->http_code = -1;
				$result->http_data = null;
				$result->http_error = 'invalid_schema';
				return $result;
			break;
		}
		
		// Make sure that the socket has been opened properly
		if (!$fp)
		{
			$result->http_code = -$errno;
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
		
		// Send request headers.
		fwrite ($fp, strtoupper ($method) . " " . $path . " HTTP/1.1\r\n");
		fwrite ($fp, "Host: " . $host . "\r\n");
		fwrite ($fp, "User-Agent: " . self::USER_AGENT . "\r\n");
		
		// Add POST data ?
		if (isset ($options ['api_data']) && ! empty ($options ['api_data']))
		{
			fwrite($fp, "Content-length: ". strlen($options ['api_data']) ."\r\n");
		}
		
		// Enable basic authentication?
		if (isset ($options ['api_key']) && isset ($options ['api_secret']))
		{
			fwrite ($fp, "Authorization: Basic " . base64_encode ($options ['api_key'] . ":" . $options ['api_secret'])."\r\n");
		}
		
		// Close request.
		fwrite ($fp, "Connection: close\r\n\r\n");
		
		// Add POST data ?
		if (isset ($options ['api_data']))
		{
			fwrite ($fp, $options ['api_data']);
		}
				
		// Fetch response
		$response = '';
		while ( !feof ($fp) )
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
	 * Check if CURL has been loaded and is not disabled.
	 */
	public function is_curl_available ()
	{
		// Make sure CURL has been loaded.
		if (in_array ('curl', get_loaded_extensions ()) and function_exists ('curl_init') and function_exists ('curl_exec'))
		{
			// Read the disabled functions.
			$disabled_functions = $this->get_disabled_php_functions ();
			
			// Make sure CURL has not been disabled.
			if (!in_array ('curl_init', $disabled_functions) and !in_array ('curl_exec', $disabled_functions))
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
	public function do_curl_request ($url, $method = 'GET', $options = array(), $timeout = 15)
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
		curl_setopt ($curl, CURLOPT_USERAGENT, self::USER_AGENT);
		
		// HTTP Method
		switch (strtoupper ($method))
		{
			case 'DELETE' :
				curl_setopt ($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
			break;
			
			case 'PUT' :
				curl_setopt ($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
			break;
			
			case 'POST' :
				curl_setopt ($curl, CURLOPT_POST, 1);
			break;
			
			default :
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
			$result->http_code = -1;
			$result->http_data = null;
			$result->http_error = curl_error ($curl);
		}
		
		// Done
		return $result;
	}
}
