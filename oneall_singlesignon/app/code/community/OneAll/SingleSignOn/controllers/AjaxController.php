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
class OneAll_SingleSignOn_AjaxController extends Mage_Core_Controller_Front_Action
{
	// Autodetect API Handler
	public function indexAction ()
	{
		// Check if CURL is available
		if (Mage::helper ('oneall_singlesignon')->is_curl_available ())
		{
			// Check CURL HTTPS - Port 443
			if (Mage::helper ('oneall_singlesignon')->is_api_connection_curl_ok (true) === true)
			{
				die ('success_autodetect_api_curl_https');
			}
			// Check CURL HTTP - Port 80
			elseif (Mage::helper ('oneall_singlesignon')->is_api_connection_curl_ok (false) === true)
			{
				die ('success_autodetect_api_curl_http');
			}
			else
			{
				die ('error_autodetect_api_curl_ports_blocked');
			}
		}
		// Check if FSOCKOPEN is available
		elseif (Mage::helper ('oneall_singlesignon')->is_fsockopen_available ())
		{
			// Check FSOCKOPEN HTTPS - Port 443
			if (Mage::helper ('oneall_singlesignon')->is_api_connection_fsockopen_ok (true) == true)
			{
				die ('success_autodetect_api_fsockopen_https');
			}
			// Check FSOCKOPEN HTTP - Port 80
			elseif (Mage::helper ('oneall_singlesignon')->is_api_connection_fsockopen_ok (false) == true)
			{
				die ('success_autodetect_api_fsockopen_http');
			}
			else
			{
				die ('error_autodetect_api_fsockopen_ports_blocked');
			}
		}
		
		// No working handler found
		die ('error_autodetect_api_no_handler');
	}
	
	// Verify API Settings
	public function verifyAction ()
	{
		// Build settings.
		$ext_settings = array();
		
		// API Credentials.
		$ext_settings ['subdomain'] = trim (Mage::app ()->getRequest ()->getParam ('api_subdomain'));
		$ext_settings ['key'] = trim (Mage::app ()->getRequest ()->getParam ('api_key'));
		$ext_settings ['secret'] = trim (Mage::app ()->getRequest ()->getParam ('api_secret'));
		
		// API Connection Handler.
		$ext_settings ['connection_handler'] = (trim (Mage::app ()->getRequest ()->getParam ('api_connection_handler')) == 'fsockopen' ? 'fsockopen' : 'curl');
		$ext_settings ['connection_port'] = (trim (Mage::app ()->getRequest ()->getParam ('api_connection_port')) == '80' ? 80 : 443);
		$ext_settings ['connection_protocol'] = ($ext_settings ['connection_port'] == 80 ? 'http' : 'https');
		
		
		// Fields missing.
		if (empty ($ext_settings ['subdomain']) || empty ($ext_settings ['key']) || empty ($ext_settings ['secret']))
		{
			die ('error_not_all_fields_filled_out');
		}
		
		// Full domain entered.
		if (preg_match ("/([a-z0-9\-]+)\.api\.oneall\.com/i", $ext_settings ['subdomain'], $matches))
		{
			$ext_settings ['subdomain'] = $matches [1];
		}
		
		// Check subdomain format
		if (!preg_match ("/^[a-z0-9\-]+$/i", $ext_settings ['subdomain']))
		{
			die ('error_subdomain_wrong_syntax');
		}
		
		// Domain
		$ext_settings ['base_url'] = ($ext_settings ['subdomain'] . '.api.oneall.loc');
		$ext_settings ['api_url'] = ($ext_settings ['connection_protocol'] . '://' . $ext_settings ['base_url']);
		
		// API Endpoint
		$api_resource_url = $ext_settings ['api_url'] . '/site.json';
		
		// API Options
		$api_options = array(
			'api_key' => $ext_settings ['key'],
			'api_secret' => $ext_settings ['secret'] 
		);
		
		// Ping.
		$result = Mage::helper ('oneall_singlesignon')->do_api_request ($ext_settings ['connection_handler'], $api_resource_url, 'GET', $api_options);
		
		// Check result.
		if (is_object ($result) && property_exists ($result, 'http_code'))
		{
			switch ($result->http_code)
			{
				// Success
				case 200 :
					if (property_exists ($result, 'http_data'))
					{
						// Decode result
						$decoded_result = @json_decode ($result->http_data);
							
						// Check result
						if (is_object ($decoded_result) && isset ($decoded_result->response->result->data->site))
						{
							// Site Details
							$site = $decoded_result->response->result->data->site;

							// Check if our plans has the cloud storage
							if (empty ($site->subscription_plan->features->has_single_signon))
							{
								die ('error_plan_has_no_single_signon');
							}
							// Success
							else
							{
								die ('success');
							}
						}
					}
				break;
				
				// Authentication Error
				case 401 :
					die ('error_authentication_credentials_wrong');
				break;
					
				// Wrong Subdomain
				case 404 :
					die ('error_subdomain_wrong');
				break;
			}
		}
		
		die ('error_communication');
	}
}