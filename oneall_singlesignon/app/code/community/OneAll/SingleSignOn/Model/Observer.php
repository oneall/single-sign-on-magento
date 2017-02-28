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

// Single Sign-On Observer
class OneAll_SingleSignOn_Model_Observer
{
	// Fired whenever a customer is saved.
	public function customer_save_after ($observer)
	{
		// Load Customer.
		$customer = $observer->getCustomer ();
		$customer_id = $customer->getId ();
		
		// Customer found.
		if (!empty ($customer_id))
		{
			// Where are we now?
			$page_tag = trim (strtolower (Mage::app ()->getFrontController ()->getAction ()->getFullActionName ('_')));
			switch ($page_tag)
			{
				// Customer is resetting his password.
				case 'customer_account_resetpasswordpost' :
					
					// Read customer's tokens.
					$tokens = Mage::helper ('oneall_singlesignon')->get_local_storage_tokens_for_customer ($customer);
					
					// If we don't have a token, nothing needs to be done
					if ($tokens->have_been_retrieved === true)
					{						
						// Get password details.
						$password_frm_new = Mage::app ()->getRequest ()->getParam ('password');
						$password_frm_confirm = Mage::app ()->getRequest ()->getParam ('confirmation');
						
						// Make sure the passwords match.
						if ($password_frm_new == $password_frm_confirm)
						{	
							// Add Log
							Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_save_after] Updating cloud password for customer ['.$customer->getId().']');
							
							// Update the customer's cloud storage.
							$password_status = Mage::helper ('oneall_singlesignon')->api_update_customer_cloud_password ($customer, $password_frm_new);							
						}
					}
				break;
			}
		}
	}
	
	// Fired whenever a new customer registers.
	public function customer_register ($observer)
	{
		// Load Customer.
		$customer = $observer->getCustomer ();
		$customer_id = $customer->getId ();
		
		// Customer found.
		if (!empty ($customer_id))
		{
			// Get login details
			$email = Mage::app ()->getRequest ()->getParam ('email');
			$password = Mage::app ()->getRequest ()->getParam ('password');
			
			// Add Log
			Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_register] Creating SSO session for customer ['.$customer->getId().']');
			
			// Setup a new SSO session for this customer
			Mage::helper ('oneall_singlesignon')->create_session_for_customer ($customer, $email, $password);
		}
	}
	
	// Fired whenever a customer updates his account settings.
	public function customer_before_update_account ($observer)
	{
		// Load Customer
		$customer = Mage::getSingleton ('customer/session')->getCustomer ();
		$customer_id = $customer->getId ();
		
		// Customer found
		if (!empty ($customer_id))
		{
			// Read User Tokens
			$tokens = Mage::helper ('oneall_singlesignon')->get_local_storage_tokens_for_customer ($customer);
			
			// If we don't have a token, nothing needs to be done.
			if ($tokens->have_been_retrieved === true)
			{
				// Add Log
				Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_update_account] Checking if password for customer ['.$customer->getId().'] must be updated');
				
				// Is the entered password valid?
				$password_is_valid = false;
				
				// Does the customer wants to change the password?
				$password_do_change = Mage::app ()->getRequest ()->getParam ('change_password');
				
				// Gather new password details.
				$password_frm_current = Mage::app ()->getRequest ()->getParam ('current_password');
				$password_frm_new = Mage::app ()->getRequest ()->getParam ('password');
				$password_frm_confirm = Mage::app ()->getRequest ()->getParam ('confirmation');
				
				// Does the password can and needs to be changed?
				if (!empty ($password_do_change))
				{
					if ( !empty ($password_frm_new) && ($password_frm_new == $password_frm_confirm) && ($password_frm_new != $password_frm_current))				
					{
						// Old Password Details
						$password_curr = $customer->getPasswordHash ();
						$password_curr_parts = explode (":", $password_curr);
						$password_curr_salt = $password_curr_parts [1];
						
						// Check if the password is valid.
						if ($password_curr == Mage::helper ('core')->getHash ($password_frm_current, $password_curr_salt))
						{
							// Add Log
							Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_update_account] Valid local password entered by customer ['.$customer->getId().']');
								
							// Password is valid
							$password_is_valid = true;
						}
						// If it's not valid then check the cloud storage.
						else
						{
							// Checks if a given customer has a cloud storage account and if the given password is valid for it.
							$password_status = Mage::helper ('oneall_singlesignon')->api_check_customer_cloud_password ($customer, $password_frm_current);
							
							// User has a cloud storage and the password matches.
							if ($password_status->is_valid === true)
							{
								// Add Log
								Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_update_account] Valid cloud password entered for customer ['.$customer->getId().']');
						
								// Password is valid
								$password_is_valid = true;
							}
						}
						
						// The entered password is valid.
						if ($password_is_valid == true)
						{
							// Add Log
							Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_update_account] Updating passwords for customer ['.$customer->getId().']');
								
							// Set the new password.
							$customer->setPassword ($password_frm_new);
							$customer->save ();						
											
							// Update the customer's cloud storage.
							$password_status = Mage::helper ('oneall_singlesignon')->api_update_customer_cloud_password ($customer, $password_frm_new);
							
							// Reset password form - we have already done everything that needs to be done.
							foreach (array('change_password', 'current_password', 'password', 'confirmation') as $field)
							{
								Mage::app ()->getRequest ()->setPost ($field, null);
							}
						}
						else
						{
							// Add Log
							Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_update_account] No valid passwords entered for customer ['.$customer->getId().']');
						}
					}
				}	
			}
		}
	}
	
	// Fired when a customer tries to login.
	public function customer_before_login ($observer)
	{
		// Retrieve login data
		$login = Mage::app ()->getRequest ()->getParam ('login');
		if (is_array ($login))
		{
			// Get login details.
			$email = (isset ($login ['username']) ? trim ($login ['username']) : '');
			$password = (isset ($login ['password']) ? trim ($login ['password']) : '');
			
			// Have the credentials been specified?
			if (!empty ($email) && !empty ($password))
			{
				if (Zend_Validate::is ($email, 'EmailAddress'))
				{
					// Add Log
					Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_login] Trying cloud login with ['. $email .']');
									
					// Try to login this user
					$cloud_login = Mage::helper ('oneall_singlesignon')->try_customer_cloud_login ($email, $password);
					
					// Not successfull
					if ( ! $cloud_login->is_successfull)
					{
						// Add Log
						Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_before_login] Cloud login with ['. $email .'] failed, trying local login');
					}
				}
			}
		}
	}
	
	// Fired after a customer has logged in.
	public function customer_after_login ($observer)
	{
		// Load Customer.
		$customer = $observer->getCustomer ();
		$customer_id = $customer->getId ();
		
		// Customer found.
		if (!empty ($customer_id))
		{
			// Add Log
			Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_after_login] Creating session for customer ['.$customer->getId().']');
			
			// Setup a new SSO session for this customer.
			Mage::helper ('oneall_singlesignon')->create_session_for_customer ($customer);
		}
	}
	
	// Fired after a customer has logged out.
	public function customer_after_logout ($observer)
	{
		// Load Customer.
		$customer = $observer->getCustomer ();
		$customer_id = $customer->getId ();
		
		// Customer found.
		if (!empty ($customer_id))
		{
			// Add Log
			Mage::helper ('oneall_singlesignon')->add_log ('[Observer: customer_after_logout] Removing session for customer ['.$customer->getId().']');
			
			// Remove the SSO session of this customer.
			Mage::helper ('oneall_singlesignon')->remove_session_for_customer ($customer);
		}
	}
	
	// Fired before the layout is loaded.
	public function layout_load_before ($observer)
	{
		// Where are we now?
		$page_tag = trim (strtolower (Mage::app ()->getFrontController ()->getAction ()->getFullActionName ('_')));
		switch ($page_tag)
		{
			// Customer is on the login page.
			case 'customer_account_login' :
				
				// Do we have the email of the customer?
				$sso_email = Mage::getSingleton ('core/session')->getSSOEmail ();				
				if (!empty ($sso_email))
				{
					Mage::getSingleton ('core/session')->addSuccess (__ ('Please login with your email address <strong>%s</strong> in order to access your account.', $sso_email));
				}
			
			break;
			
			// Customer is on the registration page.
			case 'customer_account_create' :
				
				// Do we have the email of the customer?
				$sso_email = Mage::getSingleton ('core/session')->getSSOEmail ();
				if (!empty ($sso_email))
				{
					Mage::getSingleton ('core/session')->addSuccess (__ ('You already seem to have created an account using the email address  <strong>%s</strong>. Please click <a href="%s">here</a> to login.', $sso_email, Mage::getUrl ('customer/account/login')));
				}
			
			break;
		}
	}
}