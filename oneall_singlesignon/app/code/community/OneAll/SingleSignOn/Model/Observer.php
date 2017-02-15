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
	// Fired af the login of a customer.
	public function customerLogin($observer)
    {
    	// Load Helper
    	$helper = Mage::helper ('oneall_singlesignon');
    	
    	// Load Customer
        $customer = $observer->getCustomer();
        
        // Setup a new session for the customer
        $helper->create_session_for_customer ($customer);
    }
    
    // Fired af the logout of a customer.
    public function customerLogout($observer)
    {
    	// Load Helper
    	$helper = Mage::helper ('oneall_singlesignon');
    	 
    	// Load Customer
    	$customer = $observer->getCustomer();
    
    	// Setup a new session for the customer
    	$helper->remove_session_for_customer ($customer);
    }
    
}