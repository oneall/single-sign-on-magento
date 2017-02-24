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

// Auto Link Using Unverified Emails DropDown
class OneAll_SingleSignOn_Model_Autocreatesendmail
{
	public function toOptionArray ()
	{
		$helper = Mage::helper ('oneall_singlesignon');
		
		return array(
			array(
				'value' => 1,
				'label' => $helper->__ ('Yes, send an email to newly added customers') 
			),
			array(
				'value' => 0,
				'label' => $helper->__ ('No, do not send an email to newly added customers') 
			) 
		);
	}
}