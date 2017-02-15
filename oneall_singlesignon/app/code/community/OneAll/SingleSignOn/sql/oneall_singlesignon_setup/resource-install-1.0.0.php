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

// Start Installer
$installer = $this;
$installer->startSetup ();

mail('cschlesser@oneall.com', 'Installer 1', 'Starting');

// Table to store the customer's sso_session_token
$sql = "CREATE TABLE `" . $this->getTable ('oneall_singlesignon/session') . "` (`customer_id` int(11) UNSIGNED NOT NULL, `sso_session_token` char(36) NOT NULL, PRIMARY KEY (`customer_id`)) ENGINE=InnoDB;";
$installer->run ($sql);

mail('cschlesser@oneall.com', 'Installer 2', $sql);

// Table to store the customer's user_token
$sql = "CREATE TABLE `" . $this->getTable ('oneall_singlesignon/user') . "` (`customer_id` int(11) UNSIGNED NOT NULL, `identity_token` char(36) NOT NULL, PRIMARY KEY (`customer_id`)) ENGINE=InnoDB;";
$installer->run ($sql);

mail('cschlesser@oneall.com', 'Installer 3', $sql);

// End Installer
$installer->endSetup ();