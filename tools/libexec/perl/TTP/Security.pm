# SecurityToolbox - A security toolbox as a TTP extension
# Copyright (©) 2025 PWI Consulting
#
# SecurityToolbox is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# SecurityToolbox is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SecurityToolbox; see the file COPYING. If not,
# see <http://www.gnu.org/licenses/>.
#
# Website management

package TTP::Security;
die __PACKAGE__ . " must be loaded as TTP::Security\n" unless __PACKAGE__ eq 'TTP::Security';

use strict;
use utf8;
use warnings;

use Data::Dumper;
use LWP;

use TTP;
use vars::global qw( $ep );

use TTP::Constants qw( :all );
use TTP::Message qw( :all );

# -------------------------------------------------------------------------------------------------
# Connect to a website by posting a form with a Login and a Password
# (I):
# - login
# - password
# - an optional options hash with following keys:
#   > login: the name of the login field, defaulting to 'login'
#   > password: the name of the password field, defaulting to 'password'
# (O):
# - returns false or the returned data

sub loginTo {
	my ( $login, $password, $opts ) = @_;
	my $ok = false;
	$opts //= {};
	msgVerbose( __PACKAGE__."loginTo() login='$login' password='$password'" );
	return $ok;
}

1;
