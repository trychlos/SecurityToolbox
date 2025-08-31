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
use HTML::TreeBuilder 5 -weak;
use HTTP::Cookies;
use HTTP::Response;
use LWP;

use TTP;
use vars::global qw( $ep );

use TTP::Constants qw( :all );
use TTP::Message qw( :all );

# .AspNetCore.Antiforgery.* is not an auth/session cookie.
# It’s the CSRF (anti-forgery) cookie that ASP.NET Core uses together with the hidden form field (e.g., __RequestVerificationToken).
# The framework will (re)issue/refresh that cookie whenever it needs to validate forms—regardless of whether your username/password are correct.

my $Const = {
	excludes => [
		'.*AspNetCore.Antiforgery.*'
	]
};

# -------------------------------------------------------------------------------------------------
# Connect to a website by posting a form with a Login and a Password
# (I):
# - url
# - login
# - password
# - an optional options hash with following keys:
#   > login: the name of the login field, defaulting to 'login'
#   > password: the name of the password field, defaulting to 'password'
#   > requestToken: the name of the request verification token field, defaulting to none
# (O):
# - returns false or the returned authentication HTTP::Cookies

sub loginTo {
	my ( $url, $login, $password, $opts ) = @_;
	my $cookie_jar = false;
	$opts //= {};
	msgVerbose( __PACKAGE__."loginTo() login='$login' password='$password'" );
	my $ua = LWP::UserAgent->new();
	my $response;
	my $token;
	my $cookie_ref = 'Set-Cookie';
	# if we have a request token, then get it
	if( $opts->{requestToken} ){
		$response = $ua->get( $url );
		my $html = $response->decoded_content;
		my $tree = HTML::TreeBuilder->new_from_content( $html );
		my @inputs = $tree->look_down(
			_tag  => 'input',
			name  => $opts->{requestToken}
		);
		if( @inputs ){
		    $token = $inputs[0]->attr( 'value' );
			msgVerbose( "requestToken='$opts->{requestToken}' token='$token'" );
		}
		$tree->delete;
	}
	my $flogin = $opts->{login} || 'login';
	my $fpwd = $opts->{password} || 'password';
	my $parms = {};
	$parms->{$flogin} = $login;
	$parms->{$fpwd} = $password;
	if( $token ){
		$parms->{$opts->{requestToken}} = $token;
	}
	$response = $ua->post( $url, $parms );
	print STDERR "headers ".Dumper( $response->headers());
	print STDERR "status ".Dumper( $response->status_line );
	my $cookie_line = $response->header( $cookie_ref );
	print STDERR "cookie_line ".Dumper( $cookie_line );
	# if we have got a cookie to be set, then build the Cookie object
	if( $cookie_line ){
		# make sure the received cookie is not excluded
		my $matched = false;
		foreach my $re ( @{$Const->{excludes}} ){
			if( $cookie_line =~ m/$re/i ){
				$matched = true;
				last;
			}
		}
		$cookie_line = '' if $matched;
	}
	if( $cookie_line ){
		$cookie_jar = HTTP::Cookies->new();
		$cookie_jar->extract_cookies( $response );
		#print STDERR "cookie_jar ".Dumper( $cookie_jar );
	}
	msgVerbose( $cookie_jar ? "success" : "error" );
	return $cookie_jar;
}

1;
