# @(#) test password against a Web site
#
# @(-) --[no]help                      print this message, and exit [${help}]
# @(-) --[no]colored                   color the output depending of the message level [${colored}]
# @(-) --[no]dummy                     dummy run [${dummy}]
# @(-) --[no]verbose                   run verbosely [${verbose}]
# @(-) --url=<name>                    URL of the web site [${url}]
# @(-) --pwdtext=<text>                a single password to be tested [${pwdtext}]
# @(-) --pwdfile=<filename[,...]>      path of the file which contains the passwords to be tested, may be specified several times or as a comma-separated list [${pwdfile}]
# @(-) --pwdname=<name>                name of the field which contains the password [${pwdname}]
# @(-) --pwdmax=<count>                max count of passwords to be tested, -1 is unlimited [${pwdmax}]
# @(-) --logintext=<text>              a single login name to be tested [${logintext}]
# @(-) --loginfile=<filename>[,...]    path of the file which contains the logins to be tested, may be specified several times or as a comma-separated list [${loginfile}]
# @(-) --loginname=<name>              name of the field which contains the login [${loginname}]
# @(-) --loginmax=<count>              max count of logins to be tested, -1 is unlimited [${loginmax}]
# @(-) --requesttoken=<name>           the name of the request verification token field [${requesttoken}]
# @(-) --delayms=<delayms>             count of milliseconds between each try [${delayms}]
#
# @(@) Note 1: The default passwords file may be invoked as '--pwdfile=DEFAULT' to be added to another (maybe personalized) passwords file.
#
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


use strict;
use utf8;
use warnings;

use Time::HiRes qw( usleep );

use TTP::Path;
use TTP::Security;

my $defaults = {
	help => 'no',
	colored => 'no',
	dummy => 'no',
	verbose => 'no',
	delayms => 0,
	loginfile => '',
	loginmax => -1,
	loginname => 'login',
	logintext => '',
	pwdfile => 'TTP://libexec/sec/1000000-most-common-passwords.txt',
	pwdmax => -1,
	pwdname => 'password',
	pwdtext => '',
	requesttoken => '',
	url => ''
};

my $opt_delayms = $defaults->{delayms};
my @opt_loginfiles = ();
my $opt_loginmax = $defaults->{loginmax};
my $opt_loginname = $defaults->{loginname};
my $opt_logintext = $defaults->{logintext};
my @opt_pwdfiles = ();
my $opt_pwdmax = $defaults->{pwdmax};
my $opt_pwdname = $defaults->{pwdname};
my $opt_pwdtext = $defaults->{pwdtext};
my $opt_requesttoken = $defaults->{requesttoken};
my $opt_url = $defaults->{url};

my $total_count = 0;

# -------------------------------------------------------------------------------------------------
# this is the main loop on the to-be-tested login names and passwords

sub tryPasswords {
	msgOut( "testing url $opt_url" );
	my $found = false;
	my $count = 0;
	if( $opt_logintext ){
		$count += 1;
		$found = tryPasswordsWithLogin( $opt_logintext );
	}
	if( scalar @opt_loginfiles && !$found ){
		foreach my $file ( @opt_loginfiles ){
			open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
			if( !TTP::errs()){
				while( my $login = <$fh> ){
					chomp $login;
					$count += 1;
					if( $opt_loginmax == -1 || $count <= $opt_loginmax ){
						$found = tryPasswordsWithLogin( $login );
						if( $found ){
							msgOut( "success: $login" );
						}
					}
					last if $found;
				}
			}
		}
	}
	msgOut( "found=".( $found ? 'true' : 'false' ));
}

# -------------------------------------------------------------------------------------------------
# try all passwords for the given login
# (I):
# - the login
# (O):
# - returns true if a password is successful

sub tryPasswordsWithLogin {
	my ( $login ) = @_;
	my $found = false;
	my $count = 0;
	msgVerbose( "trying login='$login'" );
	if( $opt_pwdtext ){
		$count += 1;
		$found = tryPasswordsWithPwd( $login, $opt_pwdtext );
	}
	if( !$found && scalar @opt_pwdfiles ){
		foreach my $file ( @opt_pwdfiles ){
			open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
			if( !TTP::errs()){
				while( my $pwd = <$fh> ){
					$count += 1;
					if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
						chomp $pwd;
						$found = tryPasswordsWithPwd( $login, $pwd );
					}
					last if $found;
				}
			}
		}
	}
	return $found;
}

# -------------------------------------------------------------------------------------------------
# try the given login and passwords
# (I):
# - the login
# - the password
# (O):
# - returns true if a password is successful

sub tryPasswordsWithPwd {
	my ( $login, $password ) = @_;
	my $found = TTP::Security::loginTo( $opt_url, $login, $password, {
		login => $opt_loginname,
		password => $opt_pwdname,
		requestToken => $opt_requesttoken
	});
	$total_count += 1;
	msgVerbose( "total_count=$total_count ".( $found ? 'success' : 'error' ));
	# sleep for the given time
	if( $opt_delayms ){
		msgVerbose( "sleepig for $opt_delayms ms..." );
		usleep( 1000*$opt_delayms );
	}
	return $found;
}

# =================================================================================================
# MAIN
# =================================================================================================

if( !GetOptions(
	"help!"					=> sub { $ep->runner()->help( @_ ); },
	"colored!"				=> sub { $ep->runner()->colored( @_ ); },
	"dummy!"				=> sub { $ep->runner()->dummy( @_ ); },
	"verbose!"				=> sub { $ep->runner()->verbose( @_ ); },
	"delayms=i"				=> \$opt_delayms,
	"loginfile=s"			=> \@opt_loginfiles,
	"loginmax=i"			=> \$opt_loginmax,
	"loginname=s"			=> \$opt_loginname,
	"logintext=s"			=> \$opt_logintext,
	"pwdfile=s"				=> \@opt_pwdfiles,
	"pwdmax=i"				=> \$opt_pwdmax,
	"pwdname=s"				=> \$opt_pwdname,
	"pwdtext=s"				=> \$opt_pwdtext,
	"requesttoken=s"		=> \$opt_requesttoken,
	"url=s"					=> \$opt_url )){

		msgOut( "try '".$ep->runner()->command()." ".$ep->runner()->verb()." --help' to get full usage syntax" );
		TTP::exit( 1 );
}

if( $ep->runner()->help()){
	$ep->runner()->displayHelp( $defaults );
	TTP::exit();
}

msgVerbose( "got colored='".( $ep->runner()->colored() ? 'true':'false' )."'" );
msgVerbose( "got dummy='".( $ep->runner()->dummy() ? 'true':'false' )."'" );
msgVerbose( "got verbose='".( $ep->runner()->verbose() ? 'true':'false' )."'" );
msgVerbose( "got delayms='$opt_delayms'" );
@opt_loginfiles= split( /,/, join( ',', @opt_loginfiles ));
msgVerbose( "got loginfiles=[".join( ',', @opt_loginfiles )."]" );
msgVerbose( "got loginmax='$opt_loginmax'" );
msgVerbose( "got loginname='$opt_loginname'" );
msgVerbose( "got logintext='$opt_logintext'" );
@opt_pwdfiles= split( /,/, join( ',', @opt_pwdfiles ));
msgVerbose( "got pwdfiles=[".join( ',', @opt_pwdfiles )."]" );
msgVerbose( "got pwdmax='$opt_pwdmax'" );
msgVerbose( "got pwdname='$opt_pwdname'" );
msgVerbose( "got pwdtext='$opt_pwdtext'" );
msgVerbose( "got requesttoken='$opt_requesttoken'" );
msgVerbose( "got url='$opt_url'" );

# must have --url option
msgErr( "'--url' option is mandatory, but is not specified" ) if !$opt_url;

# must have at least one --loginfile or --logintext options
print Dumper( @opt_loginfiles );
msgVerbose( "count ".scalar @opt_loginfiles );
if( scalar @opt_loginfiles ){
	my @files = ();
	foreach my $file ( @opt_loginfiles ){
		$file = TTP::Path::getResource( $file );	
		if( -r $file ){
			push( @files, $file );
		} else {
			msgErr( "$file: file not found or not readable" );
		}
	}
	@opt_loginfiles = @files;
} elsif( !$opt_logintext ){
	msgErr( "at least one login name must be specified, either with '--logintext' or '--loginfile' options, none found" );
}

# must have at least one --pwdfile or --pwdtext options
if( scalar @opt_pwdfiles ){
	my @files = ();
	foreach my $file ( @opt_pwdfiles ){
		$file = $defaults->{pwdfile} if $file eq 'DEFAULT';
		$file = TTP::Path::getResource( $file );	
		if( -r $file ){
			push( @files, $file );
		} else {
			msgErr( "$file: file not found or not readable" );
		}
	}
	@opt_pwdfiles = @files;
} elsif( !$opt_pwdtext ){
	msgErr( "at least one password must be specified, either with '--pwdtext' or '--pwdfile' options, none found" );
}

# if a delay is specified, must be greater than zero
if( $opt_delayms ){
	msgErr( "when specified, delay(ms) must be greater than zero, got $opt_delayms" ) if 0+$opt_delayms < 0;
}

if( !TTP::errs()){
	tryPasswords();
}

TTP::exit();
