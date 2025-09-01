# @(#) test password against a Web site
#
# @(-) --[no]help                      print this message, and exit [${help}]
# @(-) --[no]colored                   color the output depending of the message level [${colored}]
# @(-) --[no]dummy                     dummy run [${dummy}]
# @(-) --[no]verbose                   run verbosely [${verbose}]
# @(-) --url=<name>                    URL of the web site [${url}]
# @(-) --[no]pwdfirst                  whether to test by password first, then by login [${pwdfirst}]
# @(-) --pwdtext=<text>                a single password to be tested [${pwdtext}]
# @(-) --pwdfile=<filename[,...]>      path of the file which contains the passwords to be tested, may be specified several times or as a comma-separated list [${pwdfile}]
# @(-) --pwdname=<name>                name of the field which contains the password [${pwdname}]
# @(-) --pwdmax=<count>                max count of passwords to be tested, -1 is unlimited [${pwdmax}]
# @(-) --[no]pwdslurp                  whether to slurp the passwords file [${pwdslurp}]
# @(-) --[no]loginfirst                whether to test by login first, then by password [${loginfirst}]
# @(-) --logintext=<text>              a single login name to be tested [${logintext}]
# @(-) --loginfile=<filename>[,...]    path of the file which contains the logins to be tested, may be specified several times or as a comma-separated list [${loginfile}]
# @(-) --loginname=<name>              name of the field which contains the login [${loginname}]
# @(-) --loginmax=<count>              max count of logins to be tested, -1 is unlimited [${loginmax}]
# @(-) --[no]loginslurp                whether to slurp the logins file [${loginslurp}]
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

use Path::Tiny;
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
	loginfirst => 'yes',
	loginmax => -1,
	loginname => 'login',
	loginslurp => 'no',
	logintext => '',
	pwdfile => 'TTP://libexec/sec/1000000-most-common-passwords.txt',
	pwdfirst => 'no',
	pwdmax => -1,
	pwdname => 'password',
	pwdslurp => 'no',
	pwdtext => '',
	requesttoken => '',
	url => ''
};

my $opt_delayms = $defaults->{delayms};
my @opt_loginfiles = ();
my $opt_loginfirst = true;
my $opt_loginmax = $defaults->{loginmax};
my $opt_loginname = $defaults->{loginname};
my $opt_loginslurp = false;
my $opt_logintext = $defaults->{logintext};
my @opt_pwdfiles = ();
my $opt_pwdfirst = false;
my $opt_pwdmax = $defaults->{pwdmax};
my $opt_pwdname = $defaults->{pwdname};
my $opt_pwdslurp = false;
my $opt_pwdtext = $defaults->{pwdtext};
my $opt_requesttoken = $defaults->{requesttoken};
my $opt_url = $defaults->{url};

my $opt_loginfirst_set = false;
my $opt_pwdfirst_set = false;
my $total_count = 0;

# -------------------------------------------------------------------------------------------------
# this is the main loop on the to-be-tested login names and passwords
# test by login first which may be not the most efficient when we want test several logins

sub tryPasswordsByLogin {
	msgOut( "testing '$opt_url' URL by login first" );
	my $found = false;
	my $end = false;
	my $count = 0;
	if( $opt_logintext ){
		$count += 1;
		$found = tryPasswordsWithLogin( $opt_logintext );
	}
	if( scalar @opt_loginfiles && !$found ){
		foreach my $file ( @opt_loginfiles ){
			if( $opt_loginslurp ){
				my @logins = path( $file )->lines_utf8;
				foreach my $login ( @logins ){
					$count += 1;
					if( $opt_loginmax == -1 || $count <= $opt_loginmax ){
						chomp $login;
						$found = tryPasswordsWithLogin( $login );
						if( $found ){
							msgOut( "success: $login" );
						}
					} else {
						$end = true;
					}
					last if $found or $end;
				}
			} else {
				open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
				if( !TTP::errs()){
					while( my $login = <$fh> ){
						$count += 1;
						if( $opt_loginmax == -1 || $count <= $opt_loginmax ){
							chomp $login;
							$found = tryPasswordsWithLogin( $login );
							if( $found ){
								msgOut( "success: $login" );
							}
						} else {
							$end = true;
						}
						last if $found or $end;
					}
				}
			}
			last if $found or $end;
		}
	}
	msgOut( "found=".( $found ? 'true' : 'false' ));
}

# -------------------------------------------------------------------------------------------------
# this is the main loop on the to-be-tested login names and passwords
# test by password first: test each login for each given password

sub tryPasswordsByPassword {
	msgOut( "testing '$opt_url' URL by password first" );
	my $found = false;
	my $end = false;
	my $count = 0;
	if( $opt_pwdtext ){
		$count += 1;
		$found = tryPasswordsWithPassword( $opt_pwdtext );
	}
	if( scalar @opt_pwdfiles && !$found ){
		foreach my $file ( @opt_pwdfiles ){
			if( $opt_pwdslurp ){
				my @passwords = path( $file )->lines_utf8;
				foreach my $pwd ( @passwords ){
					$count += 1;
					if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
						chomp $pwd;
						$found = tryPasswordsWithPassword( $pwd );
						if( $found ){
							msgOut( "success: $pwd" );
						}
					} else {
						$end = true;
					}
					last if $found or $end;
				}
			} else {
				open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
				if( !TTP::errs()){
					while( my $pwd = <$fh> ){
						$count += 1;
						if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
							chomp $pwd;
							$found = tryPasswordsWithPassword( $pwd );
							if( $found ){
								msgOut( "success: $pwd" );
							}
						} else {
							$end = true;
						}
						last if $found or $end;
					}
				}
			}
			last if $found or $end;
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
	my $end = false;
	my $count = 0;
	msgVerbose( "trying login='$login'" );
	if( $opt_pwdtext ){
		$count += 1;
		$found = tryPasswordsWithLoginPassword( $login, $opt_pwdtext );
	}
	if( !$found && scalar @opt_pwdfiles ){
		foreach my $file ( @opt_pwdfiles ){
			if( $opt_pwdslurp ){
				my @passwords = path( $file )->lines_utf8;
				foreach my $pwd ( @passwords ){
					$count += 1;
					if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
						chomp $pwd;
						$found = tryPasswordsWithLoginPassword( $login, $pwd );
					} else {
						$end = true;
					}
					last if $found or $end;
				}
			} else {
				open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
				if( !TTP::errs()){
					while( my $pwd = <$fh> ){
						$count += 1;
						if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
							chomp $pwd;
							$found = tryPasswordsWithLoginPassword( $login, $pwd );
						} else {
							$end = true;
						}
						last if $found or $end;
					}
				}
			}
			last if $found or $end;
		}
	}
	return $found;
}

# -------------------------------------------------------------------------------------------------
# try all logins for the given password
# (I):
# - the password
# (O):
# - returns true if a login is successful

sub tryPasswordsWithPassword {
	my ( $password ) = @_;
	my $found = false;
	my $end = false;
	my $count = 0;
	msgVerbose( "trying password='$password'" );
	if( $opt_logintext ){
		$count += 1;
		$found = tryPasswordsWithLoginPassword( $opt_logintext, $password );
	}
	if( !$found && scalar @opt_loginfiles ){
		foreach my $file ( @opt_loginfiles ){
			if( $opt_loginslurp ){
				my @logins = path( $file )->lines_utf8;
				foreach my $login ( @logins ){
					$count += 1;
					if( $opt_loginmax == -1 || $count <= $opt_loginmax ){
						chomp $login;
						$found = tryPasswordsWithLoginPassword( $login, $password );
					} else {
						$end = true;
					}
					last if $found or $end;
				}
			} else {
				open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
				if( !TTP::errs()){
					while( my $login = <$fh> ){
						$count += 1;
						if( $opt_loginmax == -1 || $count <= $opt_loginmax ){
							chomp $login;
							$found = tryPasswordsWithLoginPassword( $login, $password );
						} else {
							$end = true;
						}
						last if $found or $end;
					}
				}
			}
			last if $found or $end;
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

sub tryPasswordsWithLoginPassword {
	my ( $login, $password ) = @_;
	my $found = TTP::Security::loginTo( $opt_url, $login, $password, {
		login => $opt_loginname,
		password => $opt_pwdname,
		requestToken => $opt_requesttoken
	});
	$total_count += 1;
	msgVerbose( "total_count=$total_count ".( $found ? 'success' : 'error' ));
	# sleep for the given time
	if( !$found && $opt_delayms ){
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
	"loginfirst!"			=> sub {
		my( $name, $value ) = @_;
		$opt_loginfirst = $value;
		$opt_loginfirst_set = true;
	},
	"loginmax=i"			=> \$opt_loginmax,
	"loginname=s"			=> \$opt_loginname,
	"loginslurp!"			=> \$opt_loginslurp,
	"logintext=s"			=> \$opt_logintext,
	"pwdfile=s"				=> \@opt_pwdfiles,
	"pwdfirst!"				=> sub {
		my( $name, $value ) = @_;
		$opt_pwdfirst = $value;
		$opt_pwdfirst_set = true;
		$opt_loginfirst = false if !$opt_loginfirst_set;
	},
	"pwdmax=i"				=> \$opt_pwdmax,
	"pwdname=s"				=> \$opt_pwdname,
	"pwdslurp!"				=> \$opt_pwdslurp,
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
msgVerbose( "got loginfirst='".( $opt_loginfirst ? 'true':'false' )."'" );
msgVerbose( "got loginmax='$opt_loginmax'" );
msgVerbose( "got loginname='$opt_loginname'" );
msgVerbose( "got loginslurp='".( $opt_loginslurp ? 'true':'false' )."'" );
msgVerbose( "got logintext='$opt_logintext'" );
@opt_pwdfiles= split( /,/, join( ',', @opt_pwdfiles ));
msgVerbose( "got pwdfiles=[".join( ',', @opt_pwdfiles )."]" );
msgVerbose( "got pwdfirst='".( $opt_pwdfirst ? 'true':'false' )."'" );
msgVerbose( "got pwdmax='$opt_pwdmax'" );
msgVerbose( "got pwdname='$opt_pwdname'" );
msgVerbose( "got pwdslurp='".( $opt_pwdslurp ? 'true':'false' )."'" );
msgVerbose( "got pwdtext='$opt_pwdtext'" );
msgVerbose( "got requesttoken='$opt_requesttoken'" );
msgVerbose( "got url='$opt_url'" );

# must have --url option
msgErr( "'--url' option is mandatory, but is not specified" ) if !$opt_url;

# must have at least one --loginfile or --logintext options
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

# --loginfirst and --pwdfirst are mutually exclusive - one and only one must be set
my $countfirst = 0;
$countfirst += 1 if $opt_loginfirst;
$countfirst += 1 if $opt_pwdfirst;
if( $countfirst != 1 ){
	if( $countfirst == 0 ){
		msgErr( "one and only one of '--loginfirst' or '--pwdfirst' options must be specified, none found" );
	} else {
		msgErr( "one and only one of '--loginfirst' or '--pwdfirst' options must be specified, both found" );
	}
}

if( !TTP::errs()){
	tryPasswordsByLogin() if $opt_loginfirst;
	tryPasswordsByPassword() if $opt_pwdfirst;
}

TTP::exit();
