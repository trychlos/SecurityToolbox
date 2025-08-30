# @(#) test password against a Web site
#
# @(-) --[no]help                  print this message, and exit [${help}]
# @(-) --[no]colored               color the output depending of the message level [${colored}]
# @(-) --[no]dummy                 dummy run [${dummy}]
# @(-) --[no]verbose               run verbosely [${verbose}]
# @(-) --url=<name>                URL of the web site [${url}]
# @(-) --pwdfile=<filename[,...]>  path of the file which contains the passwords to be tested, may be specified several times or as a comma-separated list [${pwdfile}]
# @(-) --pwdmax=<count>            max count of passwords to be tested, -1 is unlimited [${pwdmax}]
# @(-) --loginfile=<filename>      path of the file which contains the logins to be tested [${loginfile}]
# @(-) --loginmax=<count>          max count of logins to be tested, -1 is unlimited [${loginmax}]
#
# @(@) Note 1: The default passwords file may be invoked as '--pwdfile=DEFAULT' to be added to another (maybe personalized) passwords file.
#
# TheToolsProject - Tools System and Working Paradigm for IT Production
# Copyright (©) 1998-2023 Pierre Wieser (see AUTHORS)
# Copyright (©) 2023-2025 PWI Consulting
#
# TheToolsProject is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# TheToolsProject is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with TheToolsProject; see the file COPYING. If not,
# see <http://www.gnu.org/licenses/>.


use strict;
use utf8;
use warnings;

use TTP::Path;

my $defaults = {
	help => 'no',
	colored => 'no',
	dummy => 'no',
	verbose => 'no',
	loginfile => '',
	loginmax => -1,
	pwdfile => 'TTP://libexec/sec/1000000-most-common-passwords.txt',
	pwdmax => -1,
	url => ''
};

my $opt_loginfile = $defaults->{loginfile};
my $opt_loginmax = $defaults->{loginmax};
my @opt_pwdfiles = ();
my $opt_pwdmax = $defaults->{pwdmax};
my $opt_url = $defaults->{url};

# -------------------------------------------------------------------------------------------------
# this is the main loop on the to-be-tested login names and passwords

sub tryPasswords {
	msgOut( "testing url $opt_url" );
	my $found = false;
	my $count = 0;
	open( my $fh, '<:encoding(UTF-8)', $opt_loginfile ) or msgErr( "$opt_loginfile: $!" );
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
	foreach my $file ( @opt_pwdfiles ){
		open( my $fh, '<:encoding(UTF-8)', $file ) or msgErr( "$file: $!" );
		if( !TTP::errs()){
			while( my $pwd = <$fh> ){
				$count += 1;
				if( $opt_pwdmax == -1 || $count <= $opt_pwdmax ){
					chomp $pwd;
					msgVerbose( "trying password='$pwd' (count=$count)" );
				}
				last if $found;
			}
		}
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
	"loginfile=s"			=> \$opt_loginfile,
	"loginmax=i"			=> \$opt_loginmax,
	"pwdfile=s"				=> \@opt_pwdfiles,
	"pwdmax=i"				=> \$opt_pwdmax,
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
msgVerbose( "got loginfile='$opt_loginfile'" );
msgVerbose( "got loginmax='$opt_loginmax'" );
@opt_pwdfiles= split( /,/, join( ',', @opt_pwdfiles ));
msgVerbose( "got pwdfiles='".join( ',', @opt_pwdfiles )."'" );
msgVerbose( "got pwdmax='$opt_pwdmax'" );
msgVerbose( "got url='$opt_url'" );

# must have --url option
msgErr( "'--url' option is mandatory, but is not specified" ) if !$opt_url;

# must have --loginfile option
msgErr( "'--loginfile' option is mandatory, but is not specified" ) if !$opt_loginfile;
msgErr( "$opt_loginfile: file not found or not readable" ) if $opt_loginfile && ! -r $opt_loginfile;

# must have at least one --pwdfile option
if( $#opt_pwdfiles ){
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
} else {
	msgErr( "at least one '--pwdfile' option is mandatory, but none not specified" );
}

if( !TTP::errs()){
	tryPasswords();
}

TTP::exit();
