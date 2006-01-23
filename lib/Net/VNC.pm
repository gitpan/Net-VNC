package Net::VNC;
use strict;
use warnings;
use base qw(Class::Accessor::Fast);
use Crypt::DES;
use Image::Imlib2;
use IO::Socket::INET;
__PACKAGE__->mk_accessors(qw(hostname password socket name width height));
our $VERSION = '0.30';

sub login {
    my $self     = shift;
    my $hostname = $self->hostname;
    my $socket   = IO::Socket::INET->new(
        PeerAddr => $hostname,
        PeerPort => '5900',
        Proto    => 'tcp',
        Timeout  => 15,
        )
        || die "Error connecting to $hostname: $!";
    $self->socket($socket);

    $socket->read( my $protocol_version, 12 );

    #    warn "prot: $protocol_version";

    # let's use the same version of the protocol
    $socket->print($protocol_version);

    $socket->read( my $number_of_security_types, 1 );
    $number_of_security_types = unpack( "c", $number_of_security_types );

    #    warn "types: $number_of_security_types";

    if ( $number_of_security_types == 0 ) {
        die "Error authenticating";
    }

    my @security_types;
    foreach ( 1 .. $number_of_security_types ) {
        $socket->read( my $security_type, 1 );
        $security_type = unpack( "c", $security_type );

        #        warn "sec: $security_type";
        push @security_types, $security_type;
    }

    die "no vnc auth" unless grep { $_ == 2 } @security_types;

    $socket->print( pack( "c", 2 ) );

    $socket->read( my $challenge, 16 );

    #    warn "chal: " . unpack('h*', $challenge) . "\n";

    my $key = $self->password;
    $key .= pack( 'c', 0 ) until ( length($key) % 8 ) == 0;

    my $realkey;

    #    warn unpack('b*', $key);
    foreach my $byte ( split //, $key ) {
        $realkey .= pack( "b8", scalar reverse unpack( "b8", $byte ) );
    }

    #    warn unpack('b*', $realkey);

    my $cipher = Crypt::DES->new($realkey);
    my $response;
    my $i = 0;
    while ( $i < 16 ) {
        my $word = substr( $challenge, $i, 8 );

        #        warn "$i: " . length($word);
        $response .= $cipher->encrypt($word);
        $i += 8;
    }

    #    warn "resp: " . unpack('h*', $response) . "\n";

    $socket->print($response);

    $socket->read( my $security_result, 4 );
    $security_result = unpack( "I", $security_result );

    #    warn $security_result;
    die "security failed" if $security_result;

    # now client initialisation
    #    warn "logged in";

    $socket->print( pack( 'c', 1 ) );    # share

    $socket->read( my $framebuffer_width, 2 );
    $framebuffer_width = unpack( "n", $framebuffer_width );
    $self->width($framebuffer_width);

    $socket->read( my $framebuffer_height, 2 );
    $framebuffer_height = unpack( "n", $framebuffer_height );
    $self->height($framebuffer_height);

    #    warn "$framebuffer_width x $framebuffer_height";

    $socket->read( my $bits_per_pixel, 1 );
    $bits_per_pixel = unpack( "c", $bits_per_pixel );

    $socket->read( my $depth, 1 );
    $depth = unpack( "c", $depth );

    $socket->read( my $big_endian_flag, 1 );
    $big_endian_flag = unpack( "c", $big_endian_flag );

    $socket->read( my $true_colour_flag, 1 );
    $true_colour_flag = unpack( "c", $true_colour_flag );

    $socket->read( my $red_max, 2 );
    $red_max = unpack( "n", $red_max );

    $socket->read( my $green_max, 2 );
    $green_max = unpack( "n", $green_max );

    $socket->read( my $blue_max, 2 );
    $blue_max = unpack( "n", $blue_max );

    $socket->read( my $red_shift, 1 );
    $red_shift = unpack( "c", $red_shift );

    $socket->read( my $green_shift, 1 );
    $green_shift = unpack( "c", $green_shift );

    $socket->read( my $blue_shift, 1 );
    $blue_shift = unpack( "c", $blue_shift );

#    warn "$bits_per_pixel bpp / depth $depth / $big_endian_flag be / $true_colour_flag tc / $red_max,$green_max,$blue_max / $red_shift,$green_shift,$blue_shift";

    $socket->read( my $padding, 3 );

    $socket->read( my $name_length, 4 );
    $name_length = unpack( "N", $name_length );

    #    warn $name_length;

    $socket->read( my $name_string, $name_length );
    $self->name($name_string);

    #    warn $name_string;

    # setpixelformat
    $socket->print( pack( 'c', 0 ) );    # message_type
    $socket->print( pack( 'c', 0 ) );    # padding
    $socket->print( pack( 'c', 0 ) );    # padding
    $socket->print( pack( 'c', 0 ) );    # padding

    $socket->print( pack( 'c', 8 ) );                  # bpp
    $socket->print( pack( 'c', 8 ) );                  # depth
    $socket->print( pack( 'c', $big_endian_flag ) );
    $socket->print( pack( 'c', 0 ) );                  # true colour flag
    $socket->print( pack( 'n', $red_max ) );
    $socket->print( pack( 'n', $green_max ) );
    $socket->print( pack( 'n', $blue_max ) );
    $socket->print( pack( 'c', $red_shift ) );
    $socket->print( pack( 'c', $green_shift ) );
    $socket->print( pack( 'c', $blue_shift ) );
    $socket->print( pack( 'c', 0 ) );                  # padding
    $socket->print( pack( 'c', 0 ) );                  # padding
    $socket->print( pack( 'c', 0 ) );                  # padding

    # set encodings
    $socket->print( pack( 'c', 2 ) );             # message_type
    $socket->print( pack( 'c', 0 ) );             # padding
    $socket->print( pack( 'n', 2 ) );             # number_of_encodings
    $socket->print( pack( 'i', 4294967057 ) );    # cursor pseudo-encoding
    $socket->print( pack( 'N', 0 ) );             # Raw
}

sub capture {
    my $self   = shift;
    my $socket = $self->socket;

    # pointer event - doesn't seem to work?
    $socket->print( pack( 'c', 5 ) );                # message_type
    $socket->print( pack( 'c', 0 ) );                # button_mask
    $socket->print( pack( 'n', $self->width ) );     # x
    $socket->print( pack( 'n', $self->height ) );    # y

    # frame buffer update request
    $socket->print( pack( 'c', 3 ) );                # message_type
    $socket->print( pack( 'c', 0 ) );                # not incremental
    $socket->print( pack( 'n', 0 ) );                # x
    $socket->print( pack( 'n', 0 ) );                # y
    $socket->print( pack( 'n', $self->width ) );
    $socket->print( pack( 'n', $self->height ) );

    $socket->read( my $message_type, 1 );
    $message_type = unpack( "c", $message_type );

    #    warn $message_type;

    die "message type of $message_type" unless $message_type == 1;

    # set colour map entries
    $socket->read( my $padding,      1 );
    $socket->read( my $first_colour, 2 );
    $first_colour = unpack( "n", $first_colour );
    $socket->read( my $number_of_colours, 2 );
    $number_of_colours = unpack( "n", $number_of_colours );

    #    warn "colours: $first_colour.. ($number_of_colours)";

    my @colours;
    foreach my $i ( $first_colour .. $first_colour + $number_of_colours - 1 )
    {
        $socket->read( my $r, 2 );
        $r = unpack( "n", $r );
        $socket->read( my $g, 2 );
        $g = unpack( "n", $g );
        $socket->read( my $b, 2 );
        $b = unpack( "n", $b );

        #        warn "$i $r/$g/$b";
        $colours[$i] = { r => $r, g => $g, b => $b };
    }

    $socket->read( $message_type, 1 );
    $message_type = unpack( "c", $message_type );

    #    warn $message_type;

    die "message type of $message_type" unless $message_type == 0;

    # frame buffer update
    $socket->read( $padding, 1 );
    $socket->read( my $number_of_rectangles, 2 );
    $number_of_rectangles = unpack( "n", $number_of_rectangles );

    #    warn $number_of_rectangles;

    my $image = Image::Imlib2->new( $self->width, $self->height );

    foreach ( 1 .. $number_of_rectangles ) {
        $socket->read( my $x, 2 );
        $x = unpack( "n", $x );
        $socket->read( my $y, 2 );
        $y = unpack( "n", $y );
        $socket->read( my $w, 2 );
        $w = unpack( "n", $w );
        $socket->read( my $h, 2 );
        $h = unpack( "n", $h );
        $socket->read( my $encoding_type, 4 );
        $encoding_type = unpack( "N", $encoding_type );

        #        warn "$x,$y $w x $h $encoding_type";
        $socket->read( my $raw, $w * $h );
        $raw = reverse($raw);
        my ( $px, $py ) = ( $x, $y );
        while ($raw) {
            my $index  = unpack( "C", chop($raw) );
            my $colour = $colours[$index];

            $image->set_colour(
                $colour->{r} / 256,
                $colour->{g} / 256,
                $colour->{b} / 256, 255
            );
            $image->draw_point( $px, $py );
            $px++;
            if ( $px >= $x + $w ) {
                $px = $x;
                $py++;
            }
        }
    }

    return $image;
}

1;

__END__

=head1 NAME

Net::VNC - A simple VNC client

=head1 SYNOPSIS
    
  use Net::VNC;

  my $vnc = Net::VNC->new({hostname => $hostname, password => $password});
  $vnc->login;

  print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n";

  my $image = $vnc->capture;
  $image->save("out.png");

=head1 DESCRIPTION

Virtual Network Computing (VNC) is a desktop sharing system which uses
the RFB (Remote FrameBuffer) protocol to remotely control another
computer. This module acts as a VNC client and communicates to a VNC
server using the RFB protocol, allowing you to capture the screen of
the remote computer.

This module dies upon connection errors (with a timeout of 15 seconds)
and protocol errors.

=head1 METHODS

=head2 new

The constructor. Given a hostname and a password returns a L<Net::VNC> object:

  my $vnc = Net::VNC->new({hostname => $hostname, password => $password});

=head2 login

Logs into the remote computer:

  $vnc->login;

=head2 name

Returns the name of the remote computer:

  print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n";

=head2 width

Returns the width of the remote screen:

  print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n";

=head2 height

Returns the height of the remote screen:

  print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n";

=head2 capture

Captures the screen of the remote computer, returning an L<Image::Imlib2> object:

  my $image = $vnc->capture;
  $image->save("out.png");

=head1 AUTHOR

Leon Brocard acme@astray.com

Many thanks for Foxtons Ltd for giving me the opportunity to write
this module.

=head1 COPYRIGHT

Copyright (C) 2006, Leon Brocard

This module is free software; you can redistribute it or modify it
under the same terms as Perl itself.
 
