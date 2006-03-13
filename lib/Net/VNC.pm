package Net::VNC;
use strict;
use warnings;
use base qw(Class::Accessor::Fast);
use Crypt::DES;
use Image::Imlib2;
use IO::Socket::INET;
use bytes;
__PACKAGE__->mk_accessors(
    qw(hostname port password socket name width height depth save_bandwidth
        _pixinfo _colourmap _framebuffer _rfb_version
        _bpp _true_colour _big_endian
        )
);
our $VERSION = '0.31';

my $MAX_PROTOCOL_VERSION = 'RFB 003.008' . chr(0x0a);  # Max version supported

# The numbers in the hashes below were acquired from the VNC source code
my %supported_depths = (
    '24' => {
        bpp         => 32,
        true_colour => 1,
        red_max     => 255,
        green_max   => 255,
        blue_max    => 255,
        red_shift   => 16,
        green_shift => 8,
        blue_shift  => 0,
    },
    '16' => {
        bpp         => 16,
        true_colour => 1,
        red_max     => 31,
        green_max   => 31,
        blue_max    => 31,
        red_shift   => 10,
        green_shift => 5,
        blue_shift  => 0,
    },
    '8' => {
        bpp         => 8,
        true_colour => 0,
        red_max     => 255,
        green_max   => 255,
        blue_max    => 255,
        red_shift   => 16,
        green_shift => 8,
        blue_shift  => 0,
    },

    # Unused right now, but supportable
    '8t' => {
        bpp         => 8,
        true_colour => 1,    #!!!
        red_max     => 7,
        green_max   => 7,
        blue_max    => 3,
        red_shift   => 0,
        green_shift => 3,
        blue_shift  => 6,
    },
);

sub login {
    my $self     = shift;
    my $hostname = $self->hostname;
    my $port     = $self->port;
    my $socket   = IO::Socket::INET->new(
        PeerAddr => $hostname || 'localhost',
        PeerPort => $port     || '5900',
        Proto    => 'tcp',
        Timeout  => 15,
        )
        || die "Error connecting to $hostname: $!";
    $self->socket($socket);

    eval {
        $self->_handshake_protocol_version();
        $self->_handshake_security();
        $self->_client_initialization();
        $self->_server_initialization();
    };
    my $error = $@;    # store so it doesn't get overwritten
    if ($error) {

        # clean up so socket can be garbage collected
        $self->socket(undef);
        die $error;
    }
}

sub _handshake_protocol_version {
    my $self = shift;

    my $socket = $self->socket;
    $socket->read( my $protocol_version, 12 ) || die 'unexpected end of data';

    #    warn "prot: $protocol_version";

    my $protocol_pattern = qr/\A RFB [ ] (\d{3}\.\d{3}) \s* \z/xms;
    if ( $protocol_version !~ m/$protocol_pattern/xms ) {
        die 'Malformed RFB protocol: ' . $protocol_version;
    }
    $self->_rfb_version($1);

    if ( $protocol_version gt $MAX_PROTOCOL_VERSION ) {
        $protocol_version = $MAX_PROTOCOL_VERSION;

        # Repeat with the changed version
        if ( $protocol_version !~ m/$protocol_pattern/xms ) {
            die 'Malformed RFB protocol';
        }
        $self->_rfb_version($1);
    }

    if ( $self->_rfb_version lt '003.003' ) {
        die 'RFB protocols earlier than v3.3 are not supported';
    }

   # let's use the same version of the protocol, or the max, whichever's lower
    $socket->print($protocol_version);
}

sub _handshake_security {
    my $self = shift;

    my $socket = $self->socket;

    # Retrieve list of security options
    my $security_type;
    if ( $self->_rfb_version ge '003.007' ) {
        $socket->read( my $number_of_security_types, 1 )
            || die 'unexpected end of data';
        $number_of_security_types = unpack( 'C', $number_of_security_types );

        #    warn "types: $number_of_security_types";

        if ( $number_of_security_types == 0 ) {
            die 'Error authenticating';
        }

        my @security_types;
        foreach ( 1 .. $number_of_security_types ) {
            $socket->read( my $security_type, 1 )
                || die 'unexpected end of data';
            $security_type = unpack( 'C', $security_type );

            #        warn "sec: $security_type";
            push @security_types, $security_type;
        }

        for my $preferred_type ( 2, 1 ) {
            if ( 0 < grep { $_ == $preferred_type } @security_types ) {
                $security_type = $preferred_type;
                last;
            }
        }
    } else {

        # In RFB 3.3, the server dictates the security type
        $socket->read( $security_type, 4 ) || die 'unexpected end of data';
        $security_type = unpack( 'N', $security_type );
    }

    if ( !$security_type ) {

        die 'Connection failed';

    } elsif ( $security_type == 2 ) {

        # DES-encrypted challenge/response

        if ( $self->_rfb_version ge '003.007' ) {
            $socket->print( pack( 'C', 2 ) );
        }

        $socket->read( my $challenge, 16 ) || die 'unexpected end of data';

        #    warn "chal: " . unpack('h*', $challenge) . "\n";

        my $key = $self->password;
        $key = '' if ( !defined $key );
        $key .= pack( 'C', 0 ) until ( length($key) % 8 ) == 0;

        my $realkey;

        #    warn unpack('b*', $key);
        foreach my $byte ( split //, $key ) {
            $realkey .= pack( 'b8', scalar reverse unpack( 'b8', $byte ) );
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

    } elsif ( $security_type == 1 ) {

        # No authorization needed!
        if ( $self->_rfb_version ge '003.007' ) {
            $socket->print( pack( 'C', 1 ) );
        }

    } else {

        die "no supported vnc authentication mechanism";

    }

    if ( $self->_rfb_version ge '003.008' ) {
        $socket->read( my $security_result, 4 )
            || die 'unexpected end of data';
        $security_result = unpack( 'I', $security_result );

        #    warn $security_result;
        die 'login failed' if $security_result;
    }

    #elsif (!$socket->connected) {
    elsif ( $socket->eof ) {    # XXX Should this be !$socket->connected??
        die 'login failed';
    }
}

sub _client_initialization {
    my $self = shift;

    my $socket = $self->socket;

    $socket->print( pack( 'C', 1 ) );    # share
}

sub _server_initialization {
    my $self = shift;

    my $socket = $self->socket;
    $socket->read( my $server_init, 24 ) || die 'unexpected end of data';

    my ( $framebuffer_width, $framebuffer_height, $bits_per_pixel, $depth,
        $big_endian_flag, $true_colour_flag, %pixinfo, $name_length );
    (   $framebuffer_width,  $framebuffer_height,   $bits_per_pixel,
        $depth,              $big_endian_flag,      $true_colour_flag,
        $pixinfo{red_max},   $pixinfo{green_max},   $pixinfo{blue_max},
        $pixinfo{red_shift}, $pixinfo{green_shift}, $pixinfo{blue_shift},
        $name_length
        )
        = unpack 'nnCCCCnnnCCCxxxN', $server_init;

    #    warn "$framebuffer_width x $framebuffer_height";

#    warn "$bits_per_pixel bpp / depth $depth / $big_endian_flag be / $true_colour_flag tc / $pixinfo{red_max},$pixinfo{green_max},$pixinfo{blue_max} / $pixinfo{red_shift},$pixinfo{green_shift},$pixinfo{blue_shift}";

    #    warn $name_length;

    if ( !$self->depth ) {

# client did not express a depth preference, so check if the server's preference is OK
        if ( !$supported_depths{$depth} ) {
            die 'Unsupported depth ' . $depth;
        }
        if ( $bits_per_pixel != $supported_depths{$depth}->{bpp} ) {
            die 'Unsupported bits-per-pixel value ' . $bits_per_pixel;
        }
        if ($true_colour_flag
            ? !$supported_depths{$depth}->{true_colour}
            : $supported_depths{$depth}->{true_colour}
            )
        {
            die 'Unsupported true colour flag';
        }
        $self->depth($depth);

        # Use server's values for *_max and *_shift

    } elsif ( $depth != $self->depth ) {
        for my $key (
            qw(red_max green_max blue_max red_shift green_shift blue_shift))
        {
            $pixinfo{$key} = $supported_depths{ $self->depth }->{$key};
        }
    }

    # This line comes from perlport.pod
    my $am_big_endian = unpack( 'h*', pack( 's', 1 ) ) =~ /01/;

    if ( !$self->width ) {
        $self->width($framebuffer_width);
    }
    if ( !$self->height ) {
        $self->height($framebuffer_height);
    }
    $self->_pixinfo( \%pixinfo );
    $self->_bpp( $supported_depths{ $self->depth }->{bpp} );
    $self->_true_colour( $supported_depths{ $self->depth }->{true_colour} );
    $self->_big_endian($am_big_endian);

    $socket->read( my $name_string, $name_length )
        || die 'unexpected end of data';
    $self->name($name_string);

    #    warn $name_string;

    # setpixelformat
    $socket->print(
        pack(
            'CCCCCCCCnnnCCCCCC',
            0,    # message_type
            0,    # padding
            0,    # padding
            0,    # padding
            $self->_bpp,
            $self->depth,
            $self->_big_endian,
            $self->_true_colour,
            $pixinfo{red_max},
            $pixinfo{green_max},
            $pixinfo{blue_max},
            $pixinfo{red_shift},
            $pixinfo{green_shift},
            $pixinfo{blue_shift},
            0,    # padding
            0,    # padding
            0,    # padding
        )
    );

    # set encodings
    if ( $self->save_bandwidth ) {
        $socket->print(
            pack(
                'CCnNNNN',
                2,    # message_type
                0,    # padding
                4,    # number_of_encodings
                1,    # CopyRect
                5,    # Hextile
                2,    # RRE
                0,    # Raw
            )
        );
    } else {
        $socket->print(
            pack(
                'CCnNNN',
                2,    # message_type
                0,    # padding
                3,    # number_of_encodings
                1,    # CopyRect
                2,    # RRE
                0,    # Raw
            )
        );
    }

    # Disabled encoding:
    # pack pattern = 'i'
    #4294967057,    # cursor pseudo-encoding
}

sub capture {
    my $self   = shift;
    my $socket = $self->socket;

    #$self->_send_pointer_event();
    $self->_send_update_request();
    while ( ( my $message_type = $self->_receive_message() ) != 0 ) {

        #    warn $message_type;
    }

    return $self->_framebuffer;
}

sub _send_pointer_event {
    my $self = shift;

    # pointer event - doesn't seem to work?
    my $socket = $self->socket;
    $socket->print(
        pack(
            'CCnn',
            5,                # message_type
            0,                # button_mask
            $self->width,     # x
            $self->height,    # y
        )
    );
}

sub _send_update_request {
    my $self = shift;

    # frame buffer update request
    my $socket = $self->socket;
    my $incremental = $self->_framebuffer ? 1 : 0;
    $socket->print(
        pack(
            'CCnnnn',
            3,               # message_type
            $incremental,    # incremental
            0,               # x
            0,               # y
            $self->width,
            $self->height,
        )
    );
}

sub _receive_message {
    my $self = shift;

    my $socket = $self->socket;
    $socket->read( my $message_type, 1 ) || die 'unexpected end of data';
    $message_type = unpack( 'C', $message_type );

    #    warn $message_type;

    my $result =
          !defined $message_type ? die 'bad message type received'
        : $message_type == 0     ? $self->_receive_update()
        : $message_type == 1     ? $self->_receive_colour_map()
        : die 'unsupported message type received';

    return $message_type;
}

sub _receive_update {
    my $self = shift;

    my $image = $self->_framebuffer;
    if ( !$image ) {
        $self->_framebuffer( $image
                = Image::Imlib2->new( $self->width, $self->height ) );
    }

    my $socket = $self->socket;
    $socket->read( my $header, 3 ) || die 'unexpected end of data';
    my $number_of_rectangles = unpack( 'xn', $header );

    #    warn $number_of_rectangles;

    my $colours         = $self->_colourmap;
    my $depth           = $self->depth;
    my $bpp             = $self->_bpp;
    my $bytes_per_pixel = $bpp / 8;
    my $depth_bytes     = $depth / 8;
    my $pixinfo         = $self->_pixinfo;
    my $format;

    die 'unsupported bits-per-pixel' if ( $bpp % 8 != 0 );
    die 'unsupported depth'          if ( $depth % 8 != 0 );

    if ($colours) {
        if ( $depth != 8 ) {
            die 'Indexed colour only supported for 8 bit displays';
        }
    } else {
        $format =
              $bpp == 32 ? 'L'
            : $bpp == 16 ? 'S'
            : die 'Unsupported bits-per-pixel value';
    }

    foreach ( 1 .. $number_of_rectangles ) {
        $socket->read( my $data, 12 ) || die 'unexpected end of data';
        my ( $x, $y, $w, $h, $encoding_type ) = unpack 'nnnnN', $data;

        #        warn "$x,$y $w x $h $encoding_type";

        ### Raw encoding ###
        if ( $encoding_type == 0 ) {

            for my $py ( $y .. $y + $h - 1 ) {
                for my $px ( $x .. $x + $w - 1 ) {
                    $self->_read_and_set_colour();
                    $image->draw_point( $px, $py );
                }
            }

            ### CopyRect encooding ###
        } elsif ( $encoding_type == 1 ) {

            $socket->read( my $srcpos, 4 ) || die 'unexpected end of data';
            my ( $srcx, $srcy ) = unpack 'nn', $srcpos;

            my $copy = $image->crop( $srcx, $srcy, $w, $h );
            $image->blend( $copy, 0, 0, 0, $w, $h, $x, $y, $w, $h );

            ### RRE encoding ###
        } elsif ( $encoding_type == 2 ) {

            $socket->read( my $num_sub_rects, 4 )
                || die 'unexpected end of data';
            $num_sub_rects = unpack 'N', $num_sub_rects;

            $self->_read_and_set_colour();
            $image->fill_rectangle( $x, $y, $w, $h );

            for my $i ( 1 .. $num_sub_rects ) {

                $self->_read_and_set_colour();
                $socket->read( my $subrect, 8 )
                    || die 'unexpected end of data';
                my ( $sx, $sy, $sw, $sh ) = unpack 'nnnn', $subrect;
                $image->fill_rectangle( $x + $sx, $y + $sy, $sw, $sh );

            }

            ### Hextile encoding ###
        } elsif ( $encoding_type == 5 ) {

            my $maxx = $x + $w;
            my $maxy = $y + $h;
            my $background;
            my $foreground;
            for ( my $ry = $y; $ry < $maxy; $ry += 16 ) {
                my $rh = $maxy - $ry > 16 ? 16 : $maxy - $ry;
                for ( my $rx = $x; $rx < $maxx; $rx += 16 ) {
                    my $rw = $maxx - $rx > 16 ? 16 : $maxx - $rx;
                    $socket->read( my $mask, 1 )
                        || die 'unexpected end of data';
                    $mask = unpack 'C', $mask;

                    if ( $mask & 0x1 ) {    # Raw tile
                        for my $py ( $ry .. $ry + $rh - 1 ) {
                            for my $px ( $rx .. $rx + $rw - 1 ) {
                                $self->_read_and_set_colour();
                                $image->draw_point( $px, $py );
                            }
                        }

                    } else {

                        if ( $mask & 0x2 ) {    # background set
                            $background = $self->_read_and_set_colour();
                        }
                        if ( $mask & 0x4 ) {    # foreground set
                            $foreground = $self->_read_and_set_colour();
                        }
                        if ( $mask & 0x8 ) {    # has subrects

                            $socket->read( my $nsubrects, 1 )
                                || die 'unexpected end of data';
                            $nsubrects = unpack 'C', $nsubrects;

                            if ( !$mask & 0x10 ) {    # use foreground colour
                                $image->set_colour( @{$foreground} );
                            }
                            for my $i ( 1 .. $nsubrects ) {
                                if ( $mask & 0x10 ) { # use per-subrect colour
                                    $self->_read_and_set_colour();
                                }
                                $socket->read( my $pos, 1 )
                                    || die 'unexpected end of data';
                                $pos = unpack 'C', $pos;
                                $socket->read( my $size, 1 )
                                    || die 'unexpected end of data';
                                $size = unpack 'C', $size;
                                my $sx = $pos >> 4;
                                my $sy = $pos & 0xff;
                                my $sw = 1 + ( $size >> 4 );
                                my $sh = 1 + ( $size & 0xff );
                                $image->fill_rectangle( $rx + $sx, $ry + $sy,
                                    $sw, $sh );
                            }

                        } else {    # no subrects
                            $image->set_colour( @{$background} );
                            $image->fill_rectangle( $rx, $ry, $rw, $rh );
                        }
                    }
                }
            }

        } else {
            die 'unsupported update encoding ' . $encoding_type;

        }
    }

    return 1;
}

sub _read_and_set_colour {
    my $self  = shift;
    my $pixel = shift;

    my $colours         = $self->_colourmap;
    my $bytes_per_pixel = $self->_bpp / 8;
    if ( !$pixel ) {
        $self->socket->read( $pixel, $bytes_per_pixel )
            || die 'unexpected end of data';
    }
    my @colour;
    if ($colours) {    # indexed colour, depth is 8
        my $index = unpack( 'C', $pixel );
        my $colour = $colours->[$index];
        @colour = ( $colour->{r}, $colour->{g}, $colour->{b}, 255 );
    } else {           # true colour, depth is 24 or 16
        my $pixinfo = $self->_pixinfo;
        my $format  =
              $bytes_per_pixel == 4 ? 'L'
            : $bytes_per_pixel == 2 ? 'S'
            : die 'Unsupported bits-per-pixel value';
        my $colour = unpack $format, $pixel;
        my $r = $colour >> $pixinfo->{red_shift} & $pixinfo->{red_max};
        my $g = $colour >> $pixinfo->{green_shift} & $pixinfo->{green_max};
        my $b = $colour >> $pixinfo->{blue_shift} & $pixinfo->{blue_max};
        if ( $bytes_per_pixel == 4 ) {
            @colour = ( $r, $g, $b, 255 );
        } else {
            @colour = (
                $r * 255 / $pixinfo->{red_max},
                $g * 255 / $pixinfo->{green_max},
                $b * 255 / $pixinfo->{blue_max}, 255
            );
        }
    }
    $self->_framebuffer->set_colour(@colour);
    return \@colour;
}

sub _receive_colour_map {
    my $self = shift;

    # set colour map entries
    my $socket = $self->socket;
    $socket->read( my $padding,      1 ) || die 'unexpected end of data';
    $socket->read( my $first_colour, 2 ) || die 'unexpected end of data';
    $first_colour = unpack( 'n', $first_colour );
    $socket->read( my $number_of_colours, 2 ) || die 'unexpected end of data';
    $number_of_colours = unpack( 'n', $number_of_colours );

    #    warn "colours: $first_colour.. ($number_of_colours)";

    my @colours;
    foreach my $i ( $first_colour .. $first_colour + $number_of_colours - 1 )
    {
        $socket->read( my $r, 2 ) || die 'unexpected end of data';
        $r = unpack( 'n', $r );
        $socket->read( my $g, 2 ) || die 'unexpected end of data';
        $g = unpack( 'n', $g );
        $socket->read( my $b, 2 ) || die 'unexpected end of data';
        $b = unpack( 'n', $b );

        #        warn "$i $r/$g/$b";

        # The 8-bit colours are in the top byte of each field
        $colours[$i] = { r => $r >> 8, g => $g >> 8, b => $b >> 8 };
    }
    $self->_colourmap( \@colours );
    return 1;
}

1;

__END__

=head1 NAME

Net::VNC - A simple VNC client

=head1 SYNOPSIS
    
  use Net::VNC;

  my $vnc = Net::VNC->new({hostname => $hostname, password => $password});
  $vnc->depth(24);
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

This implementation is based largely on the RFB Protocol
Specification, L<http://www.realvnc.com/docs/rfbproto.pdf>.  That
document has an error in the DES encryption description, which is
clarified via L<http://www.vidarholen.net/contents/junk/vnc.html>.

=head1 METHODS

=head2 new

The constructor. Given a hostname and a password returns a L<Net::VNC> object:

  my $vnc = Net::VNC->new({hostname => $hostname, password => $password});

Optionally, you can also specify a port, which defaults to 5900.

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

You may call capture() multiple times.  Each time, the C<$image>
buffer is overwritten with the updated screen.  So, to create a
series of ten screen shots:

  for my $n (1..10) {
    my $filename = sprintf 'snapshot%02d.png', $n++;
    $vnc->capture()->save($filename);
    print "Wrote $filename\n";
  }

=head2 depth

Specify the bit depth for the screen.  The supported choices are 24,
16 or 8.  If unspecified, the server's default value is used.  This
property should be set before the call to login().

=head2 save_bandwidth

Accepts a boolean, defaults to false.  Specifies whether to use more
CPU-intensive algorithms to compress the VNC datastream.  LAN or
localhost connections may prefer to leave this false.  This property
should be set before the call to login().

=head1 BUGS AND LIMITATIONS

=head2 Bit depth

We do not yet support 8-bit true-colour mode, which is commonly
supported by servers but is rarely employed by clients.

=head2 Byte order

We have currently tested this package against servers with the same
byte order as the client.  This might break with a little-endian
server/big-endian client or vice versa.  We're working on tests for
those latter cases.  Testing and patching help would be appreciated.

=head2 Efficiency

We've implemented a subset of the data compression algorithms
supported by most VNC servers.  We hope to add more of the
high-compression transfer encodings in the future.

=head1 AUTHORS

Leon Brocard acme@astray.com

Chris Dolan clotho@cpan.org

Many thanks for Foxtons Ltd for giving Leon the opportunity to write
the original version of this module.

Copyright (C) 2006, Leon Brocard

This module is free software; you can redistribute it or modify it
under the same terms as Perl itself.
 
