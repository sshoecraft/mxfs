package PVE::Storage::Custom::MXFSPlugin;

use strict;
use warnings;
use File::Path;

use PVE::Tools qw(run_command);
use PVE::ProcFSTools;
use PVE::Storage::Plugin;
use PVE::JSONSchema qw(get_standard_option);

use base qw(PVE::Storage::Plugin);

# PVE Custom Storage Plugin API version
# Must be between (APIVER - APIAGE) and APIVER.
# PVE warns if api() != APIVER, so return the exact APIVER when it
# falls within our tested range. This covers PVE 8 (APIVER 10) through
# PVE 9 (APIVER 13) without maintaining separate plugin files.
sub api {
    my $pve_apiver = eval { PVE::Storage::APIVER() };
    if (defined $pve_apiver) {
        return $pve_apiver if $pve_apiver >= 10 && $pve_apiver <= 13;
    }
    return 10;
}

# Helper functions

sub mxfs_is_mounted {
    my ($device, $mountpoint, $mountdata) = @_;

    $mountdata = PVE::ProcFSTools::parse_proc_mounts() if !$mountdata;
    return $mountpoint if grep {
        $_->[2] eq 'mxfs'
            && $_->[0] eq $device
            && $_->[1] eq $mountpoint
    } @$mountdata;
    return undef;
}

# Check if device is mounted anywhere (returns mountpoint or undef)
sub mxfs_device_mounted_at {
    my ($device, $mountdata) = @_;

    $mountdata = PVE::ProcFSTools::parse_proc_mounts() if !$mountdata;
    for my $entry (@$mountdata) {
        if ($entry->[2] eq 'mxfs' && $entry->[0] eq $device) {
            return $entry->[1];
        }
    }
    return undef;
}

sub mxfs_mount {
    my ($device, $mountpoint, $options) = @_;

    my $cmd = ['/bin/mount', '-t', 'mxfs', $device, $mountpoint];
    if ($options) {
        push @$cmd, '-o', $options;
    }

    run_command($cmd, errmsg => "mount error");
}

sub mxfs_ensure_module {
    my $loaded = 0;
    if (open(my $fh, '<', '/proc/modules')) {
        while (<$fh>) {
            if (/^mxfs\s/) {
                $loaded = 1;
                last;
            }
        }
        close($fh);
    }
    if (!$loaded) {
        run_command(['/sbin/modprobe', 'mxfs'], errmsg => "modprobe mxfs failed");
    }
}

# Configuration

sub type {
    return 'mxfs';
}

sub plugindata {
    return {
        content => [
            {
                images => 1,
                rootdir => 1,
                vztmpl => 1,
                iso => 1,
                backup => 1,
                snippets => 1,
                import => 1,
            },
            { images => 1, rootdir => 1 },
        ],
        format => [{ raw => 1, qcow2 => 1, vmdk => 1 }, 'raw'],
        'sensitive-properties' => {},
    };
}

sub properties {
    return {
        blockdevice => {
            description => "Block device path (e.g. /dev/sdb).",
            type => 'string',
        },
    };
}

sub options {
    return {
        path => { fixed => 1 },
        'content-dirs' => { optional => 1 },
        blockdevice => { fixed => 1 },
        nodes => { optional => 1 },
        shared => { optional => 1 },
        disable => { optional => 1 },
        'prune-backups' => { optional => 1 },
        'max-protected-backups' => { optional => 1 },
        content => { optional => 1 },
        format => { optional => 1 },
        options => { optional => 1 },
        'create-base-path' => { optional => 1 },
        'create-subdirs' => { optional => 1 },
        bwlimit => { optional => 1 },
        preallocation => { optional => 1 },
    };
}

sub check_config {
    my ($class, $sectionId, $config, $create, $skipSchemaCheck) = @_;

    $config->{path} = "/mnt/pve/$sectionId" if $create && !$config->{path};
    $config->{shared} = 1 if $create;

    return $class->SUPER::check_config($sectionId, $config, $create, $skipSchemaCheck);
}

# Storage implementation

sub status {
    my ($class, $storeid, $scfg, $cache) = @_;

    $cache->{mountdata} = PVE::ProcFSTools::parse_proc_mounts()
        if !$cache->{mountdata};

    my $path = $scfg->{path};
    my $device = $scfg->{blockdevice};

    return undef if !mxfs_is_mounted($device, $path, $cache->{mountdata});

    return $class->SUPER::status($storeid, $scfg, $cache);
}

sub activate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    $cache->{mountdata} = PVE::ProcFSTools::parse_proc_mounts()
        if !$cache->{mountdata};

    my $path = $scfg->{path};
    my $device = $scfg->{blockdevice};

    if (!mxfs_is_mounted($device, $path, $cache->{mountdata})) {
        mxfs_ensure_module();

        # If device is mounted at a different path (e.g. stale mount from
        # before config removal), unmount it first so we can remount at
        # the correct path.
        my $stale = mxfs_device_mounted_at($device, $cache->{mountdata});
        if ($stale) {
            run_command(['/bin/umount', $stale],
                        errmsg => "unmount stale $stale");
            # Refresh mount data after unmount
            $cache->{mountdata} = PVE::ProcFSTools::parse_proc_mounts();
        }

        $class->config_aware_base_mkdir($scfg, $path);

        die "unable to activate storage '$storeid' - "
            . "directory '$path' does not exist\n"
            if !-d $path;

        die "unable to activate storage '$storeid' - "
            . "block device '$device' does not exist\n"
            if !-b $device;

        mxfs_mount($device, $path, $scfg->{options});
    }

    $class->SUPER::activate_storage($storeid, $scfg, $cache);
}

sub deactivate_storage {
    my ($class, $storeid, $scfg, $cache) = @_;

    $cache->{mountdata} = PVE::ProcFSTools::parse_proc_mounts()
        if !$cache->{mountdata};

    my $path = $scfg->{path};
    my $device = $scfg->{blockdevice};

    if (mxfs_is_mounted($device, $path, $cache->{mountdata})) {
        my $cmd = ['/bin/umount', $path];
        run_command($cmd, errmsg => 'umount error');
    }
}

sub check_connection {
    my ($class, $storeid, $scfg) = @_;

    my $device = $scfg->{blockdevice};

    # Check that the block device exists and is accessible
    return 0 if !-b $device;
    return 1;
}

# Delegate volume operations to DirPlugin

sub get_volume_notes {
    my $class = shift;
    PVE::Storage::DirPlugin::get_volume_notes($class, @_);
}

sub update_volume_notes {
    my $class = shift;
    PVE::Storage::DirPlugin::update_volume_notes($class, @_);
}

sub get_volume_attribute {
    return PVE::Storage::DirPlugin::get_volume_attribute(@_);
}

sub update_volume_attribute {
    return PVE::Storage::DirPlugin::update_volume_attribute(@_);
}

sub get_import_metadata {
    return PVE::Storage::DirPlugin::get_import_metadata(@_);
}

1;
