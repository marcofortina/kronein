Sample init scripts and service configuration for kroneind
===========================================================

Sample scripts and configuration files for systemd, OpenRC and macOS launchd
can be found in the contrib/init folder.

    contrib/init/kroneind.service:    systemd service unit configuration
    contrib/init/kroneind.openrc:     OpenRC compatible SysV style init script
    contrib/init/kroneind.openrcconf: OpenRC conf.d file
    contrib/init/org.kronein.kroneind.plist: macOS launch agent

Service User
---------------------------------

Both Linux startup configurations assume the existence of a "kronein" user
and group.  They must be created before attempting to use these scripts.
The macOS configuration assumes kroneind will be set up for the current user.

Configuration
---------------------------------

Running kroneind as a daemon does not require any manual configuration. You may
set the `rpcauth` setting in the `kronein.conf` configuration file to override
the default behaviour of using a special cookie for authentication.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that kroneind and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If kroneind is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but its location can be
overridden with the option `-rpccookiefile`. Default file permissions for the
cookie are "owner" (i.e. user read/writeable) via default application-wide file
umask of `0077`, but these can be overridden with the `-rpccookieperms` option.

This allows for running kroneind without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

To generate an example configuration file that describes the configuration settings,
see [contrib/devtools/README.md](../contrib/devtools/README.md#gen-kronein-confsh).

Paths
---------------------------------

### Linux

Both configurations assume several paths that might need to be adjusted.

    Binary:              /usr/bin/kroneind
    Configuration file:  /etc/kronein/kronein.conf
    Data directory:      /var/lib/kroneind
    PID file:            /var/run/kroneind/kroneind.pid (OpenRC) or
                         /run/kroneind/kroneind.pid (systemd)

The PID directory (if applicable) and data directory should both be owned by the
kronein user and group. It is advised for security reasons to make the
configuration file and data directory only readable by the kronein user and
group. Access to kronein-cli and other kroneind RPC clients can then be
controlled by group membership.

NOTE: When using the systemd .service file, the creation of the aforementioned
directories and the setting of their permissions is automatically handled by
systemd. Directories are given a permission of 710, giving the kronein group
access to files under it _if_ the files themselves give permission to the
kronein group to do so. This does not allow
for the listing of files under the directory.

NOTE: It is not currently possible to override `datadir` in
`/etc/kronein/kronein.conf` with the current systemd and OpenRC init
files out-of-the-box. This is because the command line options specified in the
init files take precedence over the configurations in
`/etc/kronein/kronein.conf`. However, some init systems have their own
configuration mechanisms that would allow for overriding the command line
options specified in the init files (e.g. setting `BITCOIND_DATADIR` for
OpenRC).

### macOS

    Binary:              /usr/local/bin/kroneind
    Configuration file:  ~/Library/Application Support/Kronein/kronein.conf
    Data directory:      ~/Library/Application Support/Kronein
    Lock file:           ~/Library/Application Support/Kronein/.lock

Installing Service Configuration
-----------------------------------

### systemd

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start kroneind` and to enable for system startup run
`systemctl enable kroneind`

NOTE: When installing for systemd in Debian/Ubuntu the .service file needs to be copied to the /lib/systemd/system directory instead.

### OpenRC

Rename kroneind.openrc to kroneind and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/kroneind start` and configure it to run on startup with
`rc-update add kroneind`

### macOS

Copy org.kronein.kroneind.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.kronein.kroneind.plist`.

This Launch Agent will cause kroneind to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run kroneind as the current user.
You will need to modify org.kronein.kroneind.plist if you intend to use it as a
Launch Daemon with a dedicated kronein user.

Auto-respawn
-----------------------------------

Auto respawning is configured for systemd.
Reasonable defaults have been chosen but YMMV.
