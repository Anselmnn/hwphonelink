project('hwphonelink', 'c',
  version: '0.1.0',
  default_options: [
    'warning_level=2',
    'werror=false',
    'c_std=c11',
    'buildtype=debugoptimized',
  ])

# Dependencies
dep_libnl3 = dependency('libnl-3.0', required: true)
dep_libnl_genl = dependency('libnl-genl-3.0', required: true)
dep_glib = dependency('glib-2.0', required: true)
dep_gio = dependency('gio-2.0', required: true)
dep_gobject = dependency('gobject-2.0', required: true)

# Threads
thread_dep = dependency('threads')

# Compiler flags
add_project_arguments([
  '-D_GNU_SOURCE',
  '-DFILE_OFFSET_BITS=64',
  '-Wall',
  '-Wextra',
  '-Wno-unused-parameter',
], language: 'c')

# Installation paths
prefix = get_option('prefix')
bindir = join_paths(prefix, 'bin')
libdir = join_paths(prefix, 'lib')
sysconfdir = join_paths(prefix, 'etc')
systemd_unitdir = join_paths(prefix, 'lib', 'systemd', 'system')

# Headers
headers = [
  'src/transport/wifi_transport.h',
  'src/transport/softap_backend.h',
  'src/transport/p2p_backend.h',
  'src/transport/netlink_utils.h',
]

# Core transport library
transport_sources = [
  'src/transport/wifi_transport.c',
  'src/transport/softap_backend.c',
  'src/transport/p2p_backend.c',
  'src/transport/netlink_utils.c',
]

transport_lib = library(
  'hwphonelink-transport',
  transport_sources,
  include_directories: include_directories('src'),
  dependencies: [dep_libnl3, dep_libnl_genl, dep_glib, dep_gio, dep_gobject, thread_dep],
  install: true,
  install_dir: libdir,
)

# Main daemon
daemon_sources = [
  'src/main.c',
]

daemon = executable(
  'hwphonelinkd',
  daemon_sources,
  dependencies: [transport_lib, dep_libnl3, dep_libnl_genl, dep_glib, dep_gio, dep_gobject, thread_dep],
  install: true,
  install_dir: bindir,
)

# Config templates
configure_file(
  input: 'data/hostapd.conf.template',
  output: 'hostapd.conf',
  configuration: {'PREFIX': prefix, 'SYSCONFDIR': sysconfdir},
  install: true,
  install_dir: join_paths(sysconfdir, 'hwphonelink'),
)

configure_file(
  input: 'data/dnsmasq.conf.template',
  output: 'dnsmasq.conf',
  configuration: {'PREFIX': prefix, 'SYSCONFDIR': sysconfdir},
  install: true,
  install_dir: join_paths(sysconfdir, 'hwphonelink'),
)

# Systemd service
systemd_service = configure_file(
  input: 'systemd/hwphonelink.service.in',
  output: 'hwphonelink.service',
  configuration: {'BINDIR': bindir},
  install: true,
  install_dir: systemd_unitdir,
)

# Udev rules
udev_rules = configure_file(
  input: 'data/99-hwphonelink.rules',
  output: '99-hwphonelink.rules',
  install: true,
  install_dir: join_paths(prefix, 'lib', 'udev', 'rules.d'),
)

# Summary
summary = {
  'Project': meson.project_name(),
  'Version': meson.project_version(),
  'Prefix': prefix,
  'Transport library': 'libhwphonelink-transport.so',
  'Daemon': 'hwphonelinkd',
  'Config dir': join_paths(sysconfdir, 'hwphonelink'),
}

foreach key, val: summary
  message(key + ': ' + val)
endforeach