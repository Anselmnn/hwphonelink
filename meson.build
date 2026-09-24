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
dep_libnl_route = dependency('libnl-route-3.0', required: true)
dep_glib = dependency('glib-2.0', required: true)
dep_gio = dependency('gio-2.0', required: true)
dep_gobject = dependency('gobject-2.0', required: true)
dep_json_glib = dependency('json-glib-1.0', required: true)
dep_openssl = dependency('openssl', required: true)

# Threads
thread_dep = dependency('threads')

# Compiler flags
add_project_arguments([
  '-D_GNU_SOURCE',
  '-DFILE_OFFSET_BITS=64',
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
  'src/proto/softbus_defs.h',
  'src/proto/softbus_frame.h',
  'src/proto/softbus_device.h',
  'src/proto/softbus_crypto.h',
  'src/proto/softbus_auth.h',
  'src/proto/softbus_session.h',
]

inc = include_directories('src')

# dsoftbus protocol core (M2): frame codec, discovery beacon, crypto,
# HiChain auth FSM, session layer.
proto_sources = [
  'src/proto/softbus_frame.c',
  'src/proto/softbus_device.c',
  'src/proto/softbus_crypto.c',
  'src/proto/softbus_auth.c',
  'src/proto/softbus_session.c',
]

proto_lib = library(
  'hwphonelink-proto',
  proto_sources,
  include_directories: inc,
  dependencies: [dep_glib, dep_gio, dep_gobject, dep_json_glib, dep_openssl, thread_dep],
  install: true,
  install_dir: libdir,
)

# Core transport library
transport_sources = [
  'src/transport/wifi_transport.c',
  'src/transport/softap_backend.c',
  'src/transport/p2p_backend.c',
  'src/transport/infra_backend.c',
  'src/transport/netlink_utils.c',
]

transport_lib = library(
  'hwphonelink-transport',
  transport_sources,
  include_directories: inc,
  link_with: proto_lib,
  dependencies: [dep_libnl3, dep_libnl_genl, dep_libnl_route, dep_glib, dep_gio, dep_gobject, thread_dep],
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
  link_with: [transport_lib, proto_lib],
  include_directories: inc,
  dependencies: [dep_libnl3, dep_libnl_genl, dep_glib, dep_gio, dep_gobject, thread_dep],
  install: true,
  install_dir: bindir,
)

# ============================ Tests (M2) ============================

# Protocol core unit tests (frame codec, beacon, crypto, auth FSM, session).
# No network needed — runs in CI via `ninja test`.
proto_test = executable(
  'hwphonelink-proto-test',
  'tests/proto_test.c',
  link_with: proto_lib,
  include_directories: inc,
  dependencies: [dep_glib, dep_gio, thread_dep],
)
test('proto', proto_test)

# Replay-stand mock phone: CoAP beacon + PSK auth + session echo over TCP.
# Manual e2e target: run the daemon (--infra) and this binary against it.
mock_phone = executable(
  'hwphonelink-mock-phone',
  'tests/mock_phone.c',
  link_with: proto_lib,
  include_directories: inc,
  dependencies: [dep_glib, dep_gio, thread_dep],
  install: true,
  install_dir: bindir,
)

# Config templates
conf_data = configuration_data()
conf_data.set('PREFIX', prefix)
conf_data.set('SYSCONFDIR', sysconfdir)
conf_data.set('BINDIR', bindir)
conf_data.set('AP_INTERFACE', 'wlp1s0_ap')
conf_data.set('SSID', 'HUAWEI_PC')
conf_data.set('HW_MODE', 'a')
conf_data.set('CHANNEL', '40')
conf_data.set('PASSPHRASE', '')
conf_data.set('AP_IP', '192.168.137.1')
conf_data.set('DHCP_START', '192.168.137.2')
conf_data.set('DHCP_END', '192.168.137.254')
conf_data.set('CONFIG_DIR', join_paths(sysconfdir, 'hwphonelink'))
conf_data.set('RUN_DIR', '/run/hwphonelink')

configure_file(
  input: 'data/hostapd.conf.template',
  output: 'hostapd.conf',
  configuration: conf_data,
  install: true,
  install_dir: join_paths(sysconfdir, 'hwphonelink'),
)

configure_file(
  input: 'data/dnsmasq.conf.template',
  output: 'dnsmasq.conf',
  configuration: conf_data,
  install: true,
  install_dir: join_paths(sysconfdir, 'hwphonelink'),
)

# Systemd service
systemd_service = configure_file(
  input: 'systemd/hwphonelink.service.in',
  output: 'hwphonelink.service',
  configuration: conf_data,
  install: true,
  install_dir: systemd_unitdir,
)

# Udev rules (copy as-is, no substitution)
udev_rules = configure_file(
  input: 'data/99-hwphonelink.rules',
  output: '99-hwphonelink.rules',
  copy: true,
  install: true,
  install_dir: join_paths(prefix, 'lib', 'udev', 'rules.d'),
)

# Summary
summary = {
  'Project': meson.project_name(),
  'Version': meson.project_version(),
  'Prefix': prefix,
  'Proto library': 'libhwphonelink-proto.so',
  'Transport library': 'libhwphonelink-transport.so',
  'Daemon': 'hwphonelinkd',
  'Mock phone': 'hwphonelink-mock-phone',
  'Config dir': join_paths(sysconfdir, 'hwphonelink'),
}

foreach key, val: summary
  message(key + ': ' + val)
endforeach