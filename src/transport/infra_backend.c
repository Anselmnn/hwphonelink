/*
 * infra_backend.c - Infrastructure Mode backend (LAN/Wi-Fi/Ethernet)
 *
 * Uses existing network infrastructure (router, switch) instead of creating AP.
 * Discovery: CoAP multicast (224.0.1.187:5683) — matches PC Manager dsoftbus
 *            discovery on shared LANs (see multiscreen-spec.md §Discovery).
 * Transport: Direct TCP session listener on the local LAN IP (default :54321).
 *
 * No AP creation, no channel selection — this mode simply rides the LAN.
 */

#include "infra_backend.h"
#include "netlink_utils.h"

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define INFRA_LISTENER_POLL_MS 200  /* accept/receive poll interval for stoppable loops */

struct _HwPhoneLinkInfraBackend {
  HwPhoneLinkTransport parent_instance;
};

typedef struct {
  HwPhoneLinkInfraConfig config;
  HwPhoneLinkNlHandle *nl_handle;
  GSocketListener *tcp_listener;
  GSocket *coap_socket;
  GCancellable *worker_cancel;  /* cancels blocking accept on stop */
  GThread *discovery_thread;
  GThread *accept_thread;
  gint running;            /* atomic: 1 while worker loops are active */
  GMutex state_mutex;
  HwPhoneLinkState state;
} HwPhoneLinkInfraBackendPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(HwPhoneLinkInfraBackend, hw_phone_link_infra_backend, HWPHONELINK_TYPE_TRANSPORT)

#define HWPHONELINK_INFRA_BACKEND_GET_PRIVATE(obj) \
  (hw_phone_link_infra_backend_get_instance_private(HWPHONELINK_INFRA_BACKEND(obj)))

static HwPhoneLinkInfraBackendPrivate* _priv(HwPhoneLinkInfraBackend *self) {
  return HWPHONELINK_INFRA_BACKEND_GET_PRIVATE(self);
}

/* Virtual method implementations (forward-declared so class_init can wire them) */
static gboolean hw_phone_link_infra_backend_start(HwPhoneLinkTransport *self, GError **error);
static gboolean hw_phone_link_infra_backend_stop(HwPhoneLinkTransport *self, GError **error);
static HwPhoneLinkState hw_phone_link_infra_backend_get_state(HwPhoneLinkTransport *self);
static const gchar* hw_phone_link_infra_backend_get_ap_interface(HwPhoneLinkTransport *self);
static const gchar* hw_phone_link_infra_backend_get_ap_ip(HwPhoneLinkTransport *self);
static guint hw_phone_link_infra_backend_get_ap_channel(HwPhoneLinkTransport *self);

static void _stop_listeners(HwPhoneLinkInfraBackend *self);

static void hw_phone_link_infra_backend_finalize(GObject *object) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(object);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  if (g_atomic_int_get(&priv->running)) {
    _stop_listeners(self);
  }
  g_mutex_clear(&priv->state_mutex);
  if (priv->worker_cancel) g_object_unref(priv->worker_cancel);
  if (priv->nl_handle) hw_phone_link_nl_handle_free(priv->nl_handle);
  g_free(priv->config.interface);
  g_free(priv->config.coap_multicast_ip);
  g_free(priv->config.service_name);
  g_free(priv->config.local_ip);
  G_OBJECT_CLASS(hw_phone_link_infra_backend_parent_class)->finalize(object);
}

static void hw_phone_link_infra_backend_class_init(HwPhoneLinkInfraBackendClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  HwPhoneLinkTransportClass *transport_class = HWPHONELINK_TRANSPORT_CLASS(klass);

  object_class->finalize = hw_phone_link_infra_backend_finalize;

  transport_class->start = hw_phone_link_infra_backend_start;
  transport_class->stop = hw_phone_link_infra_backend_stop;
  transport_class->get_state = hw_phone_link_infra_backend_get_state;
  transport_class->get_ap_interface = hw_phone_link_infra_backend_get_ap_interface;
  transport_class->get_ap_ip = hw_phone_link_infra_backend_get_ap_ip;
  transport_class->get_ap_channel = hw_phone_link_infra_backend_get_ap_channel;
}

static void hw_phone_link_infra_backend_init(HwPhoneLinkInfraBackend *self) {
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  g_mutex_init(&priv->state_mutex);
  priv->state = HWPHONELINK_STATE_STOPPED;

  priv->config.interface = g_strdup("wlp1s0");
  priv->config.coap_port = 5683;
  priv->config.coap_multicast_ip = g_strdup("224.0.1.187");
  priv->config.mdns_port = 5353;
  priv->config.service_name = g_strdup("_hw-multiscreen._tcp.local");
  priv->config.session_port = 54321;
  priv->config.auth_port = 54322;
  priv->config.local_ip = g_new0(gchar, INET_ADDRSTRLEN);
}

/*
 * Update state under the mutex and emit "state-changed" (old, new).
 */
static void _set_state(HwPhoneLinkInfraBackend *self, HwPhoneLinkState new_state) {
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  g_mutex_lock(&priv->state_mutex);
  HwPhoneLinkState old_state = priv->state;
  if (old_state != new_state) {
    priv->state = new_state;
    g_mutex_unlock(&priv->state_mutex);
    g_signal_emit_by_name(HWPHONELINK_TRANSPORT(self), "state-changed", old_state, new_state);
  } else {
    g_mutex_unlock(&priv->state_mutex);
  }
}

/*
 * Get the primary IPv4 address of an interface (legacy ioctl path —
 * fine for read-only queries, no netlink round-trip needed).
 */
static void _get_interface_ip(const gchar *ifname, gchar *ip_buf, size_t buf_len) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return;

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
    struct sockaddr_in *addr = (struct sockaddr_in*)&ifr.ifr_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_buf, buf_len);
  }
  close(sock);
}

/*
 * CoAP discovery worker: receive multicast beacons.
 * Cancellable receive so stop() can unblock it immediately.
 */
static void* _discovery_loop(gpointer data) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(data);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  gchar buf[1500];

  while (g_atomic_int_get(&priv->running)) {
    GError *err = NULL;
    GSocketAddress *src = NULL;
    gssize len = g_socket_receive_from(priv->coap_socket, &src, buf, sizeof(buf),
                                       priv->worker_cancel, &err);
    if (src) g_object_unref(src);
    if (len > 0) {
      g_print("Infra: CoAP discovery packet (%zd bytes)\n", len);
      /* TODO(M2): parse dsoftbus beacon TLV, register remote device,
       *           emit client-connected. */
    } else if (len < 0) {
      if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_clear_error(&err);
        break;  /* stop() was called */
      }
      g_warning("Infra: CoAP receive error: %s", err->message);
    }
    g_clear_error(&err);
  }
  return NULL;
}

/*
 * TCP session accept worker: accepts phone→PC session connections.
 * Uses a cancellable so stop() can unblock the accept immediately.
 */
static void* _tcp_accept_loop(gpointer data) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(data);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  while (g_atomic_int_get(&priv->running)) {
    GError *err = NULL;
    GObject *source_object = NULL;
    GSocketConnection *conn = g_socket_listener_accept(priv->tcp_listener,
                                                       &source_object,
                                                       priv->worker_cancel, &err);
    if (conn) {
      GError *addr_err = NULL;
      GSocketAddress *remote = g_socket_connection_get_remote_address(G_SOCKET_CONNECTION(conn), &addr_err);
      if (addr_err) {
        g_warning("Infra: No remote address: %s", addr_err->message);
        g_clear_error(&addr_err);
      }
      if (remote) {
        GInetAddress *inet = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(remote));
        guint port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(remote));
        gchar *peer_ip = inet ? g_inet_address_to_string(inet) : NULL;
        g_print("Infra: Incoming TCP connection from %s:%u\n", peer_ip ? peer_ip : "?", port);
        g_free(peer_ip);
        g_object_unref(remote);
      }
      /* TODO(M2): hand the connection to the dsoftbus session layer
       *           (auth handshake → session). For now drop it. */
      g_object_unref(conn);
    } else if (err) {
      if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_clear_error(&err);
        break;  /* stop() was called */
      }
      g_warning("Infra: Accept error: %s", err->message);
      g_clear_error(&err);
    }
  }
  return NULL;
}

/*
 * GSocketListener "event" callback — log listener lifecycle.
 */
static void _on_tcp_event(GSocketListener *listener,
                          GSocketListenerEvent event,
                          GSocketConnection *conn,
                          gpointer user_data) {
  (void)listener;
  (void)conn;
  (void)user_data;
  if (event == G_SOCKET_LISTENER_LISTENED) {
    g_print("Infra: TCP session listener is up\n");
  }
}

/*
 * Stop both worker loops and release sockets.
 */
static void _stop_listeners(HwPhoneLinkInfraBackend *self) {
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  g_atomic_int_set(&priv->running, 0);
  if (priv->worker_cancel) {
    g_cancellable_cancel(priv->worker_cancel);  /* unblock the accept loop */
  }

  if (priv->discovery_thread) {
    g_thread_join(priv->discovery_thread);
    priv->discovery_thread = NULL;
  }
  if (priv->accept_thread) {
    g_thread_join(priv->accept_thread);
    priv->accept_thread = NULL;
  }
  if (priv->coap_socket) {
    g_object_unref(priv->coap_socket);
    priv->coap_socket = NULL;
  }
  if (priv->worker_cancel) {
    g_object_unref(priv->worker_cancel);
    priv->worker_cancel = NULL;
  }
}

/*
 * Create the CoAP multicast receiver and start the discovery worker.
 * Binds INADDR_ANY:5683 with SO_REUSEADDR (coexist with other CoAP stacks),
 * then joins 224.0.1.187 on the LAN interface.
 */
static gboolean _start_coap_listener(HwPhoneLinkInfraBackend *self, GError **error) {
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  priv->coap_socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                                   G_SOCKET_PROTOCOL_UDP, error);
  if (!priv->coap_socket) return FALSE;

  /* Allow sharing port 5683 with other CoAP stacks; enable broadcast. */
  int one = 1;
  setsockopt(g_socket_get_fd(priv->coap_socket), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(g_socket_get_fd(priv->coap_socket), SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

  GSocketAddress *bind_addr = g_inet_socket_address_new(
      g_inet_address_new_from_string("0.0.0.0"), priv->config.coap_port);

  if (!g_socket_bind(priv->coap_socket, bind_addr, TRUE, error)) {
    g_object_unref(bind_addr);
    return FALSE;
  }
  g_object_unref(bind_addr);

  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(priv->config.coap_multicast_ip);
  mreq.imr_interface.s_addr = inet_addr(priv->config.local_ip);
  if (setsockopt(g_socket_get_fd(priv->coap_socket), IPPROTO_IP,
                 IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to join CoAP multicast group %s on %s: %s",
                priv->config.coap_multicast_ip, priv->config.local_ip, g_strerror(errno));
    return FALSE;
  }

  g_atomic_int_set(&priv->running, 1);
  priv->discovery_thread = g_thread_new("infra-discovery", _discovery_loop, self);
  if (!priv->discovery_thread) {
    g_atomic_int_set(&priv->running, 0);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create discovery thread");
    return FALSE;
  }

  g_print("Infra: CoAP discovery on %s:%u (group %s)\n",
          priv->config.local_ip, priv->config.coap_port, priv->config.coap_multicast_ip);
  return TRUE;
}

/*
 * Create the TCP session listener and start the accept worker.
 */
static gboolean _start_tcp_listener(HwPhoneLinkInfraBackend *self, GError **error) {
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  GInetAddress *addr = g_inet_address_new_from_string(priv->config.local_ip);
  GSocketAddress *sockaddr = g_inet_socket_address_new(addr, priv->config.session_port);
  g_object_unref(addr);

  priv->tcp_listener = g_socket_listener_new();
  if (!g_socket_listener_add_address(priv->tcp_listener, sockaddr,
                                     G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP,
                                     NULL, NULL, error)) {
    g_object_unref(sockaddr);
    g_object_unref(priv->tcp_listener);
    priv->tcp_listener = NULL;
    return FALSE;
  }
  g_object_unref(sockaddr);

  g_signal_connect(priv->tcp_listener, "event", G_CALLBACK(_on_tcp_event), self);

  priv->accept_thread = g_thread_new("infra-accept", _tcp_accept_loop, self);
  if (!priv->accept_thread) {
    g_object_unref(priv->tcp_listener);
    priv->tcp_listener = NULL;
    g_object_unref(priv->worker_cancel);
    priv->worker_cancel = NULL;
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to create accept thread");
    return FALSE;
  }

  g_print("Infra: TCP session listener on %s:%u\n",
          priv->config.local_ip, priv->config.session_port);
  return TRUE;
}

/* ============================ Virtual methods ============================ */

static gboolean hw_phone_link_infra_backend_start(HwPhoneLinkTransport *transport, GError **error) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(transport);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  g_mutex_lock(&priv->state_mutex);
  if (priv->state != HWPHONELINK_STATE_STOPPED) {
    g_mutex_unlock(&priv->state_mutex);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transport already running");
    return FALSE;
  }
  priv->state = HWPHONELINK_STATE_STARTING;
  g_mutex_unlock(&priv->state_mutex);

  priv->worker_cancel = g_cancellable_new();

  int ifindex = if_nametoindex(priv->config.interface);
  if (ifindex <= 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Interface %s not found", priv->config.interface);
    g_object_unref(priv->worker_cancel);
    priv->worker_cancel = NULL;
    _set_state(self, HWPHONELINK_STATE_ERROR);
    return FALSE;
  }

  _get_interface_ip(priv->config.interface, priv->config.local_ip, INET_ADDRSTRLEN);
  if (priv->config.local_ip[0] == '\0') {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Interface %s has no IPv4 address", priv->config.interface);
    g_object_unref(priv->worker_cancel);
    priv->worker_cancel = NULL;
    _set_state(self, HWPHONELINK_STATE_ERROR);
    return FALSE;
  }

  if (!_start_coap_listener(self, error)) {
    _set_state(self, HWPHONELINK_STATE_ERROR);
    return FALSE;
  }
  if (!_start_tcp_listener(self, error)) {
    _stop_listeners(self);
    _set_state(self, HWPHONELINK_STATE_ERROR);
    return FALSE;
  }

  g_print("Infra: Ready on %s (%s)\n", priv->config.interface, priv->config.local_ip);
  _set_state(self, HWPHONELINK_STATE_RUNNING);
  return TRUE;
}

static gboolean hw_phone_link_infra_backend_stop(HwPhoneLinkTransport *transport, GError **error) {
  (void)error;
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(transport);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  g_mutex_lock(&priv->state_mutex);
  if (priv->state == HWPHONELINK_STATE_STOPPED) {
    g_mutex_unlock(&priv->state_mutex);
    return TRUE;
  }
  g_mutex_unlock(&priv->state_mutex);

  _set_state(self, HWPHONELINK_STATE_STOPPING);

  _stop_listeners(self);
  if (priv->tcp_listener) {
    g_object_unref(priv->tcp_listener);
    priv->tcp_listener = NULL;
  }

  _set_state(self, HWPHONELINK_STATE_STOPPED);
  return TRUE;
}

static HwPhoneLinkState hw_phone_link_infra_backend_get_state(HwPhoneLinkTransport *transport) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(transport);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  g_mutex_lock(&priv->state_mutex);
  HwPhoneLinkState state = priv->state;
  g_mutex_unlock(&priv->state_mutex);
  return state;
}

static const gchar* hw_phone_link_infra_backend_get_ap_interface(HwPhoneLinkTransport *transport) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(transport);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  return priv->config.interface;
}

static const gchar* hw_phone_link_infra_backend_get_ap_ip(HwPhoneLinkTransport *transport) {
  HwPhoneLinkInfraBackend *self = HWPHONELINK_INFRA_BACKEND(transport);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);
  return priv->config.local_ip;
}

static guint hw_phone_link_infra_backend_get_ap_channel(HwPhoneLinkTransport *transport) {
  (void)transport;
  return 0;  /* No AP — channel is N/A in infrastructure mode */
}

/* ================================ Factory ================================ */

HwPhoneLinkTransport* hw_phone_link_infra_backend_new(const gchar *interface, GError **error) {
  HwPhoneLinkInfraBackend *self = g_object_new(HWPHONELINK_TYPE_INFRA_BACKEND, NULL);
  HwPhoneLinkInfraBackendPrivate *priv = _priv(self);

  g_free(priv->config.interface);
  priv->config.interface = g_strdup(interface && *interface ? interface : "wlp1s0");

  /* Netlink handle is optional in infra mode — only needed if we later
   * want to create virtual interfaces. Infra mode rides the existing LAN,
   * so a failed handle (e.g. no NET_ADMIN) must not be fatal. */
  {
    GError *nl_error = NULL;
    priv->nl_handle = hw_phone_link_nl_handle_new(&nl_error);
    if (!priv->nl_handle) {
      g_print("Infra: netlink handle unavailable (%s) — continuing without it\n",
              nl_error ? nl_error->message : "unknown");
      g_clear_error(&nl_error);
    }
  }

  return HWPHONELINK_TRANSPORT(self);
}
