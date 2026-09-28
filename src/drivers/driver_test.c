/*
 * Testing driver interface for a simulated network driver
 * Copyright (c) 2004-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This driver wrapper (-Dtest in wpa_supplicant, driver=test in hostapd)
 * allows the complete user space protocol implementation of hostapd and
 * wpa_supplicant to be exercised without nl80211, cfg80211, mac80211, WLAN
 * hardware, or kernel modules. Frames are exchanged between processes over a
 * local UNIX domain (or loopback UDP) datagram socket using the framing
 * described in driver_test.h.
 *
 * The test driver emulates what a mac80211-based driver exposes towards
 * hostapd (AP MLME in hostapd: EVENT_RX_MGMT, send_mlme(), TX status,
 * station table, key table, control port EAPOL) and towards wpa_supplicant
 * (SME in wpa_supplicant: scan2(), authenticate(), associate(), EVENT_AUTH,
 * EVENT_ASSOC, control port EAPOL). It does not implement any cipher, PHY,
 * channel scheduling, or regulatory behavior; see the "Limitations" section
 * in doc/testing_tools.doxygen.
 */

#include "utils/includes.h"
#include <sys/un.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/list.h"
#include "utils/wpabuf.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_common.h"
#include "common/defs.h"
#include "crypto/sha1.h"
#ifdef CONFIG_FILS
#include "crypto/aes.h"
#include "crypto/aes_siv.h"
#endif /* CONFIG_FILS */
#include "l2_packet/l2_packet.h"
#include "driver.h"
#include "driver_test.h"


/* Bounded resources */
#define TEST_MAX_PEERS 128
#define TEST_MAX_SCAN_RESULTS 64
#define TEST_MAX_GROUP_KEYS TEST_DRV_MAX_GROUP_KEYS
#define TEST_MAX_PENDING_EVENTS 256
#define TEST_MAX_TEMPLATE_LEN 3000
#define TEST_MAX_PROBE_IES 1000
#define TEST_MAX_ASSOC_IES 2500

/* Default timers (ms); all can be overridden with driver parameters */
#define TEST_DEFAULT_SCAN_TIME_MS 200
#define TEST_DEFAULT_AUTH_TIMEOUT_MS 2000
#define TEST_DEFAULT_ASSOC_TIMEOUT_MS 2000
#define TEST_DEFAULT_KEEPALIVE_MS 1000

/* Synthetic PHY capability selection for the STA association request */
#define TEST_PHY_HT BIT(0)
#define TEST_PHY_VHT BIT(1)
#define TEST_PHY_HE BIT(2)
#define TEST_PHY_EHT BIT(3)
#define TEST_PHY_ALL (TEST_PHY_HT | TEST_PHY_VHT | TEST_PHY_HE | TEST_PHY_EHT)

enum test_transport {
	TEST_TRANSPORT_NONE,
	TEST_TRANSPORT_UNIX,
	TEST_TRANSPORT_UDP,
};

enum test_sta_state {
	TEST_STA_IDLE,
	TEST_STA_AUTHENTICATING,
	TEST_STA_AUTHENTICATED,
	TEST_STA_ASSOCIATING,
	TEST_STA_ASSOCIATED,
};

struct test_key {
	bool set;
	enum wpa_alg alg;
	int key_idx;
	size_t key_len;
	enum key_flag key_flag;
	/* Key material is intentionally not stored; the test driver never
	 * encrypts anything and only needs to know that a key exists. */
};

struct test_bss;

/*
 * struct test_peer - Remote entity known to this radio
 *
 * AP mode: one entry per (link) station address. STA mode: one entry per
 * (link) BSSID. The socket address is learned from received datagrams.
 */
struct test_peer {
	struct dl_list list;
	u8 addr[ETH_ALEN]; /* address as seen on the "wire" */
	u8 mld_addr[ETH_ALEN]; /* MLD address when mld is set */
	bool mld;
	int link_id; /* MLD link this entry belongs to, or -1 */
	struct test_bss *bss; /* AP: BSS/link that owns this station */
	struct sockaddr_storage sa;
	socklen_t sa_len;
	bool sa_valid;
	struct os_reltime last_rx;
	bool added; /* AP: added with sta_add() */
	u32 flags; /* WPA_STA_* */
	u16 aid;
	struct test_key ptk;
	unsigned int rx_frames;
	unsigned int tx_frames;
};

/*
 * struct test_bss - Per-BSS (AP), per-MLD-link (AP MLD), or per-interface
 * (STA) driver context. Pointers to this structure are handed out as the
 * private driver context (priv) to hostapd/wpa_supplicant.
 */
struct test_bss {
	struct dl_list list;
	struct wpa_driver_test_data *drv;
	void *ctx;
	char ifname[IFNAMSIZ + 1];
	u8 addr[ETH_ALEN]; /* BSSID (AP) / own address (STA) */
	int link_id; /* -1 when not an MLD link */
	bool mld_link;
	u8 ssid[SSID_MAX_LEN];
	size_t ssid_len;
	int privacy;
	int freq;
	int beacon_int;
	bool started; /* set_ap() called */
	struct wpabuf *head;
	struct wpabuf *tail;
	struct test_key gtk[TEST_MAX_GROUP_KEYS];
};

enum test_pending_kind {
	TEST_EV_TX_STATUS,
	TEST_EV_SCAN_STARTED,
	TEST_EV_SCAN_ABORTED,
	TEST_EV_CLIENT_POLL_OK,
	TEST_EV_CH_SWITCH,
	TEST_EV_LOCAL_DEAUTH,
};

struct test_pending_event {
	struct dl_list list;
	enum test_pending_kind kind;
	void *ctx;
	int link_id;
	int ack;
	u8 addr[ETH_ALEN];
	int freq;
	int reason;
	size_t len;
	u8 data[];
};

struct test_stats {
	unsigned int rx_msgs;
	unsigned int rx_invalid_hdr;
	unsigned int rx_invalid_frame;
	unsigned int rx_unknown_type;
	unsigned int rx_dropped_no_bss;
	unsigned int rx_dropped_undecryptable;
	unsigned int rx_dropped_unprotected;
	unsigned int rx_dropped_peer_table_full;
	unsigned int rx_mgmt;
	unsigned int rx_eapol;
	unsigned int rx_null;
	unsigned int tx_msgs;
	unsigned int tx_failed;
	unsigned int tx_mgmt;
	unsigned int tx_eapol;
	unsigned int events;
	unsigned int peers_evicted;
	unsigned int auth_timeouts;
	unsigned int assoc_timeouts;
	unsigned int peer_lost;
};

struct wpa_driver_test_global {
	unsigned int num_ifaces;
};

struct wpa_driver_test_data {
	struct wpa_driver_test_global *global;
	void *ctx;
	bool ap;
	u8 own_addr[ETH_ALEN]; /* radio / MLD address */
	char ifname[IFNAMSIZ + 1];

	int sock;
	enum test_transport transport;
	char *own_socket_path; /* bound UNIX socket path (for unlink) */
	char *test_dir; /* directory for AP/STA socket discovery */
	struct sockaddr_storage ap_sa; /* STA: configured AP socket */
	socklen_t ap_sa_len;
	bool ap_sa_set;
	int udp_port;
	u16 tx_seq;

	struct dl_list bss; /* struct test_bss */
	struct dl_list peers; /* struct test_peer */
	unsigned int num_peers;
	struct dl_list pending; /* struct test_pending_event */
	unsigned int num_pending;
	struct test_stats stats;

	int freq; /* current operating frequency */
	unsigned int remain_on_channel_freq;
	unsigned int remain_on_channel_duration;
	int probe_req_report;
	bool mlo_capable;
	unsigned int phy_caps; /* TEST_PHY_* included in association */

	/* STA mode state */
	unsigned int scan_time_ms;
	unsigned int auth_timeout_ms;
	unsigned int assoc_timeout_ms;
	unsigned int keepalive_ms;
	bool scanning;
	int *scan_freqs; /* copy of the last scan frequency filter */
	struct wpa_scan_res *scanres[TEST_MAX_SCAN_RESULTS];
	size_t num_scanres;
	enum test_sta_state sta_state;
	u8 bssid[ETH_ALEN]; /* target/current BSSID (assoc link) */
	u8 pending_auth_alg;
	bool mfp; /* management frame protection negotiated */
	struct test_key ptk;
	struct test_key gtk[TEST_MAX_GROUP_KEYS];
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	bool reassoc;
#ifdef CONFIG_FILS
	/* FILS association: KEK and nonces for AES-SIV processing of the
	 * (Re)Association frames, like mac80211 does for FILS */
	u8 fils_kek[64];
	size_t fils_kek_len;
	u8 fils_nonces[2 * NONCE_LEN];
#endif /* CONFIG_FILS */

	/* STA MLO state */
	bool mlo;
	u8 ap_mld_addr[ETH_ALEN];
	u16 req_links;
	u16 valid_links;
	u8 assoc_link_id;
	struct {
		u8 addr[ETH_ALEN];
		u8 bssid[ETH_ALEN];
		int freq;
	} links[MAX_NUM_MLD_LINKS];
};


static void wpa_driver_test_deinit(void *priv);
static void test_driver_receive(int sock, void *eloop_ctx, void *sock_ctx);
static void test_driver_scan_timeout(void *eloop_ctx, void *timeout_ctx);
static void test_driver_auth_timeout(void *eloop_ctx, void *timeout_ctx);
static void test_driver_assoc_timeout(void *eloop_ctx, void *timeout_ctx);
static void test_driver_keepalive(void *eloop_ctx, void *timeout_ctx);
static void test_driver_roc_timeout(void *eloop_ctx, void *timeout_ctx);
static void test_driver_flush_pending(void *eloop_ctx, void *timeout_ctx);
static int test_driver_send_mlme(void *priv, const u8 *data, size_t data_len,
				 int noack, unsigned int freq,
				 const u16 *csa_offs, size_t csa_offs_len,
				 int no_encrypt, unsigned int wait,
				 int link_id);


/* ---------------------------------------------------------------------- */
/* Wire format helpers                                                     */

int test_drv_hdr_parse(const u8 *buf, size_t len, struct test_drv_hdr *hdr,
		       const u8 **payload, size_t *payload_len)
{
	size_t plen;

	if (!buf || !hdr || len < TEST_DRV_HDR_LEN || len > TEST_DRV_MAX_MSG)
		return -1;
	os_memcpy(hdr, buf, TEST_DRV_HDR_LEN);
	if (hdr->magic[0] != TEST_DRV_MAGIC_0 ||
	    hdr->magic[1] != TEST_DRV_MAGIC_1 ||
	    hdr->magic[2] != TEST_DRV_MAGIC_2 ||
	    hdr->magic[3] != TEST_DRV_MAGIC_3)
		return -1;
	if (hdr->version != TEST_DRV_VERSION)
		return -1;
	if (hdr->type != TEST_DRV_MSG_MGMT && hdr->type != TEST_DRV_MSG_EAPOL &&
	    hdr->type != TEST_DRV_MSG_NULL)
		return -1;
	if (hdr->flags & ~(TEST_DRV_FLAG_PROTECTED | TEST_DRV_FLAG_NOACK))
		return -1;
	if (hdr->link_id != TEST_DRV_LINK_ID_NONE &&
	    hdr->link_id >= MAX_NUM_MLD_LINKS)
		return -1;
	plen = le_to_host16(hdr->payload_len);
	if (plen > TEST_DRV_MAX_PAYLOAD || plen != len - TEST_DRV_HDR_LEN)
		return -1;
	if (hdr->type == TEST_DRV_MSG_NULL && plen != 0)
		return -1;
	if (payload)
		*payload = buf + TEST_DRV_HDR_LEN;
	if (payload_len)
		*payload_len = plen;
	return 0;
}


int test_drv_hdr_build(u8 *buf, size_t buflen, u8 type, u8 flags,
		       int link_id, unsigned int freq, u16 seq,
		       size_t payload_len)
{
	struct test_drv_hdr hdr;

	if (!buf || buflen < TEST_DRV_HDR_LEN ||
	    payload_len > TEST_DRV_MAX_PAYLOAD)
		return -1;
	os_memset(&hdr, 0, sizeof(hdr));
	hdr.magic[0] = TEST_DRV_MAGIC_0;
	hdr.magic[1] = TEST_DRV_MAGIC_1;
	hdr.magic[2] = TEST_DRV_MAGIC_2;
	hdr.magic[3] = TEST_DRV_MAGIC_3;
	hdr.version = TEST_DRV_VERSION;
	hdr.type = type;
	hdr.flags = flags;
	hdr.link_id = (link_id >= 0 && link_id < MAX_NUM_MLD_LINKS) ?
		(u8) link_id : TEST_DRV_LINK_ID_NONE;
	hdr.freq = host_to_le32(freq);
	hdr.payload_len = host_to_le16((u16) payload_len);
	hdr.seq = host_to_le16(seq);
	os_memcpy(buf, &hdr, TEST_DRV_HDR_LEN);
	return TEST_DRV_HDR_LEN;
}


/* ---------------------------------------------------------------------- */
/* Synthetic PHY capabilities                                              */

/*
 * These static capability sets are used both for the AP hardware feature
 * data reported to hostapd and for the (Re)Association Request frames built
 * for wpa_supplicant. They exist only so that HT/VHT/HE/EHT information
 * element generation and parsing paths can be exercised; no PHY behavior is
 * emulated.
 */

#define TEST_HT_CAPAB (HT_CAP_INFO_LDPC_CODING_CAP | \
		       HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET | \
		       HT_CAP_INFO_SMPS_DISABLED | \
		       HT_CAP_INFO_SHORT_GI20MHZ | \
		       HT_CAP_INFO_SHORT_GI40MHZ | \
		       HT_CAP_INFO_TX_STBC | \
		       HT_CAP_INFO_MAX_AMSDU_SIZE | \
		       HT_CAP_INFO_DSSS_CCK40MHZ)
#define TEST_HT_AMPDU_PARAMS 0x1b
#define TEST_VHT_CAPAB (VHT_CAP_MAX_MPDU_LENGTH_11454 | \
			VHT_CAP_RXLDPC | \
			VHT_CAP_SHORT_GI_80 | \
			VHT_CAP_TXSTBC | \
			VHT_CAP_RXSTBC_1 | \
			VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MAX | \
			VHT_CAP_RX_ANTENNA_PATTERN | \
			VHT_CAP_TX_ANTENNA_PATTERN)
static const u8 test_ht_mcs_set[16] = { 0xff, 0xff, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0x01, 0, 0, 0 };
static const u8 test_vht_mcs_set[8] = { 0xfa, 0xff, 0x00, 0x00,
					0xfa, 0xff, 0x00, 0x00 };
static const u8 test_he_mac_cap[HE_MAX_MAC_CAPAB_SIZE] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const u8 test_he_mcs[HE_MAX_MCS_CAPAB_SIZE] = {
	0xfa, 0xff, 0xfa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff };
#define TEST_HE_6GHZ_CAPA (HE_6GHZ_BAND_CAP_MAX_AMPDU_LEN_EXP_1024K | \
			   HE_6GHZ_BAND_CAP_MAX_MPDU_LEN_11454 | \
			   HE_6GHZ_BAND_CAP_SMPS_DISABLED | \
			   HE_6GHZ_BAND_CAP_RX_ANTPAT_CONS | \
			   HE_6GHZ_BAND_CAP_TX_ANTPAT_CONS)
static const u8 test_eht_mcs[EHT_MCS_NSS_CAPAB_LEN] = {
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };

static const int test_rates_g[] = { 10, 20, 55, 110, 60, 90, 120, 180, 240,
				    360, 480, 540 };
static const int test_rates_a[] = { 60, 90, 120, 180, 240, 360, 480, 540 };

/* Supported Rates element content (in 500 kbps units) */
static const u8 test_supp_rates_g[8] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12,
					 0x18, 0x24 };
static const u8 test_ext_rates_g[4] = { 0x30, 0x48, 0x60, 0x6c };
static const u8 test_supp_rates_a[8] = { 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48,
					 0x60, 0x6c };


static u8 test_he_phy_width(int freq)
{
	if (freq >= 2400 && freq < 2500)
		return HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_IN_2G;
	return HE_PHYCAP_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
}


static void test_fill_he_capab(struct he_capabilities *he, int freq,
			       bool is_6ghz)
{
	os_memset(he, 0, sizeof(*he));
	he->he_supported = 1;
	os_memcpy(he->mac_cap, test_he_mac_cap, sizeof(he->mac_cap));
	he->phy_cap[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] = test_he_phy_width(freq);
	os_memcpy(he->mcs, test_he_mcs, sizeof(he->mcs));
	if (is_6ghz)
		he->he_6ghz_capa = TEST_HE_6GHZ_CAPA;
}


static void test_fill_eht_capab(struct eht_capabilities *eht)
{
	os_memset(eht, 0, sizeof(*eht));
	eht->eht_supported = true;
	eht->mac_cap = 0;
	os_memcpy(eht->mcs, test_eht_mcs, sizeof(eht->mcs));
}


/* ---------------------------------------------------------------------- */
/* Small helpers                                                           */

static void test_derive_addr(const char *ifname, const char *label, u8 *addr)
{
	u8 hash[SHA1_MAC_LEN];

	os_memset(addr, 0, ETH_ALEN);
	if (sha1_prf((const u8 *) ifname, os_strlen(ifname), label, NULL, 0,
		     hash, sizeof(hash)) < 0) {
		/* Deterministic fallback in case SHA-1 is not available */
		size_t i, len = os_strlen(ifname);

		for (i = 0; i < len; i++)
			hash[i % SHA1_MAC_LEN] ^= (u8) ifname[i];
	}
	os_memcpy(addr + 1, hash, ETH_ALEN - 1);
	addr[0] = 0x02; /* locally administered, unicast */
}


static struct test_bss * test_bss_first(struct wpa_driver_test_data *drv)
{
	return dl_list_first(&drv->bss, struct test_bss, list);
}


static struct test_bss * test_bss_by_addr(struct wpa_driver_test_data *drv,
					  const u8 *addr)
{
	struct test_bss *bss;

	if (!addr)
		return NULL;
	dl_list_for_each(bss, &drv->bss, struct test_bss, list) {
		if (ether_addr_equal(bss->addr, addr))
			return bss;
	}
	return NULL;
}


static struct test_bss * test_bss_by_link(struct wpa_driver_test_data *drv,
					  int link_id)
{
	struct test_bss *bss;

	if (link_id < 0)
		return NULL;
	dl_list_for_each(bss, &drv->bss, struct test_bss, list) {
		if (bss->mld_link && bss->link_id == link_id)
			return bss;
	}
	return NULL;
}


static struct test_bss * test_bss_by_ifname(struct wpa_driver_test_data *drv,
					    const char *ifname)
{
	struct test_bss *bss;

	dl_list_for_each(bss, &drv->bss, struct test_bss, list) {
		if (os_strcmp(bss->ifname, ifname) == 0)
			return bss;
	}
	return NULL;
}


#ifdef CONFIG_IEEE80211BE
static struct test_bss * test_bss_by_ctx(struct wpa_driver_test_data *drv,
					 void *ctx)
{
	struct test_bss *bss;

	dl_list_for_each(bss, &drv->bss, struct test_bss, list) {
		if (bss->ctx == ctx)
			return bss;
	}
	return NULL;
}
#endif /* CONFIG_IEEE80211BE */


static bool test_drv_is_mld(struct wpa_driver_test_data *drv)
{
	struct test_bss *bss;

	dl_list_for_each(bss, &drv->bss, struct test_bss, list) {
		if (bss->mld_link)
			return true;
	}
	return false;
}


static void test_bss_free(struct test_bss *bss)
{
	wpabuf_free(bss->head);
	wpabuf_free(bss->tail);
	os_free(bss);
}


static struct test_bss * test_bss_add(struct wpa_driver_test_data *drv,
				      const char *ifname, const u8 *addr,
				      void *ctx)
{
	struct test_bss *bss;

	bss = os_zalloc(sizeof(*bss));
	if (!bss)
		return NULL;
	bss->drv = drv;
	bss->ctx = ctx;
	bss->link_id = -1;
	if (ifname)
		os_strlcpy(bss->ifname, ifname, sizeof(bss->ifname));
	if (addr)
		os_memcpy(bss->addr, addr, ETH_ALEN);
	dl_list_add_tail(&drv->bss, &bss->list);
	return bss;
}


static bool test_sockaddr_equal(const struct sockaddr_storage *a,
				socklen_t alen,
				const struct sockaddr_storage *b,
				socklen_t blen)
{
	if (alen != blen)
		return false;
	return os_memcmp(a, b, alen) == 0;
}


static struct test_peer * test_peer_get(struct wpa_driver_test_data *drv,
					const u8 *addr)
{
	struct test_peer *peer;

	if (!addr)
		return NULL;
	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		if (ether_addr_equal(peer->addr, addr))
			return peer;
	}
	return NULL;
}


static struct test_peer * test_peer_get_mld(struct wpa_driver_test_data *drv,
					    const u8 *mld_addr, int link_id)
{
	struct test_peer *peer, *any = NULL;

	if (!mld_addr)
		return NULL;
	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		if (!peer->mld || !ether_addr_equal(peer->mld_addr, mld_addr))
			continue;
		if (link_id < 0 || peer->link_id == link_id)
			return peer;
		if (!any)
			any = peer;
	}
	return any;
}


/* Find a peer by any of its addresses (link address or MLD address). When
 * an MLD address is given, prefer the entry on link_id. */
static struct test_peer * test_peer_find(struct wpa_driver_test_data *drv,
					 const u8 *addr, int link_id)
{
	struct test_peer *peer;

	if (!addr)
		return NULL;
	if (link_id >= 0) {
		peer = test_peer_get_mld(drv, addr, link_id);
		if (peer && peer->link_id == link_id)
			return peer;
		peer = test_peer_get(drv, addr);
		if (peer)
			return peer;
	} else {
		peer = test_peer_get(drv, addr);
		if (peer)
			return peer;
	}
	return test_peer_get_mld(drv, addr, link_id);
}


static void test_peer_free(struct wpa_driver_test_data *drv,
			   struct test_peer *peer)
{
	dl_list_del(&peer->list);
	drv->num_peers--;
	os_free(peer);
}


static struct test_peer * test_peer_add(struct wpa_driver_test_data *drv,
					const u8 *addr)
{
	struct test_peer *peer;

	if (drv->num_peers >= TEST_MAX_PEERS) {
		struct test_peer *oldest = NULL;

		/* Evict the least recently seen entry that is not an added
		 * station (AP) to keep the table bounded. */
		dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
			if (peer->added)
				continue;
			if (!oldest ||
			    os_reltime_before(&peer->last_rx,
					      &oldest->last_rx))
				oldest = peer;
		}
		if (!oldest) {
			drv->stats.rx_dropped_peer_table_full++;
			return NULL;
		}
		wpa_printf(MSG_DEBUG, "test_driver(%s): Evict peer " MACSTR,
			   drv->ifname, MAC2STR(oldest->addr));
		drv->stats.peers_evicted++;
		test_peer_free(drv, oldest);
	}

	peer = os_zalloc(sizeof(*peer));
	if (!peer)
		return NULL;
	os_memcpy(peer->addr, addr, ETH_ALEN);
	peer->link_id = -1;
	os_get_reltime(&peer->last_rx);
	dl_list_add_tail(&drv->peers, &peer->list);
	drv->num_peers++;
	return peer;
}


static void test_peer_set_sa(struct test_peer *peer,
			     const struct sockaddr_storage *sa, socklen_t len)
{
	if (!sa || len == 0 || len > sizeof(peer->sa))
		return;
	os_memset(&peer->sa, 0, sizeof(peer->sa));
	os_memcpy(&peer->sa, sa, len);
	peer->sa_len = len;
	peer->sa_valid = true;
}


static void test_peers_flush(struct wpa_driver_test_data *drv)
{
	struct test_peer *peer, *tmp;

	dl_list_for_each_safe(peer, tmp, &drv->peers, struct test_peer, list)
		test_peer_free(drv, peer);
}


static void test_clear_keys(struct test_key *keys, size_t num)
{
	os_memset(keys, 0, num * sizeof(*keys));
}


/* Reset a wpabuf for reuse without reallocating it */
static void test_wpabuf_reset(struct wpabuf *buf)
{
	buf->used = 0;
}


/* ---------------------------------------------------------------------- */
/* Deferred event delivery                                                 */

/*
 * Events that a kernel driver would deliver asynchronously (TX status,
 * scan started, client poll result, channel switch) are queued and delivered
 * from an eloop timeout. This avoids re-entering hostapd/wpa_supplicant from
 * within a driver operation and keeps event ordering deterministic.
 */

static void test_pending_free_all(struct wpa_driver_test_data *drv)
{
	struct test_pending_event *ev, *tmp;

	dl_list_for_each_safe(ev, tmp, &drv->pending, struct test_pending_event,
			      list) {
		dl_list_del(&ev->list);
		os_free(ev);
	}
	drv->num_pending = 0;
	eloop_cancel_timeout(test_driver_flush_pending, drv, NULL);
}


static struct test_pending_event *
test_pending_add(struct wpa_driver_test_data *drv, enum test_pending_kind kind,
		 void *ctx, const u8 *data, size_t len)
{
	struct test_pending_event *ev;

	if (drv->num_pending >= TEST_MAX_PENDING_EVENTS) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): Too many pending events - drop",
			   drv->ifname);
		return NULL;
	}
	ev = os_zalloc(sizeof(*ev) + len);
	if (!ev)
		return NULL;
	ev->kind = kind;
	ev->ctx = ctx ? ctx : drv->ctx;
	ev->link_id = -1;
	if (data && len)
		os_memcpy(ev->data, data, len);
	ev->len = len;
	dl_list_add_tail(&drv->pending, &ev->list);
	drv->num_pending++;
	if (!eloop_is_timeout_registered(test_driver_flush_pending, drv, NULL))
		eloop_register_timeout(0, 0, test_driver_flush_pending, drv,
				       NULL);
	return ev;
}


static void test_driver_flush_pending(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	struct test_pending_event *ev;
	union wpa_event_data data;

	/* Deliver exactly the events queued so far; events queued while
	 * processing are delivered in a later round to preserve ordering. */
	while ((ev = dl_list_first(&drv->pending, struct test_pending_event,
				   list))) {
		dl_list_del(&ev->list);
		drv->num_pending--;
		os_memset(&data, 0, sizeof(data));
		drv->stats.events++;

		switch (ev->kind) {
		case TEST_EV_TX_STATUS: {
			const struct ieee80211_hdr *hdr;
			u16 fc;

			if (ev->len < IEEE80211_HDRLEN)
				break;
			hdr = (const struct ieee80211_hdr *) ev->data;
			fc = le_to_host16(hdr->frame_control);
			data.tx_status.type = WLAN_FC_GET_TYPE(fc);
			data.tx_status.stype = WLAN_FC_GET_STYPE(fc);
			data.tx_status.dst = hdr->addr1;
			data.tx_status.data = ev->data;
			data.tx_status.data_len = ev->len;
			data.tx_status.ack = ev->ack;
			data.tx_status.link_id = ev->link_id;
			wpa_supplicant_event(ev->ctx, EVENT_TX_STATUS, &data);
			break;
		}
		case TEST_EV_SCAN_STARTED:
			wpa_supplicant_event(ev->ctx, EVENT_SCAN_STARTED,
					     &data);
			break;
		case TEST_EV_SCAN_ABORTED:
			data.scan_info.aborted = 1;
			wpa_supplicant_event(ev->ctx, EVENT_SCAN_RESULTS,
					     &data);
			break;
		case TEST_EV_CLIENT_POLL_OK:
			os_memcpy(data.client_poll.addr, ev->addr, ETH_ALEN);
			wpa_supplicant_event(ev->ctx,
					     EVENT_DRIVER_CLIENT_POLL_OK,
					     &data);
			break;
		case TEST_EV_CH_SWITCH:
			data.ch_switch.freq = ev->freq;
			data.ch_switch.link_id = ev->link_id;
			data.ch_switch.ht_enabled = ev->ack;
			data.ch_switch.ch_offset = 0;
			data.ch_switch.ch_width = CHAN_WIDTH_20;
			data.ch_switch.cf1 = ev->freq;
			wpa_supplicant_event(ev->ctx, EVENT_CH_SWITCH, &data);
			break;
		case TEST_EV_LOCAL_DEAUTH:
			data.deauth_info.addr = ev->addr;
			data.deauth_info.reason_code = ev->reason;
			data.deauth_info.locally_generated = 1;
			wpa_supplicant_event(ev->ctx, EVENT_DEAUTH, &data);
			break;
		}
		os_free(ev);
	}
}


static void test_queue_tx_status(struct wpa_driver_test_data *drv, void *ctx,
				 const u8 *frame, size_t len, int ack,
				 int link_id)
{
	struct test_pending_event *ev;

	if (len > TEST_DRV_MAX_PAYLOAD)
		return;
	ev = test_pending_add(drv, TEST_EV_TX_STATUS, ctx, frame, len);
	if (ev) {
		ev->ack = ack;
		ev->link_id = link_id;
	}
}


/* ---------------------------------------------------------------------- */
/* Socket handling                                                         */

static void test_driver_close_socket(struct wpa_driver_test_data *drv)
{
	if (drv->sock >= 0) {
		eloop_unregister_read_sock(drv->sock);
		close(drv->sock);
		drv->sock = -1;
	}
	if (drv->own_socket_path) {
		unlink(drv->own_socket_path);
		os_free(drv->own_socket_path);
		drv->own_socket_path = NULL;
	}
	drv->transport = TEST_TRANSPORT_NONE;
}


/* A slow or malicious peer must never be able to stall hostapd or
 * wpa_supplicant: all test sockets are non-blocking, so sendto() fails with
 * EAGAIN instead of blocking when the receiver's queue is full. */
static int test_driver_set_nonblock(int sock)
{
	int flags = fcntl(sock, F_GETFL, 0);

	if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
		wpa_printf(MSG_ERROR, "test_driver: fcntl(O_NONBLOCK): %s",
			   strerror(errno));
		return -1;
	}
	return 0;
}


static int test_driver_bind_unix(struct wpa_driver_test_data *drv,
				 const char *path)
{
	struct sockaddr_un addr;

	if (os_strlen(path) >= sizeof(addr.sun_path)) {
		wpa_printf(MSG_ERROR, "test_driver: Too long socket path '%s'",
			   path);
		return -1;
	}

	drv->sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (drv->sock < 0) {
		wpa_printf(MSG_ERROR, "test_driver: socket(PF_UNIX): %s",
			   strerror(errno));
		return -1;
	}
	if (test_driver_set_nonblock(drv->sock) < 0) {
		close(drv->sock);
		drv->sock = -1;
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
	if (bind(drv->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		int err = errno;

		if (err == EADDRINUSE) {
			/* Remove a stale socket file left behind by a crashed
			 * process, but never steal the path from a live
			 * instance: connect() to a bound datagram socket
			 * succeeds, while a stale path fails with
			 * ECONNREFUSED. Only a socket is removed, never a
			 * regular file. */
			struct stat st;
			int probe;
			bool stale = false;

			probe = socket(PF_UNIX, SOCK_DGRAM, 0);
			if (probe >= 0) {
				if (connect(probe, (struct sockaddr *) &addr,
					    sizeof(addr)) < 0 &&
				    errno == ECONNREFUSED &&
				    lstat(path, &st) == 0 &&
				    S_ISSOCK(st.st_mode))
					stale = true;
				close(probe);
			}
			if (stale) {
				wpa_printf(MSG_DEBUG,
					   "test_driver: Remove stale socket %s",
					   path);
				unlink(path);
				if (bind(drv->sock, (struct sockaddr *) &addr,
					 sizeof(addr)) == 0)
					goto bound;
				err = errno;
			}
		}
		wpa_printf(MSG_ERROR, "test_driver: bind(%s): %s", path,
			   strerror(err));
		close(drv->sock);
		drv->sock = -1;
		return -1;
	}
bound:
	/* The socket path is the "air": restrict it to the owner so that
	 * other local users cannot inject frames into a test run. */
	if (chmod(path, S_IRUSR | S_IWUSR) < 0)
		wpa_printf(MSG_DEBUG, "test_driver: chmod(%s): %s", path,
			   strerror(errno));
	drv->own_socket_path = os_strdup(path);
	if (!drv->own_socket_path) {
		close(drv->sock);
		drv->sock = -1;
		unlink(path);
		return -1;
	}
	drv->transport = TEST_TRANSPORT_UNIX;
	eloop_register_read_sock(drv->sock, test_driver_receive, drv, NULL);
	wpa_printf(MSG_DEBUG, "test_driver(%s): Bound UNIX socket %s",
		   drv->ifname, path);
	return 0;
}


static int test_driver_bind_udp(struct wpa_driver_test_data *drv, int port)
{
	struct sockaddr_in addr;

	if (port < 0 || port > 65535)
		return -1;

	drv->sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->sock < 0) {
		wpa_printf(MSG_ERROR, "test_driver: socket(PF_INET): %s",
			   strerror(errno));
		return -1;
	}
	if (test_driver_set_nonblock(drv->sock) < 0) {
		close(drv->sock);
		drv->sock = -1;
		return -1;
	}
	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	/* Local-only transport: never bind to a routable address */
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons((u16) port);
	if (bind(drv->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		wpa_printf(MSG_ERROR, "test_driver: bind(127.0.0.1:%d): %s",
			   port, strerror(errno));
		close(drv->sock);
		drv->sock = -1;
		return -1;
	}
	drv->transport = TEST_TRANSPORT_UDP;
	eloop_register_read_sock(drv->sock, test_driver_receive, drv, NULL);
	wpa_printf(MSG_DEBUG, "test_driver(%s): Bound UDP socket 127.0.0.1:%d",
		   drv->ifname, port);
	return 0;
}


static int test_driver_send_msg(struct wpa_driver_test_data *drv,
				const struct sockaddr *sa, socklen_t sa_len,
				u8 type, u8 flags, int link_id,
				const u8 *payload, size_t payload_len)
{
	u8 buf[TEST_DRV_MAX_MSG];
	ssize_t res;

	if (drv->sock < 0 || !sa || sa_len == 0)
		return -1;
	if (payload_len > TEST_DRV_MAX_PAYLOAD) {
		wpa_printf(MSG_DEBUG, "test_driver(%s): Too long payload (%zu)",
			   drv->ifname, payload_len);
		return -1;
	}
	if (test_drv_hdr_build(buf, sizeof(buf), type, flags, link_id,
			       drv->freq, drv->tx_seq++, payload_len) < 0)
		return -1;
	if (payload_len)
		os_memcpy(buf + TEST_DRV_HDR_LEN, payload, payload_len);
	res = sendto(drv->sock, buf, TEST_DRV_HDR_LEN + payload_len,
		     MSG_DONTWAIT, sa, sa_len);
	if (res < 0) {
		/* EAGAIN: the peer is not draining its queue; treat the frame
		 * as lost (no ACK) rather than blocking the process. */
		wpa_printf(MSG_DEBUG, "test_driver(%s): sendto: %s",
			   drv->ifname, strerror(errno));
		drv->stats.tx_failed++;
		return -1;
	}
	drv->stats.tx_msgs++;
	return 0;
}


static int test_driver_send_to_peer(struct wpa_driver_test_data *drv,
				    struct test_peer *peer, u8 type, u8 flags,
				    int link_id, const u8 *payload,
				    size_t payload_len)
{
	if (!peer || !peer->sa_valid)
		return -1;
	peer->tx_frames++;
	return test_driver_send_msg(drv, (struct sockaddr *) &peer->sa,
				    peer->sa_len, type, flags, link_id,
				    payload, payload_len);
}


/* Send to every reachable peer socket; each unique socket address is used
 * only once even if several (MLD link) peers share it. Returns the number of
 * successful transmissions. */
static int test_driver_send_broadcast(struct wpa_driver_test_data *drv,
				      u8 type, u8 flags, int link_id,
				      const u8 *payload, size_t payload_len)
{
	struct test_peer *peer, *prev;
	int count = 0;

	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		bool dup = false;

		if (!peer->sa_valid)
			continue;
		dl_list_for_each(prev, &drv->peers, struct test_peer, list) {
			if (prev == peer)
				break;
			if (prev->sa_valid &&
			    test_sockaddr_equal(&prev->sa, prev->sa_len,
						&peer->sa, peer->sa_len)) {
				dup = true;
				break;
			}
		}
		if (dup)
			continue;
		if (test_driver_send_to_peer(drv, peer, type, flags, link_id,
					     payload, payload_len) == 0)
			count++;
	}

	if (!drv->ap) {
		/* STA: also reach the configured AP socket and any AP socket
		 * found in the test directory (used for scanning before any
		 * peer is known). */
		if (drv->ap_sa_set) {
			bool known = false;

			dl_list_for_each(peer, &drv->peers, struct test_peer,
					 list) {
				if (peer->sa_valid &&
				    test_sockaddr_equal(&peer->sa, peer->sa_len,
							&drv->ap_sa,
							drv->ap_sa_len)) {
					known = true;
					break;
				}
			}
			if (!known &&
			    test_driver_send_msg(drv,
						 (struct sockaddr *) &drv->ap_sa,
						 drv->ap_sa_len, type, flags,
						 link_id, payload,
						 payload_len) == 0)
				count++;
		}

		if (drv->test_dir && drv->transport == TEST_TRANSPORT_UNIX) {
			DIR *dir = opendir(drv->test_dir);
			struct dirent *dent;

			while (dir && (dent = readdir(dir))) {
				struct sockaddr_un addr;
				bool known = false;
				int r;

				if (os_strncmp(dent->d_name, "AP-", 3) != 0)
					continue;
				os_memset(&addr, 0, sizeof(addr));
				addr.sun_family = AF_UNIX;
				r = os_snprintf(addr.sun_path,
						sizeof(addr.sun_path), "%s/%s",
						drv->test_dir, dent->d_name);
				if (os_snprintf_error(sizeof(addr.sun_path), r))
					continue;
				dl_list_for_each(peer, &drv->peers,
						 struct test_peer, list) {
					if (peer->sa_valid &&
					    test_sockaddr_equal(
						    &peer->sa, peer->sa_len,
						    (struct sockaddr_storage *)
						    &addr, sizeof(addr))) {
						known = true;
						break;
					}
				}
				if (known)
					continue;
				if (drv->ap_sa_set &&
				    test_sockaddr_equal(
					    &drv->ap_sa, drv->ap_sa_len,
					    (struct sockaddr_storage *) &addr,
					    sizeof(addr)))
					continue;
				if (test_driver_send_msg(
					    drv, (struct sockaddr *) &addr,
					    sizeof(addr), type, flags, link_id,
					    payload, payload_len) == 0)
					count++;
			}
			if (dir)
				closedir(dir);
		}
	}

	return count;
}


/* ---------------------------------------------------------------------- */
/* Protection (PMF) emulation                                              */

static bool test_is_robust_mgmt(const u8 *frame, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)
		frame;
	u16 fc, stype;

	if (len < IEEE80211_HDRLEN)
		return false;
	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT)
		return false;
	stype = WLAN_FC_GET_STYPE(fc);
	switch (stype) {
	case WLAN_FC_STYPE_DEAUTH:
	case WLAN_FC_STYPE_DISASSOC:
		return true;
	case WLAN_FC_STYPE_ACTION:
	case WLAN_FC_STYPE_ACTION_NO_ACK:
		if (len < IEEE80211_HDRLEN + 1)
			return false;
		switch (mgmt->u.action.category) {
		case WLAN_ACTION_PUBLIC:
		case WLAN_ACTION_HT:
		case WLAN_ACTION_UNPROTECTED_WNM:
		case WLAN_ACTION_SELF_PROTECTED:
		case WLAN_ACTION_UNPROTECTED_DMG:
		case WLAN_ACTION_VHT:
		case WLAN_ACTION_UNPROTECTED_S1G:
			return false;
		default:
			return true;
		}
	default:
		return false;
	}
}


/* ---------------------------------------------------------------------- */
/* Scan result storage (STA)                                               */

static void test_scanres_free(struct wpa_driver_test_data *drv)
{
	size_t i;

	for (i = 0; i < TEST_MAX_SCAN_RESULTS; i++) {
		os_free(drv->scanres[i]);
		drv->scanres[i] = NULL;
	}
	drv->num_scanres = 0;
}


static bool test_scan_freq_allowed(struct wpa_driver_test_data *drv, int freq)
{
	int i;

	if (!drv->scan_freqs || !freq)
		return true;
	for (i = 0; drv->scan_freqs[i]; i++) {
		if (drv->scan_freqs[i] == freq)
			return true;
	}
	return false;
}


static void test_scanres_add(struct wpa_driver_test_data *drv,
			     const struct ieee80211_mgmt *mgmt, size_t len,
			     int freq, bool beacon)
{
	struct wpa_scan_res *res, *old = NULL;
	const u8 *ies;
	size_t ies_len, i, slot = drv->num_scanres;
	struct ieee802_11_elems elems;

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_resp))
		return;
	ies = mgmt->u.probe_resp.variable;
	ies_len = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_resp));

	if (!freq && ieee802_11_parse_elems(ies, ies_len, &elems, 0) !=
	    ParseFailed && elems.ds_params) {
		int chan = elems.ds_params[0];

		if (chan >= 1 && chan <= 14)
			freq = chan == 14 ? 2484 : 2407 + chan * 5;
	}

	if (!test_scan_freq_allowed(drv, freq))
		return;

	for (i = 0; i < drv->num_scanres; i++) {
		if (drv->scanres[i] &&
		    ether_addr_equal(drv->scanres[i]->bssid, mgmt->bssid)) {
			old = drv->scanres[i];
			slot = i;
			break;
		}
	}
	if (!old && drv->num_scanres >= TEST_MAX_SCAN_RESULTS) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): No room for scan result from "
			   MACSTR, drv->ifname, MAC2STR(mgmt->bssid));
		return;
	}

	/* Keep the Probe Response IEs and the Beacon IEs separately, like a
	 * cfg80211 BSS entry does. A Beacon frame only updates the Beacon IE
	 * part of an existing entry; a Probe Response updates the main part
	 * and keeps the previously seen Beacon IEs. */
	if (old) {
		const u8 *old_ie = (const u8 *) (old + 1);
		const u8 *keep;
		size_t keep_len;

		if (beacon) {
			keep = old_ie;
			keep_len = old->ie_len;
			res = os_zalloc(sizeof(*res) + keep_len + ies_len);
			if (!res)
				return;
			os_memcpy(res, old, sizeof(*res));
			os_memcpy(res + 1, keep, keep_len);
			os_memcpy((u8 *) (res + 1) + keep_len, ies, ies_len);
			res->ie_len = keep_len;
			res->beacon_ie_len = ies_len;
		} else {
			keep = old_ie + old->ie_len;
			keep_len = old->beacon_ie_len;
			res = os_zalloc(sizeof(*res) + ies_len + keep_len);
			if (!res)
				return;
			os_memcpy(res, old, sizeof(*res));
			os_memcpy(res + 1, ies, ies_len);
			os_memcpy((u8 *) (res + 1) + ies_len, keep, keep_len);
			res->ie_len = ies_len;
			res->beacon_ie_len = keep_len;
		}
	} else {
		res = os_zalloc(sizeof(*res) + ies_len);
		if (!res)
			return;
		os_memcpy(res + 1, ies, ies_len);
		if (beacon) {
			res->ie_len = 0;
			res->beacon_ie_len = ies_len;
		} else {
			res->ie_len = ies_len;
			res->beacon_ie_len = 0;
		}
	}

	res->flags = WPA_SCAN_LEVEL_DBM | WPA_SCAN_QUAL_INVALID |
		WPA_SCAN_NOISE_INVALID;
	os_memcpy(res->bssid, mgmt->bssid, ETH_ALEN);
	res->freq = freq;
	res->beacon_int = le_to_host16(mgmt->u.probe_resp.beacon_int);
	res->caps = le_to_host16(mgmt->u.probe_resp.capab_info);
	res->level = -30; /* synthetic, constant signal level */
	res->noise = 0;
	res->qual = 0;
	res->tsf = WPA_GET_LE64(mgmt->u.probe_resp.timestamp);
	res->age = 0;
	res->beacon_newer = beacon;

	os_free(old);
	drv->scanres[slot] = res;
	if (!old)
		drv->num_scanres++;
}


/* ---------------------------------------------------------------------- */
/* STA: MLD address translation                                            */

static int test_sta_link_by_bssid(struct wpa_driver_test_data *drv,
				  const u8 *addr)
{
	int i;

	if (!drv->mlo)
		return -1;
	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		if ((drv->req_links & BIT(i)) &&
		    ether_addr_equal(drv->links[i].bssid, addr))
			return i;
	}
	return -1;
}


static int test_sta_link_by_own_addr(struct wpa_driver_test_data *drv,
				     const u8 *addr)
{
	int i;

	if (!drv->mlo)
		return -1;
	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		if ((drv->req_links & BIT(i)) &&
		    ether_addr_equal(drv->links[i].addr, addr))
			return i;
	}
	return -1;
}


/* Translate link addresses in a received frame to MLD addresses (what
 * mac80211 delivers to wpa_supplicant for an MLO association). Returns the
 * link ID the frame was received on or -1. */
static int test_sta_rx_translate(struct wpa_driver_test_data *drv,
				 struct ieee80211_hdr *hdr)
{
	int link_id;

	if (!drv->mlo)
		return -1;
	link_id = test_sta_link_by_bssid(drv, hdr->addr2);
	if (link_id < 0)
		return -1;
	os_memcpy(hdr->addr2, drv->ap_mld_addr, ETH_ALEN);
	if (test_sta_link_by_bssid(drv, hdr->addr3) >= 0)
		os_memcpy(hdr->addr3, drv->ap_mld_addr, ETH_ALEN);
	if (test_sta_link_by_own_addr(drv, hdr->addr1) >= 0)
		os_memcpy(hdr->addr1, drv->own_addr, ETH_ALEN);
	return link_id;
}


/* Translate MLD addresses in a frame to be transmitted into link addresses.
 * Returns the link ID used, or -1 for a non-MLO frame. */
static int test_sta_tx_translate(struct wpa_driver_test_data *drv,
				 struct ieee80211_hdr *hdr, int link_id)
{
	if (!drv->mlo)
		return -1;
	if (link_id < 0 || !(drv->req_links & BIT(link_id)))
		link_id = drv->assoc_link_id;
	if (ether_addr_equal(hdr->addr1, drv->ap_mld_addr))
		os_memcpy(hdr->addr1, drv->links[link_id].bssid, ETH_ALEN);
	if (ether_addr_equal(hdr->addr3, drv->ap_mld_addr))
		os_memcpy(hdr->addr3, drv->links[link_id].bssid, ETH_ALEN);
	if (ether_addr_equal(hdr->addr2, drv->own_addr))
		os_memcpy(hdr->addr2, drv->links[link_id].addr, ETH_ALEN);
	return link_id;
}


static void test_sta_reset_mlo(struct wpa_driver_test_data *drv)
{
	drv->mlo = false;
	drv->req_links = 0;
	drv->valid_links = 0;
	drv->assoc_link_id = 0;
	os_memset(drv->ap_mld_addr, 0, ETH_ALEN);
	os_memset(drv->links, 0, sizeof(drv->links));
}


#ifdef CONFIG_IEEE80211BE
static void test_sta_derive_link_addr(struct wpa_driver_test_data *drv,
				      int link_id, u8 *addr)
{
	os_memcpy(addr, drv->own_addr, ETH_ALEN);
	if (link_id == drv->assoc_link_id)
		return;
	/* Deterministic per-link address: keep the OUI, flip the link index
	 * into the last octet and mark locally administered. */
	addr[0] |= 0x02;
	addr[5] ^= (u8) (0x11 * (link_id + 1));
}
#endif /* CONFIG_IEEE80211BE */


/* ---------------------------------------------------------------------- */
/* STA: connection state                                                   */

static struct test_peer * test_sta_ap_peer(struct wpa_driver_test_data *drv,
					   const u8 *addr, int link_id)
{
	struct test_peer *peer;
	const u8 *target = addr;

	if (drv->mlo && ether_addr_equal(addr, drv->ap_mld_addr)) {
		if (link_id < 0 || !(drv->req_links & BIT(link_id)))
			link_id = drv->assoc_link_id;
		target = drv->links[link_id].bssid;
	}
	peer = test_peer_get(drv, target);
	if (peer)
		return peer;
	if (drv->ap_sa_set) {
		/* Unknown BSSID but a single AP socket is configured: create
		 * the peer entry pointing at that socket. */
		peer = test_peer_add(drv, target);
		if (peer)
			test_peer_set_sa(peer, &drv->ap_sa, drv->ap_sa_len);
	}
	return peer;
}


static void test_sta_disconnected(struct wpa_driver_test_data *drv)
{
	drv->sta_state = TEST_STA_IDLE;
	test_clear_keys(&drv->ptk, 1);
	test_clear_keys(drv->gtk, TEST_MAX_GROUP_KEYS);
	drv->mfp = false;
	eloop_cancel_timeout(test_driver_auth_timeout, drv, NULL);
	eloop_cancel_timeout(test_driver_assoc_timeout, drv, NULL);
	eloop_cancel_timeout(test_driver_keepalive, drv, NULL);
	os_free(drv->assoc_req_ies);
	drv->assoc_req_ies = NULL;
	drv->assoc_req_ies_len = 0;
#ifdef CONFIG_FILS
	forced_memzero(drv->fils_kek, sizeof(drv->fils_kek));
	drv->fils_kek_len = 0;
#endif /* CONFIG_FILS */
}


/* ---------------------------------------------------------------------- */
/* RX processing                                                           */

static void test_ap_rx_mgmt(struct wpa_driver_test_data *drv,
			    const struct test_drv_hdr *hdr,
			    const struct sockaddr_storage *from,
			    socklen_t fromlen, u8 *frame, size_t len)
{
	struct ieee80211_hdr *hdr80211 = (struct ieee80211_hdr *) frame;
	struct test_peer *peer;
	struct test_bss *bss = NULL;
	u16 fc;
	bool bcast;
	union wpa_event_data event;
	int link_id;

	fc = le_to_host16(hdr80211->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT) {
		drv->stats.rx_invalid_frame++;
		return;
	}

	if (is_multicast_ether_addr(hdr80211->addr2)) {
		drv->stats.rx_invalid_frame++;
		return;
	}

	bcast = is_broadcast_ether_addr(hdr80211->addr1) &&
		is_broadcast_ether_addr(hdr80211->addr3);
	if (!bcast) {
		bss = test_bss_by_addr(drv, hdr80211->addr3);
		if (!bss)
			bss = test_bss_by_addr(drv, hdr80211->addr1);
		if (!bss && test_drv_is_mld(drv) &&
		    (ether_addr_equal(hdr80211->addr3, drv->own_addr) ||
		     ether_addr_equal(hdr80211->addr1, drv->own_addr)) &&
		    hdr->link_id != TEST_DRV_LINK_ID_NONE)
			bss = test_bss_by_link(drv, hdr->link_id);
		if (!bss) {
			drv->stats.rx_dropped_no_bss++;
			return;
		}
	}

	peer = test_peer_get(drv, hdr80211->addr2);
	if (!peer) {
		peer = test_peer_add(drv, hdr80211->addr2);
		if (!peer)
			return;
		if (bss)
			peer->bss = bss;
	}
	test_peer_set_sa(peer, from, fromlen);
	os_get_reltime(&peer->last_rx);
	peer->rx_frames++;

	/* Protection emulation (see test_is_robust_mgmt()). Like mac80211,
	 * the Protected Frame bit is left set in the frame delivered to
	 * hostapd so that its own MFP checks can be applied. */
	if (fc & WLAN_FC_PROTECTED) {
		if (!peer->ptk.set) {
			drv->stats.rx_dropped_undecryptable++;
			return;
		}
	} else if (test_is_robust_mgmt(frame, len) && peer->ptk.set &&
		   (peer->flags & WPA_STA_MFP)) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): Drop unprotected robust frame from "
			   MACSTR, drv->ifname, MAC2STR(peer->addr));
		drv->stats.rx_dropped_unprotected++;
		return;
	}

	/* MLD address translation once the link STA has been added */
	link_id = -1;
	if (peer->mld && peer->added) {
		os_memcpy(hdr80211->addr2, peer->mld_addr, ETH_ALEN);
		if (bss && bss->mld_link) {
			if (ether_addr_equal(hdr80211->addr1, bss->addr))
				os_memcpy(hdr80211->addr1, drv->own_addr,
					  ETH_ALEN);
			if (ether_addr_equal(hdr80211->addr3, bss->addr))
				os_memcpy(hdr80211->addr3, drv->own_addr,
					  ETH_ALEN);
		}
	}
	if (bss && bss->mld_link)
		link_id = bss->link_id;

	drv->stats.rx_mgmt++;

	os_memset(&event, 0, sizeof(event));
	event.rx_mgmt.frame = frame;
	event.rx_mgmt.frame_len = len;
	event.rx_mgmt.freq = bss ? bss->freq : drv->freq;
	event.rx_mgmt.ssi_signal = -30;
	event.rx_mgmt.link_id = link_id;

	if (bss) {
		event.rx_mgmt.ctx = bss->ctx;
		wpa_supplicant_event(bss->ctx, EVENT_RX_MGMT, &event);
		return;
	}

	/* Broadcast (e.g., wildcard Probe Request): deliver once per BSS so
	 * that each BSS can respond, like a kernel driver does per vif. */
	{
		struct test_bss *b, *tmp;

		dl_list_for_each_safe(b, tmp, &drv->bss, struct test_bss,
				      list) {
			if (!b->ctx)
				continue;
			event.rx_mgmt.ctx = b->ctx;
			event.rx_mgmt.link_id = b->mld_link ? b->link_id : -1;
			event.rx_mgmt.freq = b->freq;
			wpa_supplicant_event(b->ctx, EVENT_RX_MGMT, &event);
		}
	}
}


static void test_sta_rx_mgmt(struct wpa_driver_test_data *drv,
			     const struct test_drv_hdr *hdr,
			     const struct sockaddr_storage *from,
			     socklen_t fromlen, u8 *frame, size_t len)
{
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) frame;
	struct ieee80211_hdr *hdr80211 = (struct ieee80211_hdr *) frame;
	struct test_peer *peer;
	u16 fc, stype;
	union wpa_event_data event;
	int link_id;
	int freq = le_to_host32(hdr->freq);
	bool to_us;

	fc = le_to_host16(mgmt->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
	    is_multicast_ether_addr(mgmt->sa)) {
		drv->stats.rx_invalid_frame++;
		return;
	}
	stype = WLAN_FC_GET_STYPE(fc);

	peer = test_peer_get(drv, mgmt->sa);
	if (!peer) {
		peer = test_peer_add(drv, mgmt->sa);
		if (!peer)
			return;
	}
	test_peer_set_sa(peer, from, fromlen);
	os_get_reltime(&peer->last_rx);
	peer->rx_frames++;
	if (freq)
		peer->link_id = -1;

	to_us = is_broadcast_ether_addr(mgmt->da) ||
		ether_addr_equal(mgmt->da, drv->own_addr) ||
		test_sta_link_by_own_addr(drv, mgmt->da) >= 0;

	/* Protection emulation; the Protected Frame bit is left set */
	if (fc & WLAN_FC_PROTECTED) {
		if (!drv->ptk.set || !to_us) {
			drv->stats.rx_dropped_undecryptable++;
			return;
		}
	} else if (test_is_robust_mgmt(frame, len) && drv->ptk.set &&
		   drv->mfp && to_us) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): Drop unprotected robust frame from "
			   MACSTR, drv->ifname, MAC2STR(mgmt->sa));
		drv->stats.rx_dropped_unprotected++;
		return;
	}

	drv->stats.rx_mgmt++;
	os_memset(&event, 0, sizeof(event));

	switch (stype) {
	case WLAN_FC_STYPE_BEACON:
	case WLAN_FC_STYPE_PROBE_RESP:
		if (stype == WLAN_FC_STYPE_PROBE_RESP && !to_us)
			return;
		test_scanres_add(drv, mgmt, len, freq,
				 stype == WLAN_FC_STYPE_BEACON);
		return;
	case WLAN_FC_STYPE_PROBE_REQ:
		if (!drv->probe_req_report ||
		    len < IEEE80211_HDRLEN)
			return;
		event.rx_probe_req.sa = mgmt->sa;
		event.rx_probe_req.da = mgmt->da;
		event.rx_probe_req.bssid = mgmt->bssid;
		event.rx_probe_req.ie = frame + IEEE80211_HDRLEN;
		event.rx_probe_req.ie_len = len - IEEE80211_HDRLEN;
		event.rx_probe_req.ssi_signal = -30;
		wpa_supplicant_event(drv->ctx, EVENT_RX_PROBE_REQ, &event);
		return;
	default:
		break;
	}

	if (!to_us)
		return;

	/* From here on: frames addressed to this station */
	link_id = test_sta_rx_translate(drv, hdr80211);

	switch (stype) {
	case WLAN_FC_STYPE_AUTH:
		if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.auth))
			return;
		if (drv->sta_state != TEST_STA_AUTHENTICATING &&
		    drv->sta_state != TEST_STA_AUTHENTICATED &&
		    drv->sta_state != TEST_STA_ASSOCIATED) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): Ignore unexpected Authentication frame",
				   drv->ifname);
			return;
		}
		if (!ether_addr_equal(mgmt->sa, drv->mlo ? drv->ap_mld_addr :
				      drv->bssid)) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): Authentication frame from unexpected peer "
				   MACSTR, drv->ifname, MAC2STR(mgmt->sa));
			return;
		}
		eloop_cancel_timeout(test_driver_auth_timeout, drv, NULL);
		event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
		event.auth.auth_transaction =
			le_to_host16(mgmt->u.auth.auth_transaction);
		event.auth.status_code =
			le_to_host16(mgmt->u.auth.status_code);
		os_memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
		os_memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
		event.auth.ies = mgmt->u.auth.variable;
		event.auth.ies_len = len - IEEE80211_HDRLEN -
			sizeof(mgmt->u.auth);
		event.auth.frame_body = (const u8 *) &mgmt->u.auth;
		event.auth.frame_body_len = len - IEEE80211_HDRLEN;
		if (event.auth.status_code == WLAN_STATUS_SUCCESS &&
		    drv->sta_state == TEST_STA_AUTHENTICATING &&
		    (event.auth.auth_type != WLAN_AUTH_SAE ||
		     event.auth.auth_transaction == 2))
			drv->sta_state = TEST_STA_AUTHENTICATED;
		wpa_supplicant_event(drv->ctx, EVENT_AUTH, &event);
		return;

	case WLAN_FC_STYPE_ASSOC_RESP:
	case WLAN_FC_STYPE_REASSOC_RESP: {
		u16 status;

		if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_resp))
			return;
		if (drv->sta_state != TEST_STA_ASSOCIATING) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): Ignore unexpected (Re)Association Response",
				   drv->ifname);
			return;
		}
		if (!ether_addr_equal(mgmt->sa, drv->mlo ? drv->ap_mld_addr :
				      drv->bssid))
			return;
		eloop_cancel_timeout(test_driver_assoc_timeout, drv, NULL);
		status = le_to_host16(mgmt->u.assoc_resp.status_code);
		if (status != WLAN_STATUS_SUCCESS) {
			drv->sta_state = TEST_STA_AUTHENTICATED;
			event.assoc_reject.bssid = mgmt->bssid;
			event.assoc_reject.resp_ies =
				mgmt->u.assoc_resp.variable;
			event.assoc_reject.resp_ies_len = len -
				IEEE80211_HDRLEN - sizeof(mgmt->u.assoc_resp);
			event.assoc_reject.status_code = status;
			wpa_supplicant_event(drv->ctx, EVENT_ASSOC_REJECT,
					     &event);
			return;
		}

#ifdef CONFIG_FILS
		if (drv->fils_kek_len) {
			/* Decrypt the FILS protected elements in place, like
			 * mac80211 does before delivering the frame */
			const u8 *ies = mgmt->u.assoc_resp.variable;
			size_t ies_len = len - IEEE80211_HDRLEN -
				sizeof(mgmt->u.assoc_resp);
			const u8 *session, *aad[5];
			u8 *crypt;
			size_t aad_len[5], crypt_len;
			u8 *plain;

			session = get_ie_ext(ies, ies_len,
					     WLAN_EID_EXT_FILS_SESSION);
			if (!session) {
				wpa_printf(MSG_DEBUG,
					   "test_driver(%s): FILS: No FILS Session element in response",
					   drv->ifname);
				drv->stats.rx_invalid_frame++;
				return;
			}
			crypt = (u8 *) session + 2 + session[1];
			crypt_len = frame + len - crypt;
			if (crypt_len < AES_BLOCK_SIZE) {
				drv->stats.rx_invalid_frame++;
				return;
			}
			aad[0] = mgmt->sa; /* AP BSSID */
			aad_len[0] = ETH_ALEN;
			aad[1] = mgmt->da; /* STA MAC address */
			aad_len[1] = ETH_ALEN;
			aad[2] = drv->fils_nonces + NONCE_LEN; /* ANonce */
			aad_len[2] = NONCE_LEN;
			aad[3] = drv->fils_nonces; /* SNonce */
			aad_len[3] = NONCE_LEN;
			aad[4] = frame + IEEE80211_HDRLEN;
			aad_len[4] = crypt - aad[4];
			plain = os_malloc(crypt_len);
			if (!plain)
				return;
			if (aes_siv_decrypt(drv->fils_kek, drv->fils_kek_len,
					    crypt, crypt_len, 5, aad, aad_len,
					    plain) < 0) {
				wpa_printf(MSG_DEBUG,
					   "test_driver(%s): FILS: AES-SIV decryption of (Re)Association Response failed",
					   drv->ifname);
				os_free(plain);
				drv->stats.rx_dropped_undecryptable++;
				return;
			}
			os_memcpy(crypt, plain, crypt_len - AES_BLOCK_SIZE);
			os_free(plain);
			len -= AES_BLOCK_SIZE;
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): FILS: Decrypted %zu octets of (Re)Association Response elements",
				   drv->ifname, crypt_len - AES_BLOCK_SIZE);
			forced_memzero(drv->fils_kek, sizeof(drv->fils_kek));
			drv->fils_kek_len = 0;
		}
#endif /* CONFIG_FILS */

		if (drv->mlo) {
			/* Determine which requested links were accepted from
			 * the per-STA profiles of the Basic Multi-Link element
			 * in the (Re)Association Response frame. */
			const u8 *ies = mgmt->u.assoc_resp.variable;
			size_t ies_len = len - IEEE80211_HDRLEN -
				sizeof(mgmt->u.assoc_resp);
			struct wpabuf *mlbuf = NULL;
			struct ieee802_11_elems elems;

			drv->valid_links = BIT(drv->assoc_link_id);
			if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) !=
			    ParseFailed && elems.basic_mle)
				mlbuf = ieee802_11_defrag(elems.basic_mle,
							  elems.basic_mle_len,
							  true);
			if (mlbuf) {
				int i;

				for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
					struct ieee802_11_elems e;

					if (i == (int) drv->assoc_link_id ||
					    !(drv->req_links & BIT(i)))
						continue;
					/* The parser fails for a per-STA
					 * profile with a non-zero status
					 * code, i.e., ParseOK implies the
					 * link was accepted. */
					if (ieee802_11_parse_link_assoc_resp(
						    &e, mlbuf, i, false) ==
					    ParseOK)
						drv->valid_links |= BIT(i);
				}
				wpabuf_free(mlbuf);
			}
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): MLO association: requested links 0x%x, accepted links 0x%x",
				   drv->ifname, drv->req_links,
				   drv->valid_links);
		}

		drv->sta_state = TEST_STA_ASSOCIATED;
		eloop_cancel_timeout(test_driver_keepalive, drv, NULL);
		if (drv->keepalive_ms)
			eloop_register_timeout(drv->keepalive_ms / 1000,
					       (drv->keepalive_ms % 1000) *
					       1000,
					       test_driver_keepalive, drv, NULL);
		event.assoc_info.reassoc = drv->reassoc;
		event.assoc_info.req_ies = drv->assoc_req_ies;
		event.assoc_info.req_ies_len = drv->assoc_req_ies_len;
		event.assoc_info.resp_ies = mgmt->u.assoc_resp.variable;
		event.assoc_info.resp_ies_len = len - IEEE80211_HDRLEN -
			sizeof(mgmt->u.assoc_resp);
		event.assoc_info.resp_frame = frame;
		event.assoc_info.resp_frame_len = len;
		event.assoc_info.freq = drv->freq;
		event.assoc_info.assoc_link_id = drv->mlo ?
			drv->assoc_link_id : -1;
		wpa_supplicant_event(drv->ctx, EVENT_ASSOC, &event);
		return;
	}

	case WLAN_FC_STYPE_DEAUTH:
	case WLAN_FC_STYPE_DISASSOC: {
		u16 reason;
		const u8 *ie;
		size_t ie_len;

		if (len < IEEE80211_HDRLEN + 2)
			return;
		if (drv->sta_state == TEST_STA_IDLE)
			return;
		if (!ether_addr_equal(mgmt->sa, drv->mlo ? drv->ap_mld_addr :
				      drv->bssid))
			return;
		reason = le_to_host16(mgmt->u.deauth.reason_code);
		ie = frame + IEEE80211_HDRLEN + 2;
		ie_len = len - IEEE80211_HDRLEN - 2;
		test_sta_disconnected(drv);
		if (stype == WLAN_FC_STYPE_DEAUTH) {
			event.deauth_info.addr = mgmt->sa;
			event.deauth_info.reason_code = reason;
			event.deauth_info.ie = ie;
			event.deauth_info.ie_len = ie_len;
			wpa_supplicant_event(drv->ctx, EVENT_DEAUTH, &event);
		} else {
			event.disassoc_info.addr = mgmt->sa;
			event.disassoc_info.reason_code = reason;
			event.disassoc_info.ie = ie;
			event.disassoc_info.ie_len = ie_len;
			wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, &event);
		}
		return;
	}

	case WLAN_FC_STYPE_ACTION:
	case WLAN_FC_STYPE_ACTION_NO_ACK:
		event.rx_mgmt.frame = frame;
		event.rx_mgmt.frame_len = len;
		event.rx_mgmt.freq = freq ? freq : drv->freq;
		event.rx_mgmt.ssi_signal = -30;
		event.rx_mgmt.link_id = link_id;
		wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
		return;

	default:
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): Ignore management frame subtype %u",
			   drv->ifname, stype);
		return;
	}
}


static void test_rx_eapol(struct wpa_driver_test_data *drv,
			  const struct test_drv_hdr *hdr,
			  const struct sockaddr_storage *from,
			  socklen_t fromlen, u8 *payload, size_t len)
{
	struct l2_ethhdr *eth = (struct l2_ethhdr *) payload;
	u16 proto;
	enum frame_encryption encrypted;
	struct test_peer *peer;
	int link_id = -1;
	void *ctx = drv->ctx;
	const u8 *src;
	u8 mld_src[ETH_ALEN];

	if (len < sizeof(*eth) + 4) {
		drv->stats.rx_invalid_frame++;
		return;
	}
	proto = be_to_host16(eth->h_proto);
	if (proto != ETH_P_EAPOL && proto != ETH_P_RSN_PREAUTH) {
		drv->stats.rx_invalid_frame++;
		return;
	}
	if (is_multicast_ether_addr(eth->h_source)) {
		drv->stats.rx_invalid_frame++;
		return;
	}
	encrypted = (hdr->flags & TEST_DRV_FLAG_PROTECTED) ?
		FRAME_ENCRYPTED : FRAME_NOT_ENCRYPTED;

	peer = test_peer_get(drv, eth->h_source);
	if (!peer) {
		peer = test_peer_add(drv, eth->h_source);
		if (!peer)
			return;
	}
	test_peer_set_sa(peer, from, fromlen);
	os_get_reltime(&peer->last_rx);
	peer->rx_frames++;

	src = eth->h_source;
	if (drv->ap) {
		struct test_bss *bss;

		bss = test_bss_by_addr(drv, eth->h_dest);
		if (!bss && test_drv_is_mld(drv) &&
		    ether_addr_equal(eth->h_dest, drv->own_addr) &&
		    hdr->link_id != TEST_DRV_LINK_ID_NONE)
			bss = test_bss_by_link(drv, hdr->link_id);
		if (!bss && !is_multicast_ether_addr(eth->h_dest)) {
			drv->stats.rx_dropped_no_bss++;
			return;
		}
		if (!bss)
			bss = peer->bss ? peer->bss : test_bss_first(drv);
		if (!bss || !bss->ctx) {
			drv->stats.rx_dropped_no_bss++;
			return;
		}
		if (bss->mld_link)
			link_id = bss->link_id;
		if (peer->mld && peer->added) {
			os_memcpy(mld_src, peer->mld_addr, ETH_ALEN);
			src = mld_src;
		}
		ctx = bss->ctx;
	} else {
		int l;

		if (!ether_addr_equal(eth->h_dest, drv->own_addr) &&
		    test_sta_link_by_own_addr(drv, eth->h_dest) < 0 &&
		    !is_multicast_ether_addr(eth->h_dest)) {
			drv->stats.rx_invalid_frame++;
			return;
		}
		l = test_sta_link_by_bssid(drv, eth->h_source);
		if (l >= 0) {
			link_id = l;
			os_memcpy(mld_src, drv->ap_mld_addr, ETH_ALEN);
			src = mld_src;
		}
	}

	drv->stats.rx_eapol++;
	drv_event_eapol_rx2(ctx, src, payload + sizeof(*eth),
			    len - sizeof(*eth), encrypted, link_id);
}


static void test_driver_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	u8 buf[TEST_DRV_MAX_MSG + 1];
	ssize_t res;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	struct test_drv_hdr hdr;
	const u8 *payload;
	size_t payload_len;

	os_memset(&from, 0, sizeof(from));
	res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &from,
		       &fromlen);
	if (res < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		wpa_printf(MSG_DEBUG, "test_driver(%s): recvfrom: %s",
			   drv->ifname, strerror(errno));
		if (errno == ECONNREFUSED && !drv->ap &&
		    drv->sta_state == TEST_STA_ASSOCIATED) {
			/* UDP: the AP socket is gone */
			struct test_pending_event *ev;

			drv->stats.peer_lost++;
			ev = test_pending_add(drv, TEST_EV_LOCAL_DEAUTH,
					      drv->ctx, NULL, 0);
			if (ev) {
				os_memcpy(ev->addr, drv->mlo ?
					  drv->ap_mld_addr : drv->bssid,
					  ETH_ALEN);
				ev->reason =
					WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY;
			}
			test_sta_disconnected(drv);
		}
		return;
	}
	drv->stats.rx_msgs++;

	if (fromlen > sizeof(from))
		fromlen = sizeof(from);

	if (test_drv_hdr_parse(buf, (size_t) res, &hdr, &payload,
			       &payload_len) < 0) {
		drv->stats.rx_invalid_hdr++;
		wpa_hexdump(MSG_MSGDUMP, "test_driver: Invalid datagram", buf,
			    res > 64 ? 64 : res);
		return;
	}

	/* Frames from our own socket are never expected */
	if (drv->transport == TEST_TRANSPORT_UNIX && drv->own_socket_path) {
		const struct sockaddr_un *un = (const struct sockaddr_un *)
			&from;

		if (fromlen > offsetof(struct sockaddr_un, sun_path) &&
		    un->sun_path[0] != '\0' &&
		    os_strncmp(un->sun_path, drv->own_socket_path,
			       sizeof(un->sun_path)) == 0)
			return;
	}

	switch (hdr.type) {
	case TEST_DRV_MSG_MGMT:
		if (payload_len < IEEE80211_HDRLEN) {
			drv->stats.rx_invalid_frame++;
			return;
		}
		/* payload points into buf, which is writable */
		if (drv->ap)
			test_ap_rx_mgmt(drv, &hdr, &from, fromlen,
					(u8 *) payload, payload_len);
		else
			test_sta_rx_mgmt(drv, &hdr, &from, fromlen,
					 (u8 *) payload, payload_len);
		break;
	case TEST_DRV_MSG_EAPOL:
		test_rx_eapol(drv, &hdr, &from, fromlen, (u8 *) payload,
			      payload_len);
		break;
	case TEST_DRV_MSG_NULL:
		drv->stats.rx_null++;
		{
			/* Liveness probe: refresh the sender's activity time
			 * if known; unknown senders are not added. */
			struct test_peer *peer;

			dl_list_for_each(peer, &drv->peers, struct test_peer,
					 list) {
				if (peer->sa_valid &&
				    test_sockaddr_equal(&peer->sa, peer->sa_len,
							&from, fromlen))
					os_get_reltime(&peer->last_rx);
			}
		}
		break;
	default:
		drv->stats.rx_unknown_type++;
		break;
	}
}


/* ---------------------------------------------------------------------- */
/* Common driver operations                                                */

static void test_driver_free_bsses(struct wpa_driver_test_data *drv)
{
	struct test_bss *bss, *tmp;

	dl_list_for_each_safe(bss, tmp, &drv->bss, struct test_bss, list) {
		dl_list_del(&bss->list);
		test_bss_free(bss);
	}
}


static struct wpa_driver_test_data * test_alloc_data(void *ctx,
						     const char *ifname,
						     bool ap)
{
	struct wpa_driver_test_data *drv;

	if (!ifname || os_strlen(ifname) == 0 ||
	    os_strlen(ifname) >= IFNAMSIZ) {
		wpa_printf(MSG_ERROR, "test_driver: Invalid interface name");
		return NULL;
	}

	drv = os_zalloc(sizeof(*drv));
	if (!drv)
		return NULL;
	drv->ctx = ctx;
	drv->ap = ap;
	drv->sock = -1;
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));
	dl_list_init(&drv->bss);
	dl_list_init(&drv->peers);
	dl_list_init(&drv->pending);
	drv->scan_time_ms = TEST_DEFAULT_SCAN_TIME_MS;
	drv->auth_timeout_ms = TEST_DEFAULT_AUTH_TIMEOUT_MS;
	drv->assoc_timeout_ms = TEST_DEFAULT_ASSOC_TIMEOUT_MS;
	drv->keepalive_ms = TEST_DEFAULT_KEEPALIVE_MS;
	drv->phy_caps = TEST_PHY_ALL;
#ifdef CONFIG_IEEE80211BE
	drv->mlo_capable = true;
#endif /* CONFIG_IEEE80211BE */
	drv->freq = 2412;

	/* Deterministic synthetic MAC address derived from the interface
	 * name so that multiple instances never collide. */
	test_derive_addr(ifname, ap ? "hostapd test mac addr generation" :
			 "test mac addr generation", drv->own_addr);
	return drv;
}


static int test_driver_parse_common_params(struct wpa_driver_test_data *drv,
					   const char *params)
{
	const char *pos;
	int scan_time, auth_timeout, assoc_timeout, keepalive;

	if (!params)
		return 0;

	scan_time = drv->scan_time_ms;
	auth_timeout = drv->auth_timeout_ms;
	assoc_timeout = drv->assoc_timeout_ms;
	keepalive = drv->keepalive_ms;
	pos = os_strstr(params, "scan_time=");
	if (pos)
		scan_time = atoi(pos + 10);
	pos = os_strstr(params, "auth_timeout=");
	if (pos)
		auth_timeout = atoi(pos + 13);
	pos = os_strstr(params, "assoc_timeout=");
	if (pos)
		assoc_timeout = atoi(pos + 14);
	pos = os_strstr(params, "keepalive=");
	if (pos)
		keepalive = atoi(pos + 10);
	if (scan_time < 0 || scan_time > 60000 ||
	    auth_timeout < 0 || auth_timeout > 60000 ||
	    assoc_timeout < 0 || assoc_timeout > 60000 ||
	    keepalive < 0 || keepalive > 60000) {
		wpa_printf(MSG_ERROR, "test_driver: Timer value out of range");
		return -1;
	}
	drv->scan_time_ms = scan_time;
	drv->auth_timeout_ms = auth_timeout;
	drv->assoc_timeout_ms = assoc_timeout;
	drv->keepalive_ms = keepalive;
	pos = os_strstr(params, "mlo=");
	if (pos)
		drv->mlo_capable = atoi(pos + 4) != 0;
	pos = os_strstr(params, "phy=");
	if (pos) {
		char *val, *tok, *end, *ctx = NULL;

		pos += 4;
		end = os_strchr(pos, ' ');
		val = end ? dup_binstr(pos, end - pos) : os_strdup(pos);
		if (!val)
			return -1;
		unsigned int phy = 0;

		for (tok = str_token(val, ",", &ctx); tok;
		     tok = str_token(NULL, ",", &ctx)) {
			if (os_strcmp(tok, "ht") == 0)
				phy |= TEST_PHY_HT;
			else if (os_strcmp(tok, "vht") == 0)
				phy |= TEST_PHY_VHT;
			else if (os_strcmp(tok, "he") == 0)
				phy |= TEST_PHY_HE;
			else if (os_strcmp(tok, "eht") == 0)
				phy |= TEST_PHY_EHT;
			else if (os_strcmp(tok, "all") == 0)
				phy = TEST_PHY_ALL;
			else if (os_strcmp(tok, "none") == 0)
				phy = 0;
			else {
				wpa_printf(MSG_ERROR,
					   "test_driver: Unknown phy option '%s'",
					   tok);
				os_free(val);
				return -1;
			}
		}
		drv->phy_caps = phy;
		os_free(val);
	}

	return 0;
}


static char * test_driver_param_value(const char *params, const char *name)
{
	const char *pos, *end;

	if (!params)
		return NULL;
	pos = os_strstr(params, name);
	if (!pos)
		return NULL;
	pos += os_strlen(name);
	end = os_strchr(pos, ' ');
	if (end)
		return dup_binstr(pos, end - pos);
	return os_strdup(pos);
}


static void test_driver_deinit_common(struct wpa_driver_test_data *drv)
{
	eloop_cancel_timeout(test_driver_scan_timeout, drv, ELOOP_ALL_CTX);
	eloop_cancel_timeout(test_driver_auth_timeout, drv, NULL);
	eloop_cancel_timeout(test_driver_assoc_timeout, drv, NULL);
	eloop_cancel_timeout(test_driver_keepalive, drv, NULL);
	eloop_cancel_timeout(test_driver_roc_timeout, drv, NULL);
	test_pending_free_all(drv);
	test_peers_flush(drv);
	test_driver_free_bsses(drv);
	test_driver_close_socket(drv);
	test_scanres_free(drv);
	os_free(drv->scan_freqs);
	os_free(drv->assoc_req_ies);
	os_free(drv->test_dir);
	if (drv->global && drv->global->num_ifaces)
		drv->global->num_ifaces--;
	os_free(drv);
}


static int test_driver_get_capa(void *priv, struct wpa_driver_capa *capa)
{
#ifdef CONFIG_IEEE80211BE
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
#endif /* CONFIG_IEEE80211BE */

	os_memset(capa, 0, sizeof(*capa));
	capa->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA_NONE |
		WPA_DRIVER_CAPA_KEY_MGMT_FT |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_SUITE_B |
		WPA_DRIVER_CAPA_KEY_MGMT_SUITE_B_192 |
		WPA_DRIVER_CAPA_KEY_MGMT_OWE |
		WPA_DRIVER_CAPA_KEY_MGMT_DPP |
		WPA_DRIVER_CAPA_KEY_MGMT_FILS_SHA256 |
		WPA_DRIVER_CAPA_KEY_MGMT_FILS_SHA384 |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_FILS_SHA256 |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_FILS_SHA384 |
		WPA_DRIVER_CAPA_KEY_MGMT_SAE |
		WPA_DRIVER_CAPA_KEY_MGMT_802_1X_SHA256 |
		WPA_DRIVER_CAPA_KEY_MGMT_PSK_SHA256 |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_SAE |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_802_1X_SHA384 |
		WPA_DRIVER_CAPA_KEY_MGMT_SAE_EXT_KEY |
		WPA_DRIVER_CAPA_KEY_MGMT_FT_SAE_EXT_KEY;
	capa->key_mgmt_iftype[WPA_IF_STATION] = capa->key_mgmt;
	capa->key_mgmt_iftype[WPA_IF_AP_BSS] = capa->key_mgmt;
	capa->enc = WPA_DRIVER_CAPA_ENC_WEP40 |
		WPA_DRIVER_CAPA_ENC_WEP104 |
		WPA_DRIVER_CAPA_ENC_TKIP |
		WPA_DRIVER_CAPA_ENC_CCMP |
		WPA_DRIVER_CAPA_ENC_GCMP |
		WPA_DRIVER_CAPA_ENC_GCMP_256 |
		WPA_DRIVER_CAPA_ENC_CCMP_256 |
		WPA_DRIVER_CAPA_ENC_BIP |
		WPA_DRIVER_CAPA_ENC_BIP_GMAC_128 |
		WPA_DRIVER_CAPA_ENC_BIP_GMAC_256 |
		WPA_DRIVER_CAPA_ENC_BIP_CMAC_256 |
		WPA_DRIVER_CAPA_ENC_GTK_NOT_USED;
	capa->auth = WPA_DRIVER_AUTH_OPEN | WPA_DRIVER_AUTH_SHARED;

	capa->flags = WPA_DRIVER_FLAGS_SME |
		WPA_DRIVER_FLAGS_AP |
		WPA_DRIVER_FLAGS_AP_MLME |
		WPA_DRIVER_FLAGS_SAE |
		WPA_DRIVER_FLAGS_VALID_ERROR_CODES |
		WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS |
		WPA_DRIVER_FLAGS_OFFCHANNEL_TX |
		WPA_DRIVER_FLAGS_FULL_AP_CLIENT_STATE |
		WPA_DRIVER_FLAGS_SUPPORT_FILS |
		WPA_DRIVER_FLAGS_HE_CAPABILITIES |
		WPA_DRIVER_FLAGS_MFP_OPTIONAL |
		WPA_DRIVER_FLAGS_CONTROL_PORT |
		WPA_DRIVER_FLAGS_SAFE_PTK0_REKEYS |
		WPA_DRIVER_FLAGS_BEACON_PROTECTION |
		WPA_DRIVER_FLAGS_EXTENDED_KEY_ID |
		WPA_DRIVER_FLAGS_AP_CSA;
	capa->flags2 = WPA_DRIVER_FLAGS2_CONTROL_PORT_RX |
		WPA_DRIVER_FLAGS2_BEACON_PROTECTION_CLIENT;
	/* No kernel network device exists for this interface */
	capa->flags2 |= WPA_DRIVER_FLAGS2_NO_NETDEV;
#ifdef CONFIG_IEEE80211BE
	if (drv->mlo_capable)
		capa->flags2 |= WPA_DRIVER_FLAGS2_MLO;
#endif /* CONFIG_IEEE80211BE */

	capa->max_scan_ssids = WPAS_MAX_SCAN_SSIDS;
	capa->max_remain_on_chan = 5000;
	capa->max_stations = TEST_MAX_PEERS;
	capa->max_probe_req_ie_len = TEST_MAX_PROBE_IES;
	capa->num_multichan_concurrent = 1;
	capa->max_csa_counters = 2;

	return 0;
}


static const u8 * test_driver_get_mac_addr(void *priv)
{
	struct test_bss *bss = priv;

	return bss->drv->own_addr;
}


static const char * test_driver_get_radio_name(void *priv)
{
	struct test_bss *bss = priv;

	return bss->drv->ifname;
}


static void test_add_channels(struct hostapd_hw_modes *mode,
			      const short *chans, int num, int base_freq,
			      bool ht40_rules, bool is_6ghz)
{
	int i;

	for (i = 0; i < num; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];

		chan->chan = chans[i];
		chan->freq = base_freq + chans[i] * 5;
		chan->flag = 0;
		chan->allowed_bw = HOSTAPD_CHAN_WIDTH_20;
		chan->max_tx_power = 20;
		dl_list_init(&chan->survey_list);
		if (is_6ghz) {
			chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_40P |
				HOSTAPD_CHAN_WIDTH_40M |
				HOSTAPD_CHAN_WIDTH_80 |
				HOSTAPD_CHAN_WIDTH_160 |
				HOSTAPD_CHAN_WIDTH_320;
			chan->flag |= HOSTAPD_CHAN_HT40PLUS |
				HOSTAPD_CHAN_HT40MINUS | HOSTAPD_CHAN_HT40;
		} else if (ht40_rules) {
			/* 5 GHz: 40 MHz pairing by channel number */
			if (chans[i] == 165) {
				continue;
			}
			if ((chans[i] % 8) == 4) {
				chan->flag |= HOSTAPD_CHAN_HT40PLUS |
					HOSTAPD_CHAN_HT40;
				chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_40P;
			} else if ((chans[i] % 8) == 0) {
				chan->flag |= HOSTAPD_CHAN_HT40MINUS |
					HOSTAPD_CHAN_HT40;
				chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_40M;
			}
			chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_80 |
				HOSTAPD_CHAN_WIDTH_160;
		} else {
			/* 2.4 GHz */
			if (chans[i] <= 9) {
				chan->flag |= HOSTAPD_CHAN_HT40PLUS |
					HOSTAPD_CHAN_HT40;
				chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_40P;
			}
			if (chans[i] >= 5) {
				chan->flag |= HOSTAPD_CHAN_HT40MINUS |
					HOSTAPD_CHAN_HT40;
				chan->allowed_bw |= HOSTAPD_CHAN_WIDTH_40M;
			}
		}
	}
}


static void test_free_hw_modes(struct hostapd_hw_modes *modes, u16 num)
{
	u16 i;

	if (!modes)
		return;
	for (i = 0; i < num; i++) {
		os_free(modes[i].channels);
		os_free(modes[i].rates);
	}
	os_free(modes);
}


static struct hostapd_hw_modes *
test_driver_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags,
				u8 *dfs, char *alpha2, size_t alpha2_len)
{
	static const short chans_2g[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
					  12, 13 };
	static const short chans_5g[] = { 36, 40, 44, 48, 52, 56, 60, 64,
					  100, 104, 108, 112, 116, 120, 124,
					  128, 132, 136, 140, 144, 149, 153,
					  157, 161, 165 };
	short chans_6g[59];
	struct hostapd_hw_modes *modes;
	struct hostapd_hw_modes *m;
	size_t i;
	const int num = 4;

	*num_modes = 0;
	*flags = 0;
	*dfs = 0;
	if (alpha2 && alpha2_len)
		alpha2[0] = '\0'; /* no regulatory information */

	for (i = 0; i < ARRAY_SIZE(chans_6g); i++)
		chans_6g[i] = 1 + 4 * i;

	modes = os_calloc(num, sizeof(*modes));
	if (!modes)
		return NULL;

	/* IEEE 802.11g (2.4 GHz) */
	m = &modes[0];
	m->mode = HOSTAPD_MODE_IEEE80211G;
	m->num_channels = ARRAY_SIZE(chans_2g);
	m->channels = os_calloc(m->num_channels, sizeof(*m->channels));
	m->num_rates = ARRAY_SIZE(test_rates_g);
	m->rates = os_calloc(m->num_rates, sizeof(int));
	if (!m->channels || !m->rates)
		goto fail;
	os_memcpy(m->rates, test_rates_g, sizeof(test_rates_g));
	test_add_channels(m, chans_2g, m->num_channels, 2407, false, false);
	m->ht_capab = TEST_HT_CAPAB;
	m->a_mpdu_params = TEST_HT_AMPDU_PARAMS;
	os_memcpy(m->mcs_set, test_ht_mcs_set, sizeof(m->mcs_set));
	m->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_HE_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_EHT_INFO_KNOWN;
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_AP], 2412, false);
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_INFRA], 2412, false);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_AP]);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_INFRA]);

	/* IEEE 802.11b (2.4 GHz) */
	m = &modes[1];
	m->mode = HOSTAPD_MODE_IEEE80211B;
	m->num_channels = ARRAY_SIZE(chans_2g);
	m->channels = os_calloc(m->num_channels, sizeof(*m->channels));
	m->num_rates = 4;
	m->rates = os_calloc(m->num_rates, sizeof(int));
	if (!m->channels || !m->rates)
		goto fail;
	os_memcpy(m->rates, test_rates_g, 4 * sizeof(int));
	test_add_channels(m, chans_2g, m->num_channels, 2407, false, false);
	for (i = 0; i < (size_t) m->num_channels; i++) {
		m->channels[i].flag = 0;
		m->channels[i].allowed_bw = HOSTAPD_CHAN_WIDTH_20;
	}

	/* IEEE 802.11a (5 GHz) */
	m = &modes[2];
	m->mode = HOSTAPD_MODE_IEEE80211A;
	m->num_channels = ARRAY_SIZE(chans_5g);
	m->channels = os_calloc(m->num_channels, sizeof(*m->channels));
	m->num_rates = ARRAY_SIZE(test_rates_a);
	m->rates = os_calloc(m->num_rates, sizeof(int));
	if (!m->channels || !m->rates)
		goto fail;
	os_memcpy(m->rates, test_rates_a, sizeof(test_rates_a));
	test_add_channels(m, chans_5g, m->num_channels, 5000, true, false);
	m->ht_capab = TEST_HT_CAPAB;
	m->a_mpdu_params = TEST_HT_AMPDU_PARAMS;
	os_memcpy(m->mcs_set, test_ht_mcs_set, sizeof(m->mcs_set));
	m->vht_capab = TEST_VHT_CAPAB;
	os_memcpy(m->vht_mcs_set, test_vht_mcs_set, sizeof(m->vht_mcs_set));
	m->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_HE_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_EHT_INFO_KNOWN;
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_AP], 5180, false);
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_INFRA], 5180, false);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_AP]);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_INFRA]);

	/* IEEE 802.11a (6 GHz) */
	m = &modes[3];
	m->mode = HOSTAPD_MODE_IEEE80211A;
	m->is_6ghz = true;
	m->num_channels = ARRAY_SIZE(chans_6g);
	m->channels = os_calloc(m->num_channels, sizeof(*m->channels));
	m->num_rates = ARRAY_SIZE(test_rates_a);
	m->rates = os_calloc(m->num_rates, sizeof(int));
	if (!m->channels || !m->rates)
		goto fail;
	os_memcpy(m->rates, test_rates_a, sizeof(test_rates_a));
	test_add_channels(m, chans_6g, m->num_channels, 5950, false, true);
	m->flags = HOSTAPD_MODE_FLAG_HE_INFO_KNOWN |
		HOSTAPD_MODE_FLAG_EHT_INFO_KNOWN;
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_AP], 5955, true);
	test_fill_he_capab(&m->he_capab[IEEE80211_MODE_INFRA], 5955, true);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_AP]);
	test_fill_eht_capab(&m->eht_capab[IEEE80211_MODE_INFRA]);

	*num_modes = num;
	return modes;

fail:
	test_free_hw_modes(modes, num);
	return NULL;
}


static int test_driver_set_key(void *priv,
			       struct wpa_driver_set_key_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_key *key = NULL;

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): set_key: alg=%d addr=" MACSTR
		   " key_idx=%d set_tx=%d key_len=%zu key_flag=0x%x link_id=%d",
		   drv->ifname, params->alg,
		   MAC2STR(params->addr ? params->addr : broadcast_ether_addr),
		   params->key_idx, params->set_tx, params->key_len,
		   params->key_flag, params->link_id);
	wpa_hexdump_key(MSG_MSGDUMP, "test_driver: key", params->key,
			params->key_len);

	if (params->key_idx < 0 || params->key_idx >= TEST_MAX_GROUP_KEYS)
		return -1;
	if (params->key_len > 64)
		return -1;
	if (params->alg != WPA_ALG_NONE && params->key_len == 0)
		return -1;

	if (params->addr && !is_broadcast_ether_addr(params->addr)) {
		/* Pairwise key */
		if (params->key_idx > 1)
			return -1;
		if (drv->ap) {
			struct test_peer *peer;
			bool found = false;

			dl_list_for_each(peer, &drv->peers, struct test_peer,
					 list) {
				if (!ether_addr_equal(peer->addr,
						      params->addr) &&
				    !(peer->mld &&
				      ether_addr_equal(peer->mld_addr,
						       params->addr)))
					continue;
				found = true;
				if (params->alg == WPA_ALG_NONE) {
					test_clear_keys(&peer->ptk, 1);
					continue;
				}
				if (params->key_flag & KEY_FLAG_NEXT) {
					/* Option 1: ignore next TK config */
					continue;
				}
				peer->ptk.set = true;
				peer->ptk.alg = params->alg;
				peer->ptk.key_idx = params->key_idx;
				peer->ptk.key_len = params->key_len;
				peer->ptk.key_flag = params->key_flag;
			}
			if (!found && params->alg != WPA_ALG_NONE) {
				wpa_printf(MSG_DEBUG,
					   "test_driver(%s): set_key for unknown STA",
					   drv->ifname);
				return -1;
			}
			return 0;
		}
		if (params->alg == WPA_ALG_NONE) {
			test_clear_keys(&drv->ptk, 1);
			return 0;
		}
		if (params->key_flag & KEY_FLAG_NEXT)
			return 0;
		key = &drv->ptk;
	} else {
		/* Group key (GTK, IGTK, BIGTK) */
		struct test_bss *target = bss;

		if (drv->ap && params->link_id >= 0) {
			target = test_bss_by_link(drv, params->link_id);
			if (!target)
				target = bss;
		}
		key = drv->ap ? &target->gtk[params->key_idx] :
			&drv->gtk[params->key_idx];
		if (params->alg == WPA_ALG_NONE) {
			test_clear_keys(key, 1);
			return 0;
		}
	}

	key->set = true;
	key->alg = params->alg;
	key->key_idx = params->key_idx;
	key->key_len = params->key_len;
	key->key_flag = params->key_flag;
	return 0;
}


static int test_driver_get_seqnum(const char *ifname, void *priv,
				  const u8 *addr, int idx, int link_id, u8 *seq)
{
	/* No packet numbers are consumed since nothing is encrypted */
	os_memset(seq, 0, 6);
	return 0;
}


static int test_driver_status(void *priv, char *buf, size_t buflen)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_stats *s = &drv->stats;
	struct test_peer *peer;
	int res;
	char *pos = buf, *end = buf + buflen;

	res = os_snprintf(pos, end - pos,
			  "test_driver_transport=%s\n"
			  "test_driver_socket=%s\n"
			  "test_driver_mode=%s\n"
			  "test_driver_addr=" MACSTR "\n"
			  "test_driver_freq=%d\n"
			  "test_driver_peers=%u\n"
			  "test_driver_bsses=%u\n"
			  "test_driver_mlo=%d\n"
			  "test_driver_sta_state=%d\n"
			  "test_driver_ptk_set=%d\n"
			  "test_driver_rx_msgs=%u\n"
			  "test_driver_rx_invalid_hdr=%u\n"
			  "test_driver_rx_invalid_frame=%u\n"
			  "test_driver_rx_unknown_type=%u\n"
			  "test_driver_rx_dropped_no_bss=%u\n"
			  "test_driver_rx_dropped_undecryptable=%u\n"
			  "test_driver_rx_dropped_unprotected=%u\n"
			  "test_driver_rx_dropped_peer_table_full=%u\n"
			  "test_driver_rx_mgmt=%u\n"
			  "test_driver_rx_eapol=%u\n"
			  "test_driver_rx_null=%u\n"
			  "test_driver_tx_msgs=%u\n"
			  "test_driver_tx_failed=%u\n"
			  "test_driver_tx_mgmt=%u\n"
			  "test_driver_tx_eapol=%u\n"
			  "test_driver_events=%u\n"
			  "test_driver_peers_evicted=%u\n"
			  "test_driver_auth_timeouts=%u\n"
			  "test_driver_assoc_timeouts=%u\n"
			  "test_driver_peer_lost=%u\n",
			  drv->transport == TEST_TRANSPORT_UNIX ? "unix" :
			  drv->transport == TEST_TRANSPORT_UDP ? "udp" : "none",
			  drv->own_socket_path ? drv->own_socket_path : "",
			  drv->ap ? "ap" : "sta", MAC2STR(drv->own_addr),
			  drv->freq, drv->num_peers,
			  dl_list_len(&drv->bss),
			  drv->ap ? test_drv_is_mld(drv) : drv->mlo,
			  drv->sta_state, drv->ap ? 0 : drv->ptk.set,
			  s->rx_msgs, s->rx_invalid_hdr, s->rx_invalid_frame,
			  s->rx_unknown_type, s->rx_dropped_no_bss,
			  s->rx_dropped_undecryptable,
			  s->rx_dropped_unprotected,
			  s->rx_dropped_peer_table_full, s->rx_mgmt,
			  s->rx_eapol, s->rx_null, s->tx_msgs, s->tx_failed,
			  s->tx_mgmt, s->tx_eapol, s->events, s->peers_evicted,
			  s->auth_timeouts, s->assoc_timeouts, s->peer_lost);
	if (os_snprintf_error(end - pos, res))
		return pos - buf;
	pos += res;

	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		res = os_snprintf(pos, end - pos,
				  "test_driver_peer=" MACSTR
				  " mld=%d mld_addr=" MACSTR
				  " link_id=%d added=%d flags=0x%x ptk=%d rx=%u tx=%u\n",
				  MAC2STR(peer->addr), peer->mld,
				  MAC2STR(peer->mld_addr), peer->link_id,
				  peer->added, peer->flags, peer->ptk.set,
				  peer->rx_frames, peer->tx_frames);
		if (os_snprintf_error(end - pos, res))
			return pos - buf;
		pos += res;
	}

	return pos - buf;
}


static int test_driver_set_freq(void *priv, struct hostapd_freq_params *freq)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *target = bss;

	if (freq->link_id >= 0) {
		target = test_bss_by_link(drv, freq->link_id);
		if (!target)
			target = bss;
	}
	wpa_printf(MSG_DEBUG, "test_driver(%s): set_freq %d MHz (link_id=%d)",
		   drv->ifname, freq->freq, freq->link_id);
	target->freq = freq->freq;
	if (!drv->ap || target == test_bss_first(drv))
		drv->freq = freq->freq;
	return 0;
}


static int test_driver_send_action(void *priv, unsigned int freq,
				   unsigned int wait, const u8 *dst,
				   const u8 *src, const u8 *bssid,
				   const u8 *data, size_t data_len, int no_cck,
				   int link_id)
{
	u8 *buf;
	struct ieee80211_hdr *hdr;
	int ret;

	if (data_len > TEST_DRV_MAX_PAYLOAD - IEEE80211_HDRLEN)
		return -1;
	buf = os_zalloc(IEEE80211_HDRLEN + data_len);
	if (!buf)
		return -1;
	hdr = (struct ieee80211_hdr *) buf;
	hdr->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_ACTION);
	os_memcpy(hdr->addr1, dst, ETH_ALEN);
	os_memcpy(hdr->addr2, src, ETH_ALEN);
	os_memcpy(hdr->addr3, bssid, ETH_ALEN);
	os_memcpy(buf + IEEE80211_HDRLEN, data, data_len);
	ret = test_driver_send_mlme(priv, buf, IEEE80211_HDRLEN + data_len, 0,
				    freq, NULL, 0, 0, wait, link_id);
	os_free(buf);
	return ret;
}


static void test_driver_roc_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	union wpa_event_data data;

	os_memset(&data, 0, sizeof(data));
	data.remain_on_channel.freq = drv->remain_on_channel_freq;
	data.remain_on_channel.duration = drv->remain_on_channel_duration;
	drv->remain_on_channel_freq = 0;
	wpa_supplicant_event(drv->ctx, EVENT_CANCEL_REMAIN_ON_CHANNEL, &data);
}


static int test_driver_remain_on_channel(void *priv, unsigned int freq,
					 unsigned int duration,
					 const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	union wpa_event_data data;

	/* Off-channel operation is not emulated; the request is accepted and
	 * completed on a timer so that the higher layer state machines can be
	 * exercised. */
	if (duration > 5000)
		return -1;
	if (drv->remain_on_channel_freq &&
	    drv->remain_on_channel_freq != freq)
		return -1;
	drv->remain_on_channel_freq = freq;
	drv->remain_on_channel_duration = duration;
	eloop_cancel_timeout(test_driver_roc_timeout, drv, NULL);
	eloop_register_timeout(duration / 1000, (duration % 1000) * 1000,
			       test_driver_roc_timeout, drv, NULL);
	os_memset(&data, 0, sizeof(data));
	data.remain_on_channel.freq = freq;
	data.remain_on_channel.duration = duration;
	wpa_supplicant_event(drv->ctx, EVENT_REMAIN_ON_CHANNEL, &data);
	return 0;
}


static int test_driver_cancel_remain_on_channel(void *priv)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (!drv->remain_on_channel_freq)
		return -1;
	drv->remain_on_channel_freq = 0;
	eloop_cancel_timeout(test_driver_roc_timeout, drv, NULL);
	return 0;
}


static int test_driver_probe_req_report(void *priv, int report)
{
	struct test_bss *bss = priv;

	bss->drv->probe_req_report = report;
	return 0;
}


/* ---------------------------------------------------------------------- */
/* hostapd (AP) operations                                                 */

static int test_driver_send_mlme(void *priv, const u8 *data, size_t data_len,
				 int noack, unsigned int freq,
				 const u16 *csa_offs, size_t csa_offs_len,
				 int no_encrypt, unsigned int wait, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	u8 *frame;
	struct ieee80211_hdr *hdr;
	u16 fc;
	u8 flags = noack ? TEST_DRV_FLAG_NOACK : 0;
	int ret = -1, ack = 0;
	int wire_link = -1;
	void *ctx = bss->ctx;

	if (data_len < IEEE80211_HDRLEN || data_len > TEST_DRV_MAX_PAYLOAD) {
		wpa_printf(MSG_DEBUG, "test_driver(%s): send_mlme: invalid length %zu",
			   drv->ifname, data_len);
		return -1;
	}
	if (drv->sock < 0)
		return -1;

	frame = os_memdup(data, data_len);
	if (!frame)
		return -1;
	hdr = (struct ieee80211_hdr *) frame;
	fc = le_to_host16(hdr->frame_control);
	wpa_hexdump(MSG_MSGDUMP, "test_driver: send_mlme", data, data_len);

	if (drv->ap) {
		struct test_bss *tx_bss = NULL;
		struct test_peer *peer = NULL;

		/* Determine the transmitting BSS/link */
		if (link_id >= 0)
			tx_bss = test_bss_by_link(drv, link_id);
		if (!tx_bss)
			tx_bss = test_bss_by_addr(drv, hdr->addr2);
		if (!tx_bss)
			tx_bss = bss;
		if (tx_bss->mld_link)
			wire_link = tx_bss->link_id;
		if (tx_bss->ctx)
			ctx = tx_bss->ctx;

		if (is_multicast_ether_addr(hdr->addr1)) {
			if (tx_bss->mld_link &&
			    ether_addr_equal(hdr->addr2, drv->own_addr))
				os_memcpy(hdr->addr2, tx_bss->addr, ETH_ALEN);
			ret = test_driver_send_broadcast(drv, TEST_DRV_MSG_MGMT,
							 flags, wire_link,
							 frame, data_len) >= 0 ?
				0 : -1;
			ack = 1;
		} else {
			peer = test_peer_find(drv, hdr->addr1, wire_link);
			if (!peer) {
				wpa_printf(MSG_DEBUG,
					   "test_driver(%s): send_mlme: unknown destination "
					   MACSTR, drv->ifname,
					   MAC2STR(hdr->addr1));
				ret = -1;
			} else {
				/* MLD -> link address translation */
				if (peer->mld) {
					os_memcpy(hdr->addr1, peer->addr,
						  ETH_ALEN);
					if (peer->bss && peer->bss->mld_link)
						tx_bss = peer->bss;
					if (tx_bss->mld_link)
						wire_link = tx_bss->link_id;
					if (ether_addr_equal(hdr->addr2,
							     drv->own_addr))
						os_memcpy(hdr->addr2,
							  tx_bss->addr,
							  ETH_ALEN);
					if (ether_addr_equal(hdr->addr3,
							     drv->own_addr))
						os_memcpy(hdr->addr3,
							  tx_bss->addr,
							  ETH_ALEN);
				}
				if (!no_encrypt && peer->ptk.set &&
				    test_is_robust_mgmt(frame, data_len)) {
					fc |= WLAN_FC_PROTECTED;
					hdr->frame_control = host_to_le16(fc);
					flags |= TEST_DRV_FLAG_PROTECTED;
				}
				ret = test_driver_send_to_peer(
					drv, peer, TEST_DRV_MSG_MGMT, flags,
					wire_link, frame, data_len);
				ack = ret == 0;
			}
		}
	} else {
		wire_link = test_sta_tx_translate(drv, hdr, link_id);
		if (is_multicast_ether_addr(hdr->addr1)) {
			ret = test_driver_send_broadcast(drv, TEST_DRV_MSG_MGMT,
							 flags, wire_link,
							 frame, data_len) >= 0 ?
				0 : -1;
			ack = 1;
		} else {
			struct test_peer *peer;

			peer = test_sta_ap_peer(drv, hdr->addr1, wire_link);
			if (!peer) {
				wpa_printf(MSG_DEBUG,
					   "test_driver(%s): send_mlme: unknown destination "
					   MACSTR, drv->ifname,
					   MAC2STR(hdr->addr1));
				ret = -1;
			} else {
				if (!no_encrypt && drv->ptk.set &&
				    test_is_robust_mgmt(frame, data_len)) {
					fc |= WLAN_FC_PROTECTED;
					hdr->frame_control = host_to_le16(fc);
					flags |= TEST_DRV_FLAG_PROTECTED;
				}
				ret = test_driver_send_to_peer(
					drv, peer, TEST_DRV_MSG_MGMT, flags,
					wire_link, frame, data_len);
				ack = ret == 0;
			}
		}
	}

	drv->stats.tx_mgmt++;
	/* Report TX status asynchronously with the frame as given by the
	 * caller (pre-translation addresses). */
	test_queue_tx_status(drv, ctx, data, data_len, ack && !noack,
			     wire_link);
	os_free(frame);
	return ret;
}


static int test_driver_hapd_send_eapol(void *priv, const u8 *addr,
				       const u8 *data, size_t data_len,
				       int encrypt, const u8 *own_addr,
				       u32 flags, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	u8 *msg;
	struct l2_ethhdr *eth;
	int ret;
	struct test_bss *tx_bss;

	if (data_len > TEST_DRV_MAX_PAYLOAD - sizeof(*eth))
		return -1;

	tx_bss = link_id >= 0 ? test_bss_by_link(drv, link_id) : NULL;
	if (!tx_bss)
		tx_bss = test_bss_by_addr(drv, own_addr);
	if (!tx_bss)
		tx_bss = bss;

	peer = test_peer_find(drv, addr, tx_bss->mld_link ? tx_bss->link_id :
			      -1);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): hapd_send_eapol: unknown STA "
			   MACSTR, drv->ifname, MAC2STR(addr));
		return -1;
	}
	if (peer->bss && peer->bss->mld_link)
		tx_bss = peer->bss;

	msg = os_malloc(sizeof(*eth) + data_len);
	if (!msg)
		return -1;
	eth = (struct l2_ethhdr *) msg;
	os_memcpy(eth->h_dest, peer->addr, ETH_ALEN);
	if (ether_addr_equal(own_addr, drv->own_addr) && tx_bss->mld_link)
		os_memcpy(eth->h_source, tx_bss->addr, ETH_ALEN);
	else
		os_memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = host_to_be16(ETH_P_EAPOL);
	os_memcpy(msg + sizeof(*eth), data, data_len);

	ret = test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_EAPOL,
				       encrypt ? TEST_DRV_FLAG_PROTECTED : 0,
				       tx_bss->mld_link ? tx_bss->link_id : -1,
				       msg, sizeof(*eth) + data_len);
	os_free(msg);
	drv->stats.tx_eapol++;
	return ret;
}


static int test_driver_sta_deauth_disassoc(void *priv, const u8 *own_addr,
					   const u8 *addr, u16 reason,
					   int link_id, u16 stype)
{
	struct ieee80211_mgmt mgmt;

	os_memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, stype);
	os_memcpy(mgmt.da, addr, ETH_ALEN);
	os_memcpy(mgmt.sa, own_addr, ETH_ALEN);
	os_memcpy(mgmt.bssid, own_addr, ETH_ALEN);
	mgmt.u.deauth.reason_code = host_to_le16(reason);
	return test_driver_send_mlme(priv, (u8 *) &mgmt,
				     IEEE80211_HDRLEN + sizeof(mgmt.u.deauth),
				     0, 0, NULL, 0, 0, 0, link_id);
}


static int test_driver_sta_deauth(void *priv, const u8 *own_addr,
				  const u8 *addr, u16 reason, int link_id)
{
	return test_driver_sta_deauth_disassoc(priv, own_addr, addr, reason,
					       link_id, WLAN_FC_STYPE_DEAUTH);
}


static int test_driver_sta_disassoc(void *priv, const u8 *own_addr,
				    const u8 *addr, u16 reason, int link_id)
{
	return test_driver_sta_deauth_disassoc(priv, own_addr, addr, reason,
					       link_id,
					       WLAN_FC_STYPE_DISASSOC);
}


static int test_driver_sta_add(void *priv,
			       struct hostapd_sta_add_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	const u8 *link_addr = params->addr;
	struct test_bss *link_bss = bss;
	bool mld_sta;

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): sta_add: addr=" MACSTR
		   " aid=%u set=%d flags=0x%x mld_link_sta=%d mld_link_id=%d",
		   drv->ifname, MAC2STR(params->addr), params->aid, params->set,
		   params->flags, params->mld_link_sta, params->mld_link_id);

	/* An AP MLD passes the link address of the (MLD) station for every
	 * link, including the association link (mld_link_sta == false). A
	 * legacy STA on an MLD link has a zero link address. */
	mld_sta = params->mld_link_addr &&
		!is_zero_ether_addr(params->mld_link_addr) &&
		params->mld_link_id >= 0 &&
		params->mld_link_id < MAX_NUM_MLD_LINKS;
	if (params->mld_link_sta && !mld_sta)
		return -1;
	if (mld_sta) {
		link_addr = params->mld_link_addr;
		link_bss = test_bss_by_link(drv, params->mld_link_id);
		if (!link_bss)
			return -1;
	} else if (params->mld_link_id >= 0) {
		link_bss = test_bss_by_link(drv, params->mld_link_id);
		if (!link_bss)
			link_bss = bss;
	}

	peer = test_peer_get(drv, link_addr);
	if (!peer) {
		peer = test_peer_add(drv, link_addr);
		if (!peer)
			return -1;
		/* Copy the transport address from another link entry of the
		 * same MLD STA if available. */
		if (mld_sta) {
			struct test_peer *other;

			other = test_peer_get_mld(drv, params->addr, -1);
			if (!other || !other->sa_valid)
				other = test_peer_get(drv, params->addr);
			if (other && other->sa_valid)
				test_peer_set_sa(peer, &other->sa,
						 other->sa_len);
		}
	}

	if (params->set && !peer->added) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): sta_add(set) for unknown STA - add",
			   drv->ifname);
	}

	peer->bss = link_bss;
	peer->added = true;
	peer->aid = params->aid;
	if (mld_sta) {
		peer->mld = true;
		peer->link_id = params->mld_link_id;
		os_memcpy(peer->mld_addr, params->addr, ETH_ALEN);
	} else {
		peer->mld = false;
		peer->link_id = link_bss->mld_link ? link_bss->link_id : -1;
	}
	if (params->set)
		peer->flags = (peer->flags & ~params->flags_mask) |
			params->flags;
	else
		peer->flags = params->flags;
	return 0;
}


static int test_driver_sta_remove(void *priv, const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer, *tmp;
	int found = 0;

	dl_list_for_each_safe(peer, tmp, &drv->peers, struct test_peer, list) {
		if (!ether_addr_equal(peer->addr, addr) &&
		    !(peer->mld && ether_addr_equal(peer->mld_addr, addr)))
			continue;
		found++;
		/* Keep the transport address so that a following frame (e.g.,
		 * Deauthentication) can still be delivered; drop STA state. */
		peer->added = false;
		peer->flags = 0;
		peer->aid = 0;
		test_clear_keys(&peer->ptk, 1);
		if (peer->mld && peer->link_id != -1 &&
		    !ether_addr_equal(peer->addr, addr)) {
			/* Secondary link entry of a removed MLD STA */
			test_peer_free(drv, peer);
		}
	}
	wpa_printf(MSG_DEBUG, "test_driver(%s): sta_remove " MACSTR " (%d)",
		   drv->ifname, MAC2STR(addr), found);
	return found ? 0 : -1;
}


#ifdef CONFIG_IEEE80211BE
static int test_driver_link_sta_remove(void *priv, u8 link_id, const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer, *tmp;

	dl_list_for_each_safe(peer, tmp, &drv->peers, struct test_peer, list) {
		if (peer->mld && peer->link_id == link_id &&
		    ether_addr_equal(peer->mld_addr, addr)) {
			test_peer_free(drv, peer);
			return 0;
		}
	}
	return -1;
}
#endif /* CONFIG_IEEE80211BE */


static int test_driver_sta_set_flags(void *priv, const u8 *addr,
				     unsigned int total_flags,
				     unsigned int flags_or,
				     unsigned int flags_and)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	int found = 0;

	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		if (!ether_addr_equal(peer->addr, addr) &&
		    !(peer->mld && ether_addr_equal(peer->mld_addr, addr)))
			continue;
		peer->flags = (peer->flags | flags_or) & flags_and;
		found++;
	}
	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): sta_set_flags " MACSTR
		   " total=0x%x or=0x%x and=0x%x (%d entries)",
		   drv->ifname, MAC2STR(addr), total_flags, flags_or, flags_and,
		   found);
	return found ? 0 : -1;
}


static int test_driver_get_inact_sec(void *priv, const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	struct os_reltime now, diff;

	peer = test_peer_find(drv, addr, -1);
	if (!peer)
		return -1;
	os_get_reltime(&now);
	os_reltime_sub(&now, &peer->last_rx, &diff);
	return (int) diff.sec;
}


static int test_driver_read_sta_data(void *priv,
				     struct hostap_sta_driver_data *data,
				     const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	struct os_reltime now, diff;

	peer = test_peer_find(drv, addr, -1);
	if (!peer)
		return -1;
	os_memset(data, 0, sizeof(*data));
	os_get_reltime(&now);
	os_reltime_sub(&now, &peer->last_rx, &diff);
	data->inactive_msec = diff.sec * 1000 + diff.usec / 1000;
	data->rx_packets = peer->rx_frames;
	data->tx_packets = peer->tx_frames;
	data->signal = -30;
	data->flags = 0;
	return 0;
}


static int test_driver_flush(void *priv, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;

	dl_list_for_each(peer, &drv->peers, struct test_peer, list) {
		if (link_id >= 0 && peer->link_id != link_id)
			continue;
		peer->added = false;
		peer->flags = 0;
		test_clear_keys(&peer->ptk, 1);
	}
	return 0;
}


static int test_driver_set_ap(void *priv, struct wpa_driver_ap_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *target = bss;

#ifdef CONFIG_IEEE80211BE
	if (params->mld_ap) {
		target = test_bss_by_link(drv, params->mld_link_id);
		if (!target) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): set_ap: unknown link %u",
				   drv->ifname, params->mld_link_id);
			return -1;
		}
	}
#endif /* CONFIG_IEEE80211BE */

	if (params->head_len > TEST_MAX_TEMPLATE_LEN ||
	    params->tail_len > TEST_MAX_TEMPLATE_LEN ||
	    params->ssid_len > SSID_MAX_LEN)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): set_ap: bss=%s freq=%d beacon_int=%d dtim=%d privacy=%d head_len=%zu tail_len=%zu",
		   drv->ifname, target->ifname,
		   params->freq ? params->freq->freq : 0, params->beacon_int,
		   params->dtim_period, params->privacy, params->head_len,
		   params->tail_len);

	wpabuf_free(target->head);
	wpabuf_free(target->tail);
	target->head = params->head ?
		wpabuf_alloc_copy(params->head, params->head_len) : NULL;
	target->tail = params->tail ?
		wpabuf_alloc_copy(params->tail, params->tail_len) : NULL;
	if (params->ssid) {
		os_memcpy(target->ssid, params->ssid, params->ssid_len);
		target->ssid_len = params->ssid_len;
	}
	target->privacy = params->privacy;
	target->beacon_int = params->beacon_int;
	if (params->freq) {
		target->freq = params->freq->freq;
		if (target == test_bss_first(drv))
			drv->freq = params->freq->freq;
	}
	target->started = true;
	return 0;
}


static int test_driver_stop_ap(void *priv, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *target = link_id >= 0 ?
		test_bss_by_link(drv, link_id) : bss;

	if (!target)
		return -1;
	target->started = false;
	return 0;
}


static int test_driver_hapd_set_ssid(void *priv, const u8 *buf, int len)
{
	struct test_bss *bss = priv;

	if (len < 0 || (size_t) len > SSID_MAX_LEN)
		return -1;
	os_memcpy(bss->ssid, buf, len);
	bss->ssid_len = len;
	return 0;
}


static int test_driver_hapd_get_ssid(void *priv, u8 *buf, int len)
{
	struct test_bss *bss = priv;

	if (len < 0 || (size_t) len < bss->ssid_len)
		return -1;
	os_memcpy(buf, bss->ssid, bss->ssid_len);
	return bss->ssid_len;
}


static int test_driver_set_privacy(void *priv, int enabled)
{
	struct test_bss *bss = priv;

	bss->privacy = enabled;
	return 0;
}


static int test_driver_set_sta_vlan(void *priv, const u8 *addr,
				    const char *ifname, int vlan_id,
				    int link_id)
{
	wpa_printf(MSG_DEBUG, "test_driver: set_sta_vlan " MACSTR
		   " ifname=%s vlan_id=%d link_id=%d (no data path - accepted)",
		   MAC2STR(addr), ifname, vlan_id, link_id);
	return 0;
}


static int test_driver_if_add(void *priv, enum wpa_driver_if_type type,
			      const char *ifname, const u8 *addr,
			      void *bss_ctx, void **drv_priv,
			      char *force_ifname, u8 *if_addr,
			      const char *bridge, int use_existing,
			      int setup_ap)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *nbss;
	u8 new_addr[ETH_ALEN];

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): if_add type=%d ifname=%s bss_ctx=%p",
		   drv->ifname, type, ifname, bss_ctx);

	if (!ifname || os_strlen(ifname) >= IFNAMSIZ)
		return -1;

	if (type == WPA_IF_AP_VLAN) {
		/* No data path exists; VLAN interfaces are accepted as
		 * no-ops so that hostapd VLAN configuration paths run. */
		if (if_addr)
			os_memcpy(if_addr, addr ? addr : drv->own_addr,
				  ETH_ALEN);
		return 0;
	}

	if (type != WPA_IF_AP_BSS) {
		wpa_printf(MSG_DEBUG,
			   "test_driver: Unsupported interface type %d", type);
		return -1;
	}

	if (test_bss_by_ifname(drv, ifname)) {
		if (!use_existing)
			return -1;
		nbss = test_bss_by_ifname(drv, ifname);
		nbss->ctx = bss_ctx;
		if (addr)
			os_memcpy(nbss->addr, addr, ETH_ALEN);
	} else {
		if (addr) {
			os_memcpy(new_addr, addr, ETH_ALEN);
		} else {
			char label[IFNAMSIZ + 32];

			os_snprintf(label, sizeof(label), "%s/%s", drv->ifname,
				    ifname);
			test_derive_addr(label,
					 "hostapd test bss addr generation",
					 new_addr);
		}
		if (test_bss_by_addr(drv, new_addr)) {
			wpa_printf(MSG_ERROR,
				   "test_driver: Duplicate BSS address " MACSTR,
				   MAC2STR(new_addr));
			return -1;
		}
		nbss = test_bss_add(drv, ifname, new_addr, bss_ctx);
		if (!nbss)
			return -1;
		nbss->freq = drv->freq;
	}

	if (if_addr)
		os_memcpy(if_addr, nbss->addr, ETH_ALEN);
	if (drv_priv)
		*drv_priv = nbss;
	return 0;
}


static void test_driver_remove_bss_peers(struct wpa_driver_test_data *drv,
					 struct test_bss *bss)
{
	struct test_peer *peer, *tmp;

	dl_list_for_each_safe(peer, tmp, &drv->peers, struct test_peer, list) {
		if (peer->bss == bss)
			test_peer_free(drv, peer);
	}
}


static int test_driver_if_remove(void *priv, enum wpa_driver_if_type type,
				 const char *ifname)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *target;

	wpa_printf(MSG_DEBUG, "test_driver(%s): if_remove type=%d ifname=%s",
		   drv->ifname, type, ifname);
	if (type == WPA_IF_AP_VLAN)
		return 0;
	if (type != WPA_IF_AP_BSS)
		return -1;
	target = test_bss_by_ifname(drv, ifname);
	if (!target)
		return -1;
	if (target == test_bss_first(drv)) {
		/* The primary BSS is owned by hapd_deinit() */
		return -1;
	}
	test_driver_remove_bss_peers(drv, target);
	dl_list_del(&target->list);
	test_bss_free(target);
	return 0;
}


#ifdef CONFIG_IEEE80211BE

static int test_driver_get_mld_capab(void *priv, enum wpa_driver_if_type type,
				     u16 *eml_capa, u16 *mld_capa_and_ops)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (!drv->mlo_capable)
		return -1;
	/* No EML (EMLSR/EMLMR) emulation; all links may be simultaneously
	 * active as far as the protocol state is concerned. */
	*eml_capa = 0;
	*mld_capa_and_ops = (MAX_NUM_MLD_LINKS - 1) &
		EHT_ML_MLD_CAPA_MAX_NUM_SIM_LINKS_MASK;
	return 0;
}


static int test_driver_link_add(void *priv, u8 link_id, const u8 *addr,
				void *bss_ctx)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *link;
	char ifname[IFNAMSIZ + 1];

	if (link_id >= MAX_NUM_MLD_LINKS || !addr)
		return -1;
	if (!drv->mlo_capable)
		return -1;

	wpa_printf(MSG_DEBUG, "test_driver(%s): link_add link_id=%u addr="
		   MACSTR " bss_ctx=%p", drv->ifname, link_id, MAC2STR(addr),
		   bss_ctx);

	if (test_bss_by_link(drv, link_id)) {
		wpa_printf(MSG_DEBUG, "test_driver: Link %u already exists",
			   link_id);
		return -1;
	}

	/* The first link reuses the BSS context created in hapd_init() (its
	 * ctx is the same hostapd_data); further links get their own. */
	link = test_bss_by_ctx(drv, bss_ctx);
	if (!link) {
		os_snprintf(ifname, sizeof(ifname), "%.*s-l%u",
			    (int) (IFNAMSIZ - 4), drv->ifname, link_id);
		link = test_bss_add(drv, ifname, addr, bss_ctx);
		if (!link)
			return -1;
		link->freq = drv->freq;
	}
	os_memcpy(link->addr, addr, ETH_ALEN);
	link->link_id = link_id;
	link->mld_link = true;
	return 0;
}


static int test_driver_link_remove(void *priv, enum wpa_driver_if_type type,
				   const char *ifname, u8 link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *link;

	wpa_printf(MSG_DEBUG, "test_driver(%s): link_remove ifname=%s link_id=%u",
		   drv->ifname, ifname, link_id);
	link = test_bss_by_link(drv, link_id);
	if (!link)
		return -1;
	test_driver_remove_bss_peers(drv, link);
	if (link == test_bss_first(drv)) {
		/* Primary context stays allocated until hapd_deinit() */
		link->mld_link = false;
		link->link_id = -1;
		link->started = false;
		link->ctx = NULL;
		return 0;
	}
	dl_list_del(&link->list);
	test_bss_free(link);
	return 0;
}


static bool test_driver_is_drv_shared(void *priv, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *b;
	int others = 0;

	dl_list_for_each(b, &drv->bss, struct test_bss, list) {
		if (b->mld_link && b->link_id != link_id)
			others++;
	}
	return others > 0;
}

#endif /* CONFIG_IEEE80211BE */


static void test_driver_poll_client(void *priv, const u8 *own_addr,
				    const u8 *addr, int qos)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	struct test_pending_event *ev;

	peer = test_peer_find(drv, addr, -1);
	if (!peer)
		return;
	/* A UNIX datagram send fails synchronously if the peer socket has
	 * disappeared; use that as a deterministic liveness probe. */
	if (test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_NULL, 0,
				     peer->link_id, NULL, 0) < 0)
		return;
	ev = test_pending_add(drv, TEST_EV_CLIENT_POLL_OK,
			      peer->bss ? peer->bss->ctx : bss->ctx, NULL, 0);
	if (ev)
		os_memcpy(ev->addr, addr, ETH_ALEN);
}


static int test_driver_switch_channel(void *priv, struct csa_settings *settings)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_bss *target = bss;
	struct test_pending_event *ev;

	if (!settings)
		return -1;
#ifdef CONFIG_IEEE80211BE
	if (settings->link_id >= 0) {
		target = test_bss_by_link(drv, settings->link_id);
		if (!target)
			return -1;
	}
#endif /* CONFIG_IEEE80211BE */
	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): switch_channel to %d MHz (no beacon countdown emulated)",
		   drv->ifname, settings->freq_params.freq);
	target->freq = settings->freq_params.freq;
	if (target == test_bss_first(drv))
		drv->freq = settings->freq_params.freq;
	ev = test_pending_add(drv, TEST_EV_CH_SWITCH, target->ctx, NULL, 0);
	if (!ev)
		return -1;
	ev->freq = settings->freq_params.freq;
	ev->ack = settings->freq_params.ht_enabled;
	ev->link_id = target->mld_link ? target->link_id : -1;
	return 0;
}


static int test_driver_ap_setup_socket(struct wpa_driver_test_data *drv,
				       const char *params)
{
	char *val;

	val = test_driver_param_value(params, "test_udp=");
	if (val) {
		drv->udp_port = atoi(val);
		os_free(val);
		if (drv->udp_port <= 0 || drv->udp_port > 65535)
			return -1;
		return test_driver_bind_udp(drv, drv->udp_port);
	}

	val = test_driver_param_value(params, "test_dir=");
	if (val) {
		char path[300];
		int r;

		if (os_strlen(val) == 0) {
			os_free(val);
			return -1;
		}
		drv->test_dir = val;
		r = os_snprintf(path, sizeof(path), "%s/AP-%s", drv->test_dir,
				drv->ifname);
		if (os_snprintf_error(sizeof(path), r))
			return -1;
		return test_driver_bind_unix(drv, path);
	}

	val = test_driver_param_value(params, "test_socket=");
	if (val) {
		int ret = os_strlen(val) ? test_driver_bind_unix(drv, val) : -1;

		os_free(val);
		return ret;
	}

	wpa_printf(MSG_ERROR,
		   "test_driver: driver_params must include test_socket=<path>, test_dir=<dir>, or test_udp=<port>");
	return -1;
}


static void * test_driver_init(struct hostapd_data *hapd,
			       struct wpa_init_params *params)
{
	struct wpa_driver_test_data *drv;
	struct test_bss *bss;

	drv = test_alloc_data(hapd, params->ifname, true);
	if (!drv)
		return NULL;
	drv->global = params->global_priv;
	if (drv->global)
		drv->global->num_ifaces++;

	if (params->bssid && !is_zero_ether_addr(params->bssid))
		os_memcpy(drv->own_addr, params->bssid, ETH_ALEN);
	os_memcpy(params->own_addr, drv->own_addr, ETH_ALEN);

	bss = test_bss_add(drv, params->ifname, drv->own_addr, hapd);
	if (!bss) {
		test_driver_deinit_common(drv);
		return NULL;
	}
	bss->freq = drv->freq;

	if (test_driver_parse_common_params(drv, params->driver_params) < 0 ||
	    test_driver_ap_setup_socket(drv, params->driver_params) < 0) {
		test_driver_deinit_common(drv);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "test_driver(%s): AP initialized with address "
		   MACSTR, drv->ifname, MAC2STR(drv->own_addr));
	return bss;
}


/* ---------------------------------------------------------------------- */
/* wpa_supplicant (STA) operations                                         */

static void test_driver_scan_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	union wpa_event_data event;

	drv->scanning = false;
	os_memset(&event, 0, sizeof(event));
	wpa_supplicant_event(timeout_ctx ? timeout_ctx : drv->ctx,
			     EVENT_SCAN_RESULTS, &event);
}


static int test_driver_build_probe_req(struct wpa_driver_test_data *drv,
				       struct wpabuf *buf, const u8 *bssid,
				       const u8 *ssid, size_t ssid_len,
				       const u8 *extra_ies,
				       size_t extra_ies_len)
{
	struct ieee80211_hdr *hdr;

	if (ssid_len > SSID_MAX_LEN)
		return -1;
	hdr = wpabuf_put(buf, IEEE80211_HDRLEN);
	hdr->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_PROBE_REQ);
	os_memcpy(hdr->addr1, bssid ? bssid : broadcast_ether_addr, ETH_ALEN);
	os_memcpy(hdr->addr2, drv->own_addr, ETH_ALEN);
	os_memcpy(hdr->addr3, bssid ? bssid : broadcast_ether_addr, ETH_ALEN);

	wpabuf_put_u8(buf, WLAN_EID_SSID);
	wpabuf_put_u8(buf, ssid_len);
	wpabuf_put_data(buf, ssid, ssid_len);

	wpabuf_put_u8(buf, WLAN_EID_SUPP_RATES);
	wpabuf_put_u8(buf, sizeof(test_supp_rates_g));
	wpabuf_put_data(buf, test_supp_rates_g, sizeof(test_supp_rates_g));
	wpabuf_put_u8(buf, WLAN_EID_EXT_SUPP_RATES);
	wpabuf_put_u8(buf, sizeof(test_ext_rates_g));
	wpabuf_put_data(buf, test_ext_rates_g, sizeof(test_ext_rates_g));

	if (extra_ies && extra_ies_len) {
		if (extra_ies_len > TEST_MAX_PROBE_IES)
			return -1;
		wpabuf_put_data(buf, extra_ies, extra_ies_len);
	}
	return 0;
}


static int test_driver_scan2(void *priv, struct wpa_driver_scan_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct wpabuf *buf;
	size_t i, num_ssids;

	if (drv->scanning) {
		wpa_printf(MSG_DEBUG, "test_driver(%s): Scan already in progress",
			   drv->ifname);
		return -1;
	}
	if (drv->ap) {
		/* AP mode scans (e.g., HT40 OBSS scan before enabling a 40 MHz
		 * channel) complete deterministically with no neighboring
		 * BSSes; there is no radio to scan with. */
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): AP scan request - report empty results",
			   drv->ifname);
		drv->scanning = true;
		eloop_cancel_timeout(test_driver_scan_timeout, drv,
				     ELOOP_ALL_CTX);
		eloop_register_timeout(drv->scan_time_ms / 1000,
				       (drv->scan_time_ms % 1000) * 1000,
				       test_driver_scan_timeout, drv, bss->ctx);
		return 0;
	}
	if (drv->sock < 0) {
		wpa_printf(MSG_ERROR,
			   "test_driver(%s): No test socket configured - use driver_param test_socket=/test_dir=/test_udp=",
			   drv->ifname);
		return -1;
	}

	/* Frequency filter for the emulated channel list */
	os_free(drv->scan_freqs);
	drv->scan_freqs = NULL;
	if (params->freqs) {
		size_t n = 0;

		while (params->freqs[n])
			n++;
		if (n > 0 && n < 1024) {
			drv->scan_freqs = os_memdup(params->freqs,
						    (n + 1) * sizeof(int));
		}
	}

	num_ssids = params->num_ssids;
	if (num_ssids > WPAS_MAX_SCAN_SSIDS)
		num_ssids = WPAS_MAX_SCAN_SSIDS;

	buf = wpabuf_alloc(IEEE80211_HDRLEN + 2 + SSID_MAX_LEN + 16 +
			   TEST_MAX_PROBE_IES);
	if (!buf)
		return -1;

	for (i = 0; i < (num_ssids ? num_ssids : 1); i++) {
		const u8 *ssid = NULL;
		size_t ssid_len = 0;

		if (num_ssids) {
			ssid = params->ssids[i].ssid;
			ssid_len = params->ssids[i].ssid_len;
		}
		test_wpabuf_reset(buf);
		if (test_driver_build_probe_req(drv, buf, params->bssid, ssid,
						ssid_len, params->extra_ies,
						params->extra_ies_len) < 0) {
			wpabuf_free(buf);
			return -1;
		}
		wpa_hexdump_ascii(MSG_DEBUG, "test_driver: Scan SSID", ssid,
				  ssid_len);
		test_driver_send_broadcast(drv, TEST_DRV_MSG_MGMT, 0, -1,
					   wpabuf_head(buf), wpabuf_len(buf));
	}
	wpabuf_free(buf);

	drv->scanning = true;
	test_pending_add(drv, TEST_EV_SCAN_STARTED, drv->ctx, NULL, 0);
	eloop_cancel_timeout(test_driver_scan_timeout, drv, ELOOP_ALL_CTX);
	eloop_register_timeout(drv->scan_time_ms / 1000,
			       (drv->scan_time_ms % 1000) * 1000,
			       test_driver_scan_timeout, drv, NULL);
	return 0;
}


static int test_driver_abort_scan(void *priv, u64 scan_cookie)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (!drv->scanning)
		return -1;
	eloop_cancel_timeout(test_driver_scan_timeout, drv, ELOOP_ALL_CTX);
	drv->scanning = false;
	/* Reported asynchronously like a kernel scan-aborted event */
	test_pending_add(drv, TEST_EV_SCAN_ABORTED, drv->ctx, NULL, 0);
	return 0;
}


static struct wpa_scan_results * test_driver_get_scan_results2(void *priv)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct wpa_scan_results *res;
	size_t i;

	res = os_zalloc(sizeof(*res));
	if (!res)
		return NULL;
	res->res = os_calloc(drv->num_scanres + 1, sizeof(struct wpa_scan_res *));
	if (!res->res) {
		os_free(res);
		return NULL;
	}
	for (i = 0; i < drv->num_scanres; i++) {
		struct wpa_scan_res *r, *src = drv->scanres[i];
		size_t len;

		if (!src)
			continue;
		len = sizeof(*src) + src->ie_len + src->beacon_ie_len;
		r = os_memdup(src, len);
		if (!r)
			break;
		res->res[res->num++] = r;
	}
	os_get_reltime(&res->fetch_time);
	return res;
}


static void test_driver_auth_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	union wpa_event_data event;

	if (drv->sta_state != TEST_STA_AUTHENTICATING)
		return;
	wpa_printf(MSG_DEBUG, "test_driver(%s): Authentication timed out",
		   drv->ifname);
	drv->stats.auth_timeouts++;
	drv->sta_state = TEST_STA_IDLE;
	os_memset(&event, 0, sizeof(event));
	os_memcpy(event.timeout_event.addr, drv->mlo ? drv->ap_mld_addr :
		  drv->bssid, ETH_ALEN);
	wpa_supplicant_event(drv->ctx, EVENT_AUTH_TIMED_OUT, &event);
}


static void test_driver_assoc_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	union wpa_event_data event;

	if (drv->sta_state != TEST_STA_ASSOCIATING)
		return;
	wpa_printf(MSG_DEBUG, "test_driver(%s): Association timed out",
		   drv->ifname);
	drv->stats.assoc_timeouts++;
	drv->sta_state = TEST_STA_AUTHENTICATED;
	os_memset(&event, 0, sizeof(event));
	os_memcpy(event.timeout_event.addr, drv->mlo ? drv->ap_mld_addr :
		  drv->bssid, ETH_ALEN);
	wpa_supplicant_event(drv->ctx, EVENT_ASSOC_TIMED_OUT, &event);
}


static void test_driver_keepalive(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_driver_test_data *drv = eloop_ctx;
	struct test_peer *peer;
	bool lost = false;

	if (drv->sta_state != TEST_STA_ASSOCIATED)
		return;

	peer = test_sta_ap_peer(drv, drv->mlo ? drv->ap_mld_addr : drv->bssid,
				-1);
	if (!peer) {
		lost = true;
	} else if (test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_NULL, 0,
					    drv->mlo ? (int) drv->assoc_link_id :
					    -1, NULL, 0) < 0 &&
		   (errno == ECONNREFUSED || errno == ENOENT ||
		    errno == ENOTCONN)) {
		lost = true;
	}

	if (lost) {
		struct test_pending_event *ev;

		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): AP socket disappeared - report local deauthentication",
			   drv->ifname);
		drv->stats.peer_lost++;
		ev = test_pending_add(drv, TEST_EV_LOCAL_DEAUTH, drv->ctx,
				      NULL, 0);
		if (ev) {
			os_memcpy(ev->addr, drv->mlo ? drv->ap_mld_addr :
				  drv->bssid, ETH_ALEN);
			ev->reason = WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY;
		}
		test_sta_disconnected(drv);
		return;
	}

	eloop_register_timeout(drv->keepalive_ms / 1000,
			       (drv->keepalive_ms % 1000) * 1000,
			       test_driver_keepalive, drv, NULL);
}


static void test_add_ml_ie_auth(struct wpabuf *buf, const u8 *mld_addr)
{
	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	wpabuf_put_u8(buf, 4 + ETH_ALEN);
	wpabuf_put_u8(buf, WLAN_EID_EXT_MULTI_LINK);
	wpabuf_put_le16(buf, MULTI_LINK_CONTROL_TYPE_BASIC);
	wpabuf_put_u8(buf, 1 + ETH_ALEN); /* Common Info Length */
	wpabuf_put_data(buf, mld_addr, ETH_ALEN);
}


static int test_driver_authenticate(void *priv,
				    struct wpa_driver_auth_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct wpabuf *buf;
	struct ieee80211_mgmt *mgmt;
	struct test_peer *peer;
	u16 trans = 1, status = WLAN_STATUS_SUCCESS;
	const u8 *auth_data = params->auth_data;
	size_t auth_data_len = params->auth_data_len;
	int ret, link_id = -1;

	if (drv->ap || !params->bssid)
		return -1;
	if (drv->sock < 0)
		return -1;
	if (params->ie_len > TEST_MAX_ASSOC_IES ||
	    auth_data_len > TEST_MAX_ASSOC_IES)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): authenticate: bssid=" MACSTR
		   " freq=%d auth_alg=%d ie_len=%zu auth_data_len=%zu mld=%d link_id=%u",
		   drv->ifname, MAC2STR(params->bssid), params->freq,
		   params->auth_alg, params->ie_len, auth_data_len,
		   params->mld, params->mld_link_id);

	if (params->local_state_change) {
		/* Only update the local state (e.g., FT over-the-DS marks the
		 * target AP as authenticated without sending a frame). */
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): Mark " MACSTR
			   " as authenticated (local state change)",
			   drv->ifname, MAC2STR(params->bssid));
		if (drv->mlo && !params->mld)
			test_sta_reset_mlo(drv);
		os_memcpy(drv->bssid, params->bssid, ETH_ALEN);
		if (params->freq)
			drv->freq = params->freq;
		drv->sta_state = TEST_STA_AUTHENTICATED;
		eloop_cancel_timeout(test_driver_auth_timeout, drv, NULL);
		eloop_cancel_timeout(test_driver_assoc_timeout, drv, NULL);
		return 0;
	}

	if (drv->sta_state == TEST_STA_ASSOCIATED &&
	    !ether_addr_equal(params->bssid, drv->bssid) &&
	    !(drv->mlo && params->mld && params->ap_mld_addr &&
	      ether_addr_equal(params->ap_mld_addr, drv->ap_mld_addr))) {
		/* Roaming to a new BSS: drop the old association state */
		test_sta_disconnected(drv);
	}

	if (params->mld) {
#ifdef CONFIG_IEEE80211BE
		if (!drv->mlo_capable || !params->ap_mld_addr ||
		    params->mld_link_id >= MAX_NUM_MLD_LINKS)
			return -1;
		if (!drv->mlo ||
		    !ether_addr_equal(drv->ap_mld_addr, params->ap_mld_addr)) {
			test_sta_reset_mlo(drv);
			drv->mlo = true;
			os_memcpy(drv->ap_mld_addr, params->ap_mld_addr,
				  ETH_ALEN);
		}
		drv->assoc_link_id = params->mld_link_id;
		drv->req_links |= BIT(params->mld_link_id);
		os_memcpy(drv->links[params->mld_link_id].bssid, params->bssid,
			  ETH_ALEN);
		drv->links[params->mld_link_id].freq = params->freq;
		test_sta_derive_link_addr(drv, params->mld_link_id,
					  drv->links[params->mld_link_id].addr);
		link_id = params->mld_link_id;
#else /* CONFIG_IEEE80211BE */
		return -1;
#endif /* CONFIG_IEEE80211BE */
	} else if (drv->mlo) {
		test_sta_reset_mlo(drv);
	}

	os_memcpy(drv->bssid, params->bssid, ETH_ALEN);
	if (params->freq)
		drv->freq = params->freq;
	drv->pending_auth_alg = params->auth_alg;

	switch (params->auth_alg) {
	case WPA_AUTH_ALG_OPEN:
	case WPA_AUTH_ALG_FT:
	case WPA_AUTH_ALG_FILS:
	case WPA_AUTH_ALG_FILS_SK_PFS:
	case WPA_AUTH_ALG_SAE:
	case WPA_AUTH_ALG_SHARED:
	case WPA_AUTH_ALG_LEAP:
		break;
	default:
		if (!(params->auth_alg & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_FT |
					  WPA_AUTH_ALG_FILS | WPA_AUTH_ALG_SAE |
					  WPA_AUTH_ALG_FILS_SK_PFS)))
			return -1;
		break;
	}

	if (params->auth_alg & WPA_AUTH_ALG_SAE) {
		/* SAE data starts with transaction sequence and status */
		if (auth_data_len < 4)
			return -1;
		trans = WPA_GET_LE16(auth_data);
		status = WPA_GET_LE16(auth_data + 2);
		auth_data += 4;
		auth_data_len -= 4;
	}

	buf = wpabuf_alloc(IEEE80211_HDRLEN + 6 + params->ie_len +
			   auth_data_len + 16);
	if (!buf)
		return -1;
	mgmt = wpabuf_put(buf, IEEE80211_HDRLEN + 6);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_AUTH);
	os_memcpy(mgmt->da, drv->mlo ? drv->ap_mld_addr : params->bssid,
		  ETH_ALEN);
	os_memcpy(mgmt->sa, drv->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, drv->mlo ? drv->ap_mld_addr : params->bssid,
		  ETH_ALEN);
	if (params->auth_alg & WPA_AUTH_ALG_SAE)
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_SAE);
	else if (params->auth_alg & WPA_AUTH_ALG_FT)
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_FT);
	else if (params->auth_alg & WPA_AUTH_ALG_FILS)
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_FILS_SK);
	else if (params->auth_alg & WPA_AUTH_ALG_FILS_SK_PFS)
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_FILS_SK_PFS);
	else if (params->auth_alg & WPA_AUTH_ALG_SHARED)
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_SHARED_KEY);
	else
		mgmt->u.auth.auth_alg = host_to_le16(WLAN_AUTH_OPEN);
	mgmt->u.auth.auth_transaction = host_to_le16(trans);
	mgmt->u.auth.status_code = host_to_le16(status);
	if (auth_data && auth_data_len)
		wpabuf_put_data(buf, auth_data, auth_data_len);
	if (params->ie && params->ie_len)
		wpabuf_put_data(buf, params->ie, params->ie_len);
	if (drv->mlo)
		test_add_ml_ie_auth(buf, drv->own_addr);

	/* The Authentication frame is sent with link addresses */
	test_sta_tx_translate(drv, (struct ieee80211_hdr *) wpabuf_mhead(buf),
			      link_id);

	peer = test_sta_ap_peer(drv, params->bssid, link_id);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): No transport address known for "
			   MACSTR, drv->ifname, MAC2STR(params->bssid));
		wpabuf_free(buf);
		return -1;
	}

	drv->sta_state = TEST_STA_AUTHENTICATING;
	drv->stats.tx_mgmt++;
	ret = test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_MGMT, 0,
				       link_id, wpabuf_head(buf),
				       wpabuf_len(buf));
	wpabuf_free(buf);

	eloop_cancel_timeout(test_driver_auth_timeout, drv, NULL);
	eloop_register_timeout(drv->auth_timeout_ms / 1000,
			       (drv->auth_timeout_ms % 1000) * 1000,
			       test_driver_auth_timeout, drv, NULL);
	return ret;
}


static const struct wpa_scan_res *
test_sta_scanres_get(struct wpa_driver_test_data *drv, const u8 *bssid)
{
	size_t i;

	for (i = 0; i < drv->num_scanres; i++) {
		if (drv->scanres[i] &&
		    ether_addr_equal(drv->scanres[i]->bssid, bssid))
			return drv->scanres[i];
	}
	return NULL;
}


/* Add synthetic PHY capability elements matching what the target BSS
 * advertises. This mirrors how mac80211 disables HT/VHT/HE/EHT when the AP
 * does not support them. */
static void test_add_phy_capab_ies(struct wpa_driver_test_data *drv,
				   struct wpabuf *buf, const u8 *bss_ies,
				   size_t bss_ies_len, int freq,
				   bool disable_ht, bool disable_vht,
				   bool disable_he, bool disable_eht,
				   const u8 *htcaps, const u8 *htcaps_mask)
{
	struct ieee802_11_elems elems;
	bool ht, vht, he, eht, wmm;
	bool is_2g = freq >= 2400 && freq < 2500;
	bool is_6g = freq >= 5925;

	if (!bss_ies ||
	    ieee802_11_parse_elems(bss_ies, bss_ies_len, &elems, 0) ==
	    ParseFailed)
		os_memset(&elems, 0, sizeof(elems));

	wmm = elems.wmm != NULL;
	ht = elems.ht_capabilities && elems.ht_operation && wmm &&
		(drv->phy_caps & TEST_PHY_HT) && !disable_ht && !is_6g;
	vht = ht && elems.vht_capabilities && elems.vht_operation &&
		(drv->phy_caps & TEST_PHY_VHT) && !disable_vht && !is_2g;
	he = elems.he_capabilities && elems.he_operation && wmm &&
		(drv->phy_caps & TEST_PHY_HE) && !disable_he &&
		(ht || is_6g);
	eht = he && elems.eht_capabilities && elems.eht_operation &&
		(drv->phy_caps & TEST_PHY_EHT) && !disable_eht;

	if (wmm) {
		static const u8 wmm_ie[] = { 0x00, 0x50, 0xf2, 0x02, 0x00,
					     0x01, 0x00 };

		wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(buf, sizeof(wmm_ie));
		wpabuf_put_data(buf, wmm_ie, sizeof(wmm_ie));
	}

	if (ht) {
		struct ieee80211_ht_capabilities *cap;
		u16 info = TEST_HT_CAPAB;

		wpabuf_put_u8(buf, WLAN_EID_HT_CAP);
		wpabuf_put_u8(buf, sizeof(*cap));
		cap = wpabuf_put(buf, sizeof(*cap));
		if (htcaps && htcaps_mask) {
			const struct ieee80211_ht_capabilities *o =
				(const struct ieee80211_ht_capabilities *)
				htcaps;
			const struct ieee80211_ht_capabilities *m =
				(const struct ieee80211_ht_capabilities *)
				htcaps_mask;
			u16 mask = le_to_host16(m->ht_capabilities_info);

			info = (info & ~mask) |
				(le_to_host16(o->ht_capabilities_info) & mask);
		}
		cap->ht_capabilities_info = host_to_le16(info);
		cap->a_mpdu_params = TEST_HT_AMPDU_PARAMS;
		os_memcpy(cap->supported_mcs_set, test_ht_mcs_set,
			  sizeof(cap->supported_mcs_set));
	}

	if (vht) {
		struct ieee80211_vht_capabilities *cap;

		wpabuf_put_u8(buf, WLAN_EID_VHT_CAP);
		wpabuf_put_u8(buf, sizeof(*cap));
		cap = wpabuf_put(buf, sizeof(*cap));
		cap->vht_capabilities_info = host_to_le32(TEST_VHT_CAPAB);
		os_memcpy(&cap->vht_supported_mcs_set, test_vht_mcs_set,
			  sizeof(test_vht_mcs_set));
	}

	if (he) {
		/* HE Capabilities: MAC (6) + PHY (11) + MCS/NSS <= 80 (4) */
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + 6 + 11 + 4);
		wpabuf_put_u8(buf, WLAN_EID_EXT_HE_CAPABILITIES);
		wpabuf_put_data(buf, test_he_mac_cap, 6);
		{
			u8 phy[11];

			os_memset(phy, 0, sizeof(phy));
			phy[HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] =
				test_he_phy_width(freq);
			wpabuf_put_data(buf, phy, sizeof(phy));
		}
		wpabuf_put_data(buf, test_he_mcs, 4);

		if (is_6g) {
			wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
			wpabuf_put_u8(buf, 1 + 2);
			wpabuf_put_u8(buf, WLAN_EID_EXT_HE_6GHZ_BAND_CAP);
			wpabuf_put_le16(buf, TEST_HE_6GHZ_CAPA);
		}
	}

	if (eht) {
		/* EHT Capabilities: MAC (2) + PHY (9) + MCS/NSS (3) */
		u8 phy[EHT_PHY_CAPAB_LEN];

		os_memset(phy, 0, sizeof(phy));
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + 2 + EHT_PHY_CAPAB_LEN + 3);
		wpabuf_put_u8(buf, WLAN_EID_EXT_EHT_CAPABILITIES);
		wpabuf_put_le16(buf, 0);
		wpabuf_put_data(buf, phy, sizeof(phy));
		wpabuf_put_data(buf, test_eht_mcs, 3);
	}
}


static void test_add_rates_ies(struct wpabuf *buf, int freq)
{
	if (freq >= 2400 && freq < 2500) {
		wpabuf_put_u8(buf, WLAN_EID_SUPP_RATES);
		wpabuf_put_u8(buf, sizeof(test_supp_rates_g));
		wpabuf_put_data(buf, test_supp_rates_g,
				sizeof(test_supp_rates_g));
		wpabuf_put_u8(buf, WLAN_EID_EXT_SUPP_RATES);
		wpabuf_put_u8(buf, sizeof(test_ext_rates_g));
		wpabuf_put_data(buf, test_ext_rates_g,
				sizeof(test_ext_rates_g));
	} else {
		wpabuf_put_u8(buf, WLAN_EID_SUPP_RATES);
		wpabuf_put_u8(buf, sizeof(test_supp_rates_a));
		wpabuf_put_data(buf, test_supp_rates_a,
				sizeof(test_supp_rates_a));
	}
}


#ifdef CONFIG_IEEE80211BE

/* Append a possibly fragmented subelement (id + data) to the ML element
 * body. Fragments use subelement ID 254 (Fragment). */
static void test_put_mle_subelem(struct wpabuf *buf, u8 id, const u8 *data,
				 size_t len)
{
	size_t chunk = len > 255 ? 255 : len;

	wpabuf_put_u8(buf, id);
	wpabuf_put_u8(buf, chunk);
	wpabuf_put_data(buf, data, chunk);
	data += chunk;
	len -= chunk;
	while (len) {
		chunk = len > 255 ? 255 : len;
		wpabuf_put_u8(buf, 254); /* Fragment subelement */
		wpabuf_put_u8(buf, chunk);
		wpabuf_put_data(buf, data, chunk);
		data += chunk;
		len -= chunk;
	}
}


/* Append an element (possibly fragmented with EID 242) built from body. */
static void test_put_ext_elem_fragmented(struct wpabuf *buf, u8 ext_id,
					 const u8 *body, size_t len)
{
	size_t chunk = len > 254 ? 254 : len;

	wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
	wpabuf_put_u8(buf, 1 + chunk);
	wpabuf_put_u8(buf, ext_id);
	wpabuf_put_data(buf, body, chunk);
	body += chunk;
	len -= chunk;
	while (len) {
		chunk = len > 255 ? 255 : len;
		wpabuf_put_u8(buf, WLAN_EID_FRAGMENT);
		wpabuf_put_u8(buf, chunk);
		wpabuf_put_data(buf, body, chunk);
		body += chunk;
		len -= chunk;
	}
}


static int test_add_ml_ie_assoc(struct wpa_driver_test_data *drv,
				struct wpabuf *buf,
				struct wpa_driver_associate_params *params,
				u16 capab)
{
	struct wpa_driver_mld_params *mld = &params->mld_params;
	struct wpabuf *body, *prof;
	int i, num_links = 0;
	u16 mld_capa;

	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		if (mld->valid_links & BIT(i))
			num_links++;
	}
	if (num_links < 1)
		return 0;

	body = wpabuf_alloc(64 + num_links * (16 + TEST_MAX_ASSOC_IES));
	prof = wpabuf_alloc(16 + TEST_MAX_ASSOC_IES);
	if (!body || !prof) {
		wpabuf_free(body);
		wpabuf_free(prof);
		return -1;
	}

	/* Multi-Link Control: Basic, MLD Capabilities present */
	wpabuf_put_le16(body, MULTI_LINK_CONTROL_TYPE_BASIC |
			BASIC_MULTI_LINK_CTRL_PRES_MLD_CAPA);
	/* Common Info: Length, MLD MAC Address, MLD Capabilities */
	wpabuf_put_u8(body, 1 + ETH_ALEN + 2);
	wpabuf_put_data(body, drv->own_addr, ETH_ALEN);
	mld_capa = (num_links - 1) & 0x0f; /* Maximum Number of Simultaneous
					    * Links */
	wpabuf_put_le16(body, mld_capa);

	/* Per-STA Profile for each non-assoc link */
	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		const struct wpa_scan_res *res;
		const u8 *ies = NULL;
		size_t ies_len = 0;
		int freq;

		if (!(mld->valid_links & BIT(i)) || i == drv->assoc_link_id)
			continue;
		if (!mld->mld_links[i].bssid)
			continue;
		if (mld->mld_links[i].ies_len > TEST_MAX_ASSOC_IES)
			goto fail;

		drv->req_links |= BIT(i);
		os_memcpy(drv->links[i].bssid, mld->mld_links[i].bssid,
			  ETH_ALEN);
		drv->links[i].freq = mld->mld_links[i].freq;
		test_sta_derive_link_addr(drv, i, drv->links[i].addr);
		freq = mld->mld_links[i].freq;

		test_wpabuf_reset(prof);
		/* STA Control: Link ID, Complete Profile, STA MAC Address
		 * Present */
		wpabuf_put_le16(prof, (i & BASIC_MLE_STA_CTRL_LINK_ID_MASK) |
				BASIC_MLE_STA_CTRL_PRES_STA_MAC |
				BASIC_MLE_STA_CTRL_COMPLETE_PROFILE);
		/* STA Info: Length, STA MAC Address */
		wpabuf_put_u8(prof, 1 + ETH_ALEN);
		wpabuf_put_data(prof, drv->links[i].addr, ETH_ALEN);
		/* STA Profile: Capability Information + elements */
		wpabuf_put_le16(prof, capab);
		test_add_rates_ies(prof, freq);
		res = test_sta_scanres_get(drv, mld->mld_links[i].bssid);
		if (res) {
			ies = (const u8 *) (res + 1);
			ies_len = res->ie_len;
		}
		test_add_phy_capab_ies(drv, prof, ies, ies_len, freq,
				       params->disable_ht, false, false,
				       params->disable_eht, NULL, NULL);
		if (mld->mld_links[i].ies && mld->mld_links[i].ies_len)
			wpabuf_put_data(prof, mld->mld_links[i].ies,
					mld->mld_links[i].ies_len);

		test_put_mle_subelem(body, 0, wpabuf_head(prof),
				     wpabuf_len(prof));
	}

	if (wpabuf_len(body) > TEST_MAX_ASSOC_IES)
		goto fail;
	test_put_ext_elem_fragmented(buf, WLAN_EID_EXT_MULTI_LINK,
				     wpabuf_head(body), wpabuf_len(body));
	wpabuf_free(body);
	wpabuf_free(prof);
	return 0;

fail:
	wpabuf_free(body);
	wpabuf_free(prof);
	return -1;
}

#endif /* CONFIG_IEEE80211BE */


static int test_driver_associate(void *priv,
				 struct wpa_driver_associate_params *params)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct wpabuf *buf;
	struct ieee80211_mgmt *mgmt;
	struct test_peer *peer;
	const struct wpa_scan_res *res;
	const u8 *bss_ies = NULL;
	size_t bss_ies_len = 0;
	size_t fixed_len, ies_len;
	u16 capab, stype;
	int ret, link_id = -1;
	const u8 *bssid = params->bssid;
	bool reassoc = params->prev_bssid != NULL;
	bool privacy;

	if (drv->ap)
		return -1;
	if (params->mode != IEEE80211_MODE_INFRA) {
		wpa_printf(MSG_INFO,
			   "test_driver(%s): Only infrastructure STA mode is supported (mode=%d requested)",
			   drv->ifname, params->mode);
		return -1;
	}
	if (!bssid || !params->ssid || params->ssid_len > SSID_MAX_LEN ||
	    params->wpa_ie_len > TEST_MAX_ASSOC_IES)
		return -1;
	if (drv->sock < 0)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "test_driver(%s): associate: bssid=" MACSTR
		   " freq=%d key_mgmt=0x%x pairwise=0x%x group=0x%x mgmt_group=0x%x auth_alg=%d wpa_ie_len=%zu reassoc=%d mfp=%d",
		   drv->ifname, MAC2STR(bssid), params->freq.freq,
		   params->key_mgmt_suite, params->pairwise_suite,
		   params->group_suite, params->mgmt_group_suite,
		   params->auth_alg, params->wpa_ie_len, reassoc,
		   params->mgmt_frame_protection);
	wpa_hexdump_ascii(MSG_DEBUG, "test_driver: SSID", params->ssid,
			  params->ssid_len);
	wpa_hexdump(MSG_MSGDUMP, "test_driver: wpa_ie", params->wpa_ie,
		    params->wpa_ie_len);

#ifdef CONFIG_IEEE80211BE
	if (params->mld_params.mld_addr && params->mld_params.valid_links) {
		if (!drv->mlo_capable)
			return -1;
		if (!drv->mlo ||
		    !ether_addr_equal(drv->ap_mld_addr,
				      params->mld_params.mld_addr)) {
			test_sta_reset_mlo(drv);
			drv->mlo = true;
			os_memcpy(drv->ap_mld_addr, params->mld_params.mld_addr,
				  ETH_ALEN);
		}
		drv->assoc_link_id = params->mld_params.assoc_link_id;
		if (drv->assoc_link_id >= MAX_NUM_MLD_LINKS)
			return -1;
		/* For an MLO association, params->bssid is the AP MLD address
		 * and the per-link BSSIDs are in mld_params. */
		if (params->mld_params.mld_links[drv->assoc_link_id].bssid)
			bssid = params->mld_params.mld_links[drv->assoc_link_id].
				bssid;
		drv->req_links |= BIT(drv->assoc_link_id);
		os_memcpy(drv->links[drv->assoc_link_id].bssid, bssid,
			  ETH_ALEN);
		drv->links[drv->assoc_link_id].freq = params->freq.freq;
		test_sta_derive_link_addr(drv, drv->assoc_link_id,
					  drv->links[drv->assoc_link_id].addr);
		link_id = drv->assoc_link_id;
	}
#endif /* CONFIG_IEEE80211BE */

	if (drv->sta_state == TEST_STA_ASSOCIATED &&
	    !ether_addr_equal(bssid, drv->bssid))
		test_sta_disconnected(drv);
	os_memcpy(drv->bssid, bssid, ETH_ALEN);
	if (params->freq.freq)
		drv->freq = params->freq.freq;
	drv->reassoc = reassoc;
	drv->mfp = params->mgmt_frame_protection != NO_MGMT_FRAME_PROTECTION;

	res = test_sta_scanres_get(drv, bssid);
	if (res) {
		bss_ies = (const u8 *) (res + 1);
		bss_ies_len = res->ie_len;
	}

	privacy = params->wpa_ie_len > 0 ||
		(params->key_mgmt_suite != WPA_KEY_MGMT_NONE &&
		 params->key_mgmt_suite != 0) ||
		params->wep_key_len[params->wep_tx_keyidx] > 0;
	capab = WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_SHORT_SLOT_TIME;
	if (privacy)
		capab |= WLAN_CAPABILITY_PRIVACY;
	if (drv->freq >= 2400 && drv->freq < 2500)
		capab |= WLAN_CAPABILITY_SHORT_PREAMBLE;

	buf = wpabuf_alloc(IEEE80211_HDRLEN + 10 + 2 + SSID_MAX_LEN + 200 +
			   params->wpa_ie_len + 3 * TEST_MAX_ASSOC_IES);
	if (!buf)
		return -1;
	fixed_len = IEEE80211_HDRLEN + (reassoc ? sizeof(mgmt->u.reassoc_req) :
					sizeof(mgmt->u.assoc_req));
	mgmt = wpabuf_put(buf, fixed_len);
	stype = reassoc ? WLAN_FC_STYPE_REASSOC_REQ : WLAN_FC_STYPE_ASSOC_REQ;
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT, stype);
	os_memcpy(mgmt->da, drv->mlo ? drv->ap_mld_addr : bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, drv->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, drv->mlo ? drv->ap_mld_addr : bssid, ETH_ALEN);
	if (reassoc) {
		mgmt->u.reassoc_req.capab_info = host_to_le16(capab);
		mgmt->u.reassoc_req.listen_interval = host_to_le16(10);
		os_memcpy(mgmt->u.reassoc_req.current_ap, params->prev_bssid,
			  ETH_ALEN);
	} else {
		mgmt->u.assoc_req.capab_info = host_to_le16(capab);
		mgmt->u.assoc_req.listen_interval = host_to_le16(10);
	}

	wpabuf_put_u8(buf, WLAN_EID_SSID);
	wpabuf_put_u8(buf, params->ssid_len);
	wpabuf_put_data(buf, params->ssid, params->ssid_len);
	test_add_rates_ies(buf, drv->freq);
	test_add_phy_capab_ies(drv, buf, bss_ies, bss_ies_len, drv->freq,
			       params->disable_ht,
#ifdef CONFIG_VHT_OVERRIDES
			       params->disable_vht,
#else /* CONFIG_VHT_OVERRIDES */
			       false,
#endif /* CONFIG_VHT_OVERRIDES */
#ifdef CONFIG_HE_OVERRIDES
			       params->disable_he,
#else /* CONFIG_HE_OVERRIDES */
			       false,
#endif /* CONFIG_HE_OVERRIDES */
			       params->disable_eht, params->htcaps,
			       params->htcaps_mask);
	if (params->wpa_ie && params->wpa_ie_len)
		wpabuf_put_data(buf, params->wpa_ie, params->wpa_ie_len);
#ifdef CONFIG_IEEE80211BE
	if (drv->mlo && test_add_ml_ie_assoc(drv, buf, params, capab) < 0) {
		wpabuf_free(buf);
		return -1;
	}
#endif /* CONFIG_IEEE80211BE */

#ifdef CONFIG_FILS
	if (params->fils_kek && params->fils_kek_len &&
	    params->fils_nonces && params->fils_nonces_len == 2 * NONCE_LEN) {
		/* Like mac80211, the driver performs the AES-SIV encryption of
		 * the elements following the FILS Session element using the
		 * KEK and nonces provided by wpa_supplicant. */
		const u8 *frame = wpabuf_head(buf);
		const u8 *ies = frame + fixed_len;
		const u8 *session, *crypt, *end = frame + wpabuf_len(buf);
		const u8 *aad[5];
		size_t aad_len[5], plain_len;
		struct wpabuf *enc;

		session = get_ie_ext(ies, wpabuf_len(buf) - fixed_len,
				     WLAN_EID_EXT_FILS_SESSION);
		if (!session) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): FILS: No FILS Session element",
				   drv->ifname);
			wpabuf_free(buf);
			return -1;
		}
		crypt = session + 2 + session[1];
		plain_len = end - crypt;
		enc = wpabuf_alloc(wpabuf_len(buf) + AES_BLOCK_SIZE);
		if (!enc) {
			wpabuf_free(buf);
			return -1;
		}
		wpabuf_put_data(enc, frame, crypt - frame);
		aad[0] = mgmt->sa;
		aad_len[0] = ETH_ALEN;
		aad[1] = mgmt->da;
		aad_len[1] = ETH_ALEN;
		aad[2] = params->fils_nonces; /* SNonce */
		aad_len[2] = NONCE_LEN;
		aad[3] = params->fils_nonces + NONCE_LEN; /* ANonce */
		aad_len[3] = NONCE_LEN;
		aad[4] = frame + IEEE80211_HDRLEN; /* Capability Information */
		aad_len[4] = crypt - aad[4];
		if (aes_siv_encrypt(params->fils_kek, params->fils_kek_len,
				    crypt, plain_len, 5, aad, aad_len,
				    wpabuf_put(enc, plain_len +
					       AES_BLOCK_SIZE)) < 0) {
			wpa_printf(MSG_DEBUG,
				   "test_driver(%s): FILS: AES-SIV encryption failed",
				   drv->ifname);
			wpabuf_free(enc);
			wpabuf_free(buf);
			return -1;
		}
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): FILS: Encrypted %zu octets of (Re)Association Request elements",
			   drv->ifname, plain_len);
		wpabuf_free(buf);
		buf = enc;
		/* Keep the KEK for decrypting the (Re)Association Response */
		if (params->fils_kek_len <= sizeof(drv->fils_kek)) {
			os_memcpy(drv->fils_kek, params->fils_kek,
				  params->fils_kek_len);
			drv->fils_kek_len = params->fils_kek_len;
			os_memcpy(drv->fils_nonces, params->fils_nonces,
				  sizeof(drv->fils_nonces));
		}
	} else {
		forced_memzero(drv->fils_kek, sizeof(drv->fils_kek));
		drv->fils_kek_len = 0;
	}
#endif /* CONFIG_FILS */

	/* Keep a copy of the request elements for EVENT_ASSOC */
	ies_len = wpabuf_len(buf) - fixed_len;
	os_free(drv->assoc_req_ies);
	drv->assoc_req_ies = os_memdup(wpabuf_head_u8(buf) + fixed_len,
				       ies_len);
	drv->assoc_req_ies_len = drv->assoc_req_ies ? ies_len : 0;

	test_sta_tx_translate(drv, (struct ieee80211_hdr *) wpabuf_mhead(buf),
			      link_id);

	peer = test_sta_ap_peer(drv, bssid, link_id);
	if (!peer) {
		wpabuf_free(buf);
		return -1;
	}

	drv->sta_state = TEST_STA_ASSOCIATING;
	drv->stats.tx_mgmt++;
	ret = test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_MGMT, 0,
				       link_id, wpabuf_head(buf),
				       wpabuf_len(buf));
	wpabuf_free(buf);

	eloop_cancel_timeout(test_driver_assoc_timeout, drv, NULL);
	eloop_register_timeout(drv->assoc_timeout_ms / 1000,
			       (drv->assoc_timeout_ms % 1000) * 1000,
			       test_driver_assoc_timeout, drv, NULL);
	return ret;
}


static int test_driver_deauthenticate(void *priv, const u8 *addr,
				      u16 reason_code)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct ieee80211_mgmt mgmt;
	struct test_peer *peer;
	int link_id;

	wpa_printf(MSG_DEBUG, "test_driver(%s): deauthenticate " MACSTR
		   " reason=%u state=%d", drv->ifname, MAC2STR(addr),
		   reason_code, drv->sta_state);

	if (drv->ap)
		return -1;
	if (drv->sta_state == TEST_STA_IDLE) {
		test_sta_disconnected(drv);
		return 0;
	}

	os_memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DEAUTH);
	os_memcpy(mgmt.da, addr, ETH_ALEN);
	os_memcpy(mgmt.sa, drv->own_addr, ETH_ALEN);
	os_memcpy(mgmt.bssid, addr, ETH_ALEN);
	mgmt.u.deauth.reason_code = host_to_le16(reason_code);
	link_id = test_sta_tx_translate(drv, (struct ieee80211_hdr *) &mgmt,
					-1);
	if (drv->ptk.set && drv->mfp) {
		mgmt.frame_control |= host_to_le16(WLAN_FC_PROTECTED);
	}

	peer = test_sta_ap_peer(drv, addr, link_id);
	if (peer && drv->sock >= 0) {
		drv->stats.tx_mgmt++;
		test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_MGMT,
					 (drv->ptk.set && drv->mfp) ?
					 TEST_DRV_FLAG_PROTECTED : 0,
					 link_id, (const u8 *) &mgmt,
					 IEEE80211_HDRLEN +
					 sizeof(mgmt.u.deauth));
	}
	test_sta_disconnected(drv);
	return 0;
}


static int test_driver_get_bssid(void *priv, u8 *bssid)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (drv->ap) {
		os_memcpy(bssid, bss->addr, ETH_ALEN);
		return 0;
	}
	if (drv->sta_state != TEST_STA_ASSOCIATED) {
		os_memset(bssid, 0, ETH_ALEN);
		return 0;
	}
	os_memcpy(bssid, drv->mlo ? drv->ap_mld_addr : drv->bssid, ETH_ALEN);
	return 0;
}


static int test_driver_get_ssid(void *priv, u8 *ssid)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	const struct wpa_scan_res *res;
	const u8 *ie;

	if (drv->ap) {
		os_memcpy(ssid, bss->ssid, bss->ssid_len);
		return bss->ssid_len;
	}
	if (drv->sta_state != TEST_STA_ASSOCIATED)
		return 0;
	res = test_sta_scanres_get(drv, drv->bssid);
	if (!res)
		return 0;
	ie = get_ie((const u8 *) (res + 1), res->ie_len, WLAN_EID_SSID);
	if (!ie || ie[1] > SSID_MAX_LEN)
		return 0;
	os_memcpy(ssid, ie + 2, ie[1]);
	return ie[1];
}


static int test_driver_tx_control_port(void *priv, const u8 *dest, u16 proto,
				       const u8 *buf, size_t len,
				       int no_encrypt, int link_id)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	struct test_peer *peer;
	u8 *msg;
	struct l2_ethhdr *eth;
	int ret, wire_link = -1;

	if (len > TEST_DRV_MAX_PAYLOAD - sizeof(*eth))
		return -1;
	if (drv->sock < 0)
		return -1;

	msg = os_malloc(sizeof(*eth) + len);
	if (!msg)
		return -1;
	eth = (struct l2_ethhdr *) msg;
	os_memcpy(eth->h_dest, dest, ETH_ALEN);
	os_memcpy(eth->h_source, drv->own_addr, ETH_ALEN);
	eth->h_proto = host_to_be16(proto);
	os_memcpy(msg + sizeof(*eth), buf, len);

	if (drv->ap) {
		peer = test_peer_find(drv, dest, link_id);
	} else {
		if (drv->mlo) {
			wire_link = (link_id >= 0 &&
				     (drv->req_links & BIT(link_id))) ?
				link_id : (int) drv->assoc_link_id;
			if (ether_addr_equal(dest, drv->ap_mld_addr))
				os_memcpy(eth->h_dest,
					  drv->links[wire_link].bssid,
					  ETH_ALEN);
			os_memcpy(eth->h_source, drv->links[wire_link].addr,
				  ETH_ALEN);
		}
		peer = test_sta_ap_peer(drv, dest, wire_link);
	}
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "test_driver(%s): tx_control_port: unknown destination "
			   MACSTR, drv->ifname, MAC2STR(dest));
		os_free(msg);
		return -1;
	}

	drv->stats.tx_eapol++;
	ret = test_driver_send_to_peer(drv, peer, TEST_DRV_MSG_EAPOL,
				       no_encrypt ? 0 : TEST_DRV_FLAG_PROTECTED,
				       wire_link, msg, sizeof(*eth) + len);
	os_free(msg);
	return ret;
}


static int test_driver_get_sta_mlo_info(void *priv,
					struct driver_sta_mlo_info *mlo_info)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	int i;

	os_memset(mlo_info, 0, sizeof(*mlo_info));
	if (drv->ap || !drv->mlo || drv->sta_state != TEST_STA_ASSOCIATED)
		return 0;
	mlo_info->default_map = true;
	mlo_info->req_links = drv->req_links;
	mlo_info->valid_links = drv->valid_links;
	mlo_info->assoc_link_id = drv->assoc_link_id;
	os_memcpy(mlo_info->ap_mld_addr, drv->ap_mld_addr, ETH_ALEN);
	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
		if (!(drv->valid_links & BIT(i)))
			continue;
		os_memcpy(mlo_info->links[i].addr, drv->links[i].addr,
			  ETH_ALEN);
		os_memcpy(mlo_info->links[i].bssid, drv->links[i].bssid,
			  ETH_ALEN);
		mlo_info->links[i].freq = drv->links[i].freq;
	}
	return 0;
}


static int test_driver_set_mac_addr(void *priv, const u8 *addr)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (drv->ap || drv->sta_state != TEST_STA_IDLE)
		return -1;
	if (!addr) {
		/* Restore the permanent (derived) address */
		test_derive_addr(drv->ifname, "test mac addr generation",
				 drv->own_addr);
	} else {
		if (is_multicast_ether_addr(addr) || is_zero_ether_addr(addr))
			return -1;
		os_memcpy(drv->own_addr, addr, ETH_ALEN);
	}
	os_memcpy(bss->addr, drv->own_addr, ETH_ALEN);
	wpa_printf(MSG_DEBUG, "test_driver(%s): MAC address set to " MACSTR,
		   drv->ifname, MAC2STR(drv->own_addr));
	return 0;
}


static int test_driver_signal_poll(void *priv, struct wpa_signal_info *si)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	if (drv->ap || drv->sta_state != TEST_STA_ASSOCIATED)
		return -1;
	os_memset(si, 0, sizeof(*si));
	si->frequency = drv->freq;
	si->data.signal = -30;
	si->current_noise = WPA_INVALID_NOISE;
	si->chanwidth = CHAN_WIDTH_20;
	si->center_frq1 = drv->freq;
	return 0;
}


static int test_driver_update_ft_ies(void *priv, const u8 *md, const u8 *ies,
				     size_t ies_len)
{
	wpa_hexdump(MSG_DEBUG, "test_driver: update_ft_ies (FT handled in SME)",
		    ies, ies_len);
	return 0;
}


static int test_driver_set_operstate(void *priv, int state)
{
	wpa_printf(MSG_DEBUG, "test_driver: set_operstate %d", state);
	return 0;
}


static int test_driver_set_supp_port(void *priv, int authorized)
{
	wpa_printf(MSG_DEBUG, "test_driver: set_supp_port authorized=%d",
		   authorized);
	return 0;
}


static int test_driver_set_countermeasures(void *priv, int enabled)
{
	wpa_printf(MSG_DEBUG, "test_driver: set_countermeasures %d", enabled);
	return 0;
}


static int test_driver_mlme_setprotection(void *priv, const u8 *addr,
					  int protect_type, int key_type)
{
	wpa_printf(MSG_DEBUG, "test_driver: mlme_setprotection " MACSTR
		   " protect_type=%d key_type=%d", MAC2STR(addr), protect_type,
		   key_type);
	return 0;
}


static int test_driver_add_pmkid(void *priv, struct wpa_pmkid_params *params)
{
	return 0;
}


static int test_driver_remove_pmkid(void *priv, struct wpa_pmkid_params *params)
{
	return 0;
}


static int test_driver_flush_pmkid(void *priv)
{
	return 0;
}


static int test_driver_set_param(void *priv, const char *param)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;
	char *val;
	char path[300];
	int r;

	wpa_printf(MSG_DEBUG, "test_driver(%s): set_param '%s'", drv->ifname,
		   param ? param : "");
	if (!param)
		return 0;

	if (test_driver_parse_common_params(drv, param) < 0)
		return -1;

	test_driver_close_socket(drv);
	drv->ap_sa_set = false;
	os_free(drv->test_dir);
	drv->test_dir = NULL;

	val = test_driver_param_value(param, "test_udp=");
	if (val) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &drv->ap_sa;
		int port = atoi(val);

		os_free(val);
		if (port <= 0 || port > 65535)
			return -1;
		if (test_driver_bind_udp(drv, 0) < 0)
			return -1;
		os_memset(&drv->ap_sa, 0, sizeof(drv->ap_sa));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin->sin_port = htons((u16) port);
		drv->ap_sa_len = sizeof(*sin);
		drv->ap_sa_set = true;
		return 0;
	}

	val = test_driver_param_value(param, "test_dir=");
	if (val) {
		if (os_strlen(val) == 0) {
			os_free(val);
			return -1;
		}
		drv->test_dir = val;
		r = os_snprintf(path, sizeof(path), "%s/STA-%s", drv->test_dir,
				drv->ifname);
		if (os_snprintf_error(sizeof(path), r))
			return -1;
		if (test_driver_bind_unix(drv, path) < 0)
			return -1;
	}

	val = test_driver_param_value(param, "test_socket=");
	if (val) {
		struct sockaddr_un *un = (struct sockaddr_un *) &drv->ap_sa;

		if (os_strlen(val) == 0 ||
		    os_strlen(val) >= sizeof(un->sun_path)) {
			os_free(val);
			return -1;
		}
		if (!drv->test_dir) {
			/* Bind our own socket next to the AP socket */
			char *dir = os_strdup(val), *slash;

			if (!dir) {
				os_free(val);
				return -1;
			}
			slash = os_strrchr(dir, '/');
			if (slash)
				*slash = '\0';
			else
				os_strlcpy(dir, ".", 2);
			r = os_snprintf(path, sizeof(path), "%s/STA-%s", dir,
					drv->ifname);
			os_free(dir);
			if (os_snprintf_error(sizeof(path), r) ||
			    test_driver_bind_unix(drv, path) < 0) {
				os_free(val);
				return -1;
			}
		}
		os_memset(&drv->ap_sa, 0, sizeof(drv->ap_sa));
		un->sun_family = AF_UNIX;
		os_strlcpy(un->sun_path, val, sizeof(un->sun_path));
		drv->ap_sa_len = sizeof(*un);
		drv->ap_sa_set = true;
		os_free(val);
	}

	if (drv->sock < 0) {
		wpa_printf(MSG_ERROR,
			   "test_driver: driver_param must include test_socket=<path>, test_dir=<dir>, or test_udp=<port>");
		return -1;
	}
	return 0;
}


static void * test_driver_global_init(void *ctx)
{
	struct wpa_driver_test_global *global;

	global = os_zalloc(sizeof(*global));
	return global;
}


static void test_driver_global_deinit(void *priv)
{
	struct wpa_driver_test_global *global = priv;

	if (global && global->num_ifaces)
		wpa_printf(MSG_DEBUG, "test_driver: %u interface(s) still active at global deinit",
			   global->num_ifaces);
	os_free(global);
}


static void * test_driver_init2(void *ctx, const char *ifname,
				void *global_priv, enum wpa_p2p_mode p2p_mode)
{
	struct wpa_driver_test_data *drv;
	struct test_bss *bss;

	drv = test_alloc_data(ctx, ifname, false);
	if (!drv)
		return NULL;
	drv->global = global_priv;
	if (drv->global)
		drv->global->num_ifaces++;
	bss = test_bss_add(drv, ifname, drv->own_addr, ctx);
	if (!bss) {
		test_driver_deinit_common(drv);
		return NULL;
	}
	wpa_printf(MSG_DEBUG, "test_driver(%s): STA initialized with address "
		   MACSTR, drv->ifname, MAC2STR(drv->own_addr));
	return bss;
}


static void wpa_driver_test_deinit(void *priv)
{
	struct test_bss *bss = priv;
	struct wpa_driver_test_data *drv = bss->drv;

	wpa_printf(MSG_DEBUG, "test_driver(%s): deinit", drv->ifname);
	if (drv->ap && dl_list_len(&drv->bss) != 1)
		wpa_printf(MSG_DEBUG, "test_driver(%s): %u BSS entries remain",
			   drv->ifname, dl_list_len(&drv->bss));
	test_driver_deinit_common(drv);
}


const struct wpa_driver_ops wpa_driver_test_ops = {
	.name = "test",
	.desc = "hostapd/wpa_supplicant user space test driver",
	/* common */
	.get_capa = test_driver_get_capa,
	.get_mac_addr = test_driver_get_mac_addr,
	.get_radio_name = test_driver_get_radio_name,
	.get_hw_feature_data = test_driver_get_hw_feature_data,
	.set_key = test_driver_set_key,
	.get_seqnum = test_driver_get_seqnum,
	.send_mlme = test_driver_send_mlme,
	.send_action = test_driver_send_action,
	.remain_on_channel = test_driver_remain_on_channel,
	.cancel_remain_on_channel = test_driver_cancel_remain_on_channel,
	.probe_req_report = test_driver_probe_req_report,
	.set_freq = test_driver_set_freq,
	.tx_control_port = test_driver_tx_control_port,
	.status = test_driver_status,
	.get_bssid = test_driver_get_bssid,
	.get_ssid = test_driver_get_ssid,
	.set_operstate = test_driver_set_operstate,
	.set_countermeasures = test_driver_set_countermeasures,
	.mlme_setprotection = test_driver_mlme_setprotection,
	.add_pmkid = test_driver_add_pmkid,
	.remove_pmkid = test_driver_remove_pmkid,
	.flush_pmkid = test_driver_flush_pmkid,
	/* hostapd */
	.hapd_init = test_driver_init,
	.hapd_deinit = wpa_driver_test_deinit,
	.set_ap = test_driver_set_ap,
	.stop_ap = test_driver_stop_ap,
	.hapd_send_eapol = test_driver_hapd_send_eapol,
	.sta_deauth = test_driver_sta_deauth,
	.sta_disassoc = test_driver_sta_disassoc,
	.sta_add = test_driver_sta_add,
	.sta_remove = test_driver_sta_remove,
	.sta_set_flags = test_driver_sta_set_flags,
	.get_inact_sec = test_driver_get_inact_sec,
	.read_sta_data = test_driver_read_sta_data,
	.flush = test_driver_flush,
	.hapd_set_ssid = test_driver_hapd_set_ssid,
	.hapd_get_ssid = test_driver_hapd_get_ssid,
	.set_privacy = test_driver_set_privacy,
	.set_sta_vlan = test_driver_set_sta_vlan,
	.if_add = test_driver_if_add,
	.if_remove = test_driver_if_remove,
	.poll_client = test_driver_poll_client,
	.switch_channel = test_driver_switch_channel,
#ifdef CONFIG_IEEE80211BE
	.get_mld_capab = test_driver_get_mld_capab,
	.link_add = test_driver_link_add,
	.link_remove = test_driver_link_remove,
	.is_drv_shared = test_driver_is_drv_shared,
	.link_sta_remove = test_driver_link_sta_remove,
#endif /* CONFIG_IEEE80211BE */
	/* wpa_supplicant */
	.global_init = test_driver_global_init,
	.global_deinit = test_driver_global_deinit,
	.init2 = test_driver_init2,
	.deinit = wpa_driver_test_deinit,
	.set_param = test_driver_set_param,
	.scan2 = test_driver_scan2,
	.abort_scan = test_driver_abort_scan,
	.get_scan_results2 = test_driver_get_scan_results2,
	.authenticate = test_driver_authenticate,
	.associate = test_driver_associate,
	.deauthenticate = test_driver_deauthenticate,
	.update_ft_ies = test_driver_update_ft_ies,
	.set_supp_port = test_driver_set_supp_port,
	.get_sta_mlo_info = test_driver_get_sta_mlo_info,
	.set_mac_addr = test_driver_set_mac_addr,
	.signal_poll = test_driver_signal_poll,
};
