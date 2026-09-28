/*
 * Test driver interface (driver_test.c) - unit test program
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Exercises the datagram framing parser, capability reporting, synthetic
 * hardware feature data, parameter parsing, key table bounds, and the
 * initialization/deinitialization paths of the user space test driver
 * without starting hostapd or wpa_supplicant.
 */

#include "utils/includes.h"
#include <sys/un.h>
#include <sys/stat.h>

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "drivers/driver.h"
#include "drivers/driver_test.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)


static void test_hdr_roundtrip(void)
{
	u8 buf[TEST_DRV_MAX_MSG];
	struct test_drv_hdr hdr;
	const u8 *payload;
	size_t payload_len;
	u8 frame[24] = { 0x40, 0x00 };

	printf("hdr: build/parse round trip\n");
	CHECK(test_drv_hdr_build(buf, sizeof(buf), TEST_DRV_MSG_MGMT, 0, -1,
				 2412, 7, sizeof(frame)) == TEST_DRV_HDR_LEN);
	os_memcpy(buf + TEST_DRV_HDR_LEN, frame, sizeof(frame));
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + sizeof(frame), &hdr,
				 &payload, &payload_len) == 0);
	CHECK(hdr.type == TEST_DRV_MSG_MGMT);
	CHECK(hdr.link_id == TEST_DRV_LINK_ID_NONE);
	CHECK(le_to_host32(hdr.freq) == 2412);
	CHECK(le_to_host16(hdr.seq) == 7);
	CHECK(payload == buf + TEST_DRV_HDR_LEN);
	CHECK(payload_len == sizeof(frame));

	/* link ID is carried when valid and clamped to "none" otherwise */
	CHECK(test_drv_hdr_build(buf, sizeof(buf), TEST_DRV_MSG_EAPOL,
				 TEST_DRV_FLAG_PROTECTED, 3, 5180, 1, 0) ==
	      TEST_DRV_HDR_LEN);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN, &hdr, NULL, NULL) == 0);
	CHECK(hdr.link_id == 3 && hdr.flags == TEST_DRV_FLAG_PROTECTED);
	CHECK(test_drv_hdr_build(buf, sizeof(buf), TEST_DRV_MSG_NULL, 0,
				 MAX_NUM_MLD_LINKS, 0, 0, 0) == TEST_DRV_HDR_LEN);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN, &hdr, NULL, NULL) == 0);
	CHECK(hdr.link_id == TEST_DRV_LINK_ID_NONE);

	/* build refuses oversized payloads and short buffers */
	CHECK(test_drv_hdr_build(buf, sizeof(buf), TEST_DRV_MSG_MGMT, 0, -1, 0,
				 0, TEST_DRV_MAX_PAYLOAD + 1) == -1);
	CHECK(test_drv_hdr_build(buf, TEST_DRV_HDR_LEN - 1, TEST_DRV_MSG_MGMT,
				 0, -1, 0, 0, 0) == -1);
	CHECK(test_drv_hdr_build(NULL, sizeof(buf), TEST_DRV_MSG_MGMT, 0, -1,
				 0, 0, 0) == -1);
}


static void test_hdr_malformed(void)
{
	u8 buf[TEST_DRV_MAX_MSG + 64];
	struct test_drv_hdr hdr;
	size_t i;

	printf("hdr: malformed inputs\n");
	os_memset(buf, 0, sizeof(buf));
	CHECK(test_drv_hdr_build(buf, sizeof(buf), TEST_DRV_MSG_MGMT, 0, -1,
				 2412, 0, 24) == TEST_DRV_HDR_LEN);

	/* truncated */
	for (i = 0; i < TEST_DRV_HDR_LEN; i++)
		CHECK(test_drv_hdr_parse(buf, i, &hdr, NULL, NULL) == -1);
	/* length mismatch in both directions */
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 23, &hdr, NULL,
				 NULL) == -1);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 25, &hdr, NULL,
				 NULL) == -1);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == 0);
	/* oversized datagram */
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_MAX_MSG + 1, &hdr, NULL,
				 NULL) == -1);
	/* bad magic */
	buf[0] ^= 0xff;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[0] ^= 0xff;
	/* bad version */
	buf[4] = 2;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[4] = TEST_DRV_VERSION;
	/* unknown type */
	buf[5] = 0;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[5] = 200;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[5] = TEST_DRV_MSG_MGMT;
	/* reserved flags */
	buf[6] = 0x04;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[6] = 0;
	/* invalid link ID */
	buf[7] = MAX_NUM_MLD_LINKS;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[7] = 0xfe;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	buf[7] = TEST_DRV_LINK_ID_NONE;
	/* payload_len field larger than allowed */
	WPA_PUT_LE16(buf + 12, TEST_DRV_MAX_PAYLOAD + 1);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + TEST_DRV_MAX_PAYLOAD +
				 1, &hdr, NULL, NULL) == -1);
	WPA_PUT_LE16(buf + 12, 24);
	/* NULL message with payload */
	buf[5] = TEST_DRV_MSG_NULL;
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN + 24, &hdr, NULL,
				 NULL) == -1);
	WPA_PUT_LE16(buf + 12, 0);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN, &hdr, NULL, NULL) == 0);
	/* NULL pointers */
	CHECK(test_drv_hdr_parse(NULL, TEST_DRV_HDR_LEN, &hdr, NULL, NULL) ==
	      -1);
	CHECK(test_drv_hdr_parse(buf, TEST_DRV_HDR_LEN, NULL, NULL, NULL) ==
	      -1);
}


static void test_sta_instance(void)
{
	const struct wpa_driver_ops *ops = &wpa_driver_test_ops;
	void *global, *priv, *priv2;
	struct wpa_driver_capa capa;
	const u8 *addr, *addr2;
	u8 addr_copy[ETH_ALEN];
	struct hostapd_hw_modes *modes;
	u16 num_modes, flags;
	u8 dfs;
	char alpha2[3];
	struct wpa_driver_set_key_params kp;
	u8 key[64];
	struct wpa_driver_scan_params sp;
	char path[128];
	struct stat st;
	int dummy_ctx = 0, dummy_ctx2 = 0;
	u8 bssid[ETH_ALEN];
	char status[4096];

	printf("sta: init/deinit, capabilities, parameters\n");
	CHECK(os_strcmp(ops->name, "test") == 0);
	global = ops->global_init(NULL);
	CHECK(global != NULL);

	/* invalid interface names are rejected */
	CHECK(ops->init2(&dummy_ctx, "", global, 0) == NULL);
	CHECK(ops->init2(&dummy_ctx,
			 "this-interface-name-is-far-too-long", global,
			 0) == NULL);

	priv = ops->init2(&dummy_ctx, "sta1", global, 0);
	CHECK(priv != NULL);
	if (!priv)
		return;

	/* deterministic, locally administered unicast address derived from
	 * the interface name */
	addr = ops->get_mac_addr(priv);
	CHECK(addr != NULL);
	CHECK((addr[0] & 0x03) == 0x02);
	os_memcpy(addr_copy, addr, ETH_ALEN);
	priv2 = ops->init2(&dummy_ctx2, "sta1", global, 0);
	CHECK(priv2 != NULL);
	if (priv2) {
		addr2 = ops->get_mac_addr(priv2);
		CHECK(os_memcmp(addr, addr2, ETH_ALEN) == 0);
		ops->deinit(priv2);
	}
	priv2 = ops->init2(&dummy_ctx2, "sta2", global, 0);
	CHECK(priv2 != NULL);
	if (priv2) {
		addr2 = ops->get_mac_addr(priv2);
		CHECK(os_memcmp(addr, addr2, ETH_ALEN) != 0);
		ops->deinit(priv2);
	}

	/* capabilities: SME, control port, no netdev */
	CHECK(ops->get_capa(priv, &capa) == 0);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_SME);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_CONTROL_PORT);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_SAE);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_FULL_AP_CLIENT_STATE);
	CHECK(capa.flags2 & WPA_DRIVER_FLAGS2_CONTROL_PORT_RX);
	CHECK(capa.flags2 & WPA_DRIVER_FLAGS2_NO_NETDEV);
	CHECK(capa.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_SAE);
	CHECK(capa.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_OWE);
	CHECK(capa.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_FT);
	CHECK(capa.enc & WPA_DRIVER_CAPA_ENC_BIP_GMAC_256);
	CHECK(capa.max_scan_ssids > 0);

	/* synthetic hardware modes: 2.4 GHz g/b, 5 GHz a, 6 GHz a */
	modes = ops->get_hw_feature_data(priv, &num_modes, &flags, &dfs,
					 alpha2, sizeof(alpha2));
	CHECK(modes != NULL);
	CHECK(num_modes == 4);
	if (modes && num_modes == 4) {
		int i, have_6ghz = 0;

		for (i = 0; i < num_modes; i++) {
			CHECK(modes[i].num_channels > 0);
			CHECK(modes[i].channels != NULL);
			CHECK(modes[i].rates != NULL);
			if (modes[i].is_6ghz) {
				have_6ghz = 1;
				CHECK(modes[i].he_capab[IEEE80211_MODE_AP].
				      he_supported);
				CHECK(modes[i].he_capab[IEEE80211_MODE_AP].
				      he_6ghz_capa != 0);
				CHECK(modes[i].eht_capab[IEEE80211_MODE_AP].
				      eht_supported);
			}
		}
		CHECK(have_6ghz);
		CHECK(modes[0].mode == HOSTAPD_MODE_IEEE80211G);
		CHECK(modes[0].channels[0].freq == 2412);
		CHECK(modes[0].ht_capab != 0);
		CHECK(modes[2].mode == HOSTAPD_MODE_IEEE80211A);
		CHECK(modes[2].vht_capab != 0);
		for (i = 0; i < num_modes; i++) {
			os_free(modes[i].channels);
			os_free(modes[i].rates);
		}
		os_free(modes);
	}

	/* key table bounds */
	os_memset(key, 0x11, sizeof(key));
	os_memset(&kp, 0, sizeof(kp));
	kp.alg = WPA_ALG_CCMP;
	kp.key = key;
	kp.key_len = 16;
	kp.key_idx = 1;
	kp.key_flag = KEY_FLAG_GROUP_RX;
	CHECK(ops->set_key(priv, &kp) == 0);
	kp.key_idx = TEST_DRV_MAX_GROUP_KEYS;
	CHECK(ops->set_key(priv, &kp) == -1);
	kp.key_idx = -1;
	CHECK(ops->set_key(priv, &kp) == -1);
	kp.key_idx = 0;
	kp.key_len = 65;
	CHECK(ops->set_key(priv, &kp) == -1);
	kp.key_len = 0;
	CHECK(ops->set_key(priv, &kp) == -1);
	kp.key_len = 16;
	kp.addr = addr_copy; /* pairwise */
	kp.key_flag = KEY_FLAG_PAIRWISE_RX_TX;
	kp.key_idx = 2;
	CHECK(ops->set_key(priv, &kp) == -1); /* pairwise key idx > 1 */
	kp.key_idx = 0;
	CHECK(ops->set_key(priv, &kp) == 0);
	kp.alg = WPA_ALG_NONE;
	kp.key_len = 0;
	CHECK(ops->set_key(priv, &kp) == 0);

	/* scanning without a configured transport fails cleanly */
	os_memset(&sp, 0, sizeof(sp));
	CHECK(ops->scan2(priv, &sp) == -1);

	/* not associated: zero BSSID, empty SSID */
	CHECK(ops->get_bssid(priv, bssid) == 0);
	CHECK(is_zero_ether_addr(bssid));
	CHECK(ops->get_ssid(priv, key) == 0);

	/* driver parameters: invalid values rejected, valid socket bound */
	CHECK(ops->set_param(priv, "phy=bogus") == -1);
	CHECK(ops->set_param(priv, "test_udp=70000") == -1);
	CHECK(ops->set_param(priv, "test_udp=0") == -1);
	CHECK(ops->set_param(priv, "scan_time=99999999") == -1);
	CHECK(ops->set_param(priv, "no_transport_here=1") == -1);
	os_snprintf(path, sizeof(path), "/tmp/test-driver_test-%d/ap1",
		    (int) getpid());
	{
		char dir[128];
		int res;

		os_snprintf(dir, sizeof(dir), "/tmp/test-driver_test-%d",
			    (int) getpid());
		mkdir(dir, 0700);
		CHECK(ops->set_param(priv, "test_socket=") == -1);
		res = os_snprintf(dir, sizeof(dir),
				  "test_socket=%s phy=ht,he scan_time=50",
				  path);
		CHECK(!os_snprintf_error(sizeof(dir), res));
		CHECK(ops->set_param(priv, dir) == 0);
		os_snprintf(dir, sizeof(dir), "/tmp/test-driver_test-%d/STA-sta1",
			    (int) getpid());
		CHECK(stat(dir, &st) == 0 && S_ISSOCK(st.st_mode));
		/* a scan can now be requested; the AP socket does not exist,
		 * so the probe request send fails but the scan completes */
		CHECK(ops->scan2(priv, &sp) == 0);
		CHECK(ops->scan2(priv, &sp) == -1); /* already scanning */
		CHECK(ops->abort_scan(priv, 0) == 0);

		/* status output is bounded and terminated */
		res = ops->status(priv, status, sizeof(status));
		CHECK(res > 0 && res < (int) sizeof(status));
		CHECK(os_strstr(status, "test_driver_transport=unix") != NULL);
		res = ops->status(priv, status, 10);
		CHECK(res >= 0 && res < 10);

		ops->deinit(priv);
		/* the socket file is removed on deinit */
		CHECK(stat(dir, &st) != 0);
		os_snprintf(dir, sizeof(dir), "/tmp/test-driver_test-%d",
			    (int) getpid());
		rmdir(dir);
	}

	ops->global_deinit(global);
}


static void test_ap_instance(void)
{
	const struct wpa_driver_ops *ops = &wpa_driver_test_ops;
	struct wpa_init_params params;
	u8 own_addr[ETH_ALEN];
	u8 bssid[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0x00 };
	void *global, *priv, *bss2 = NULL;
	char dir[128], drvparams[200], sockpath[160];
	int dummy_hapd = 0, dummy_hapd2 = 0;
	struct wpa_driver_capa capa;
	struct hostapd_sta_add_params sa;
	u8 sta_addr[ETH_ALEN] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
	u8 if_addr[ETH_ALEN];
	char force_ifname[IFNAMSIZ];
	struct stat st;
	u8 ssid[SSID_MAX_LEN + 1];

	printf("ap: init/deinit, BSS add/remove, station table\n");
	global = ops->global_init(NULL);
	CHECK(global != NULL);
	os_snprintf(dir, sizeof(dir), "/tmp/test-driver_test-ap-%d",
		    (int) getpid());
	mkdir(dir, 0700);
	os_snprintf(sockpath, sizeof(sockpath), "%s/ap1", dir);

	/* missing transport parameters fail initialization */
	os_memset(&params, 0, sizeof(params));
	params.ifname = "ap1";
	params.own_addr = own_addr;
	params.global_priv = global;
	params.driver_params = NULL;
	CHECK(ops->hapd_init((void *) &dummy_hapd, &params) == NULL);
	params.driver_params = "test_udp=99999";
	CHECK(ops->hapd_init((void *) &dummy_hapd, &params) == NULL);

	os_snprintf(drvparams, sizeof(drvparams), "test_socket=%s", sockpath);
	params.driver_params = drvparams;
	params.bssid = bssid;
	priv = ops->hapd_init((void *) &dummy_hapd, &params);
	CHECK(priv != NULL);
	if (!priv)
		return;
	CHECK(os_memcmp(own_addr, bssid, ETH_ALEN) == 0);
	CHECK(stat(sockpath, &st) == 0 && S_ISSOCK(st.st_mode));

	/* a second radio cannot bind the same socket path */
	CHECK(ops->hapd_init((void *) &dummy_hapd2, &params) == NULL);
	CHECK(stat(sockpath, &st) == 0); /* the original socket survives */

	CHECK(ops->get_capa(priv, &capa) == 0);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_AP);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_AP_MLME);
	CHECK(capa.flags & WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS);
	CHECK(capa.flags2 & WPA_DRIVER_FLAGS2_NO_NETDEV);
	CHECK(capa.max_stations > 0);

	/* SSID handling */
	os_memset(ssid, 'a', sizeof(ssid));
	CHECK(ops->hapd_set_ssid(priv, ssid, SSID_MAX_LEN + 1) == -1);
	CHECK(ops->hapd_set_ssid(priv, ssid, -1) == -1);
	CHECK(ops->hapd_set_ssid(priv, (const u8 *) "test", 4) == 0);
	CHECK(ops->hapd_get_ssid(priv, ssid, sizeof(ssid)) == 4);
	CHECK(ops->hapd_get_ssid(priv, ssid, 3) == -1);

	/* multi-BSS: add, duplicate, remove, remove primary */
	CHECK(ops->if_add(priv, WPA_IF_AP_BSS, "ap1-2", NULL,
			  (void *) &dummy_hapd2, &bss2, force_ifname, if_addr,
			  NULL, 0, 1) == 0);
	CHECK(bss2 != NULL && bss2 != priv);
	CHECK((if_addr[0] & 0x03) == 0x02);
	CHECK(os_memcmp(if_addr, bssid, ETH_ALEN) != 0);
	CHECK(ops->if_add(priv, WPA_IF_AP_BSS, "ap1-2", NULL,
			  (void *) &dummy_hapd2, &bss2, force_ifname, if_addr,
			  NULL, 0, 1) == -1);
	CHECK(ops->if_add(priv, WPA_IF_STATION, "sta9", NULL, NULL, NULL,
			  force_ifname, if_addr, NULL, 0, 0) == -1);
	CHECK(ops->if_remove(priv, WPA_IF_AP_BSS, "does-not-exist") == -1);
	CHECK(ops->if_remove(priv, WPA_IF_AP_BSS, "ap1") == -1);
	CHECK(ops->if_remove(priv, WPA_IF_AP_BSS, "ap1-2") == 0);

	/* station table */
	os_memset(&sa, 0, sizeof(sa));
	sa.addr = sta_addr;
	sa.aid = 1;
	sa.mld_link_id = -1;
	CHECK(ops->sta_add(priv, &sa) == 0);
	CHECK(ops->sta_set_flags(priv, sta_addr, WPA_STA_AUTHORIZED,
				 WPA_STA_AUTHORIZED, ~0U) == 0);
	CHECK(ops->get_inact_sec(priv, sta_addr) >= 0);
	CHECK(ops->get_inact_sec(priv, bssid) == -1);
	CHECK(ops->sta_remove(priv, sta_addr) == 0);
	CHECK(ops->sta_remove(priv, bssid) == -1);
	CHECK(ops->sta_set_flags(priv, bssid, 0, 0, 0) == -1);
	/* sending to a station without a transport address fails */
	CHECK(ops->hapd_send_eapol(priv, sta_addr, (const u8 *) "\x02\x00\x00\x00",
				   4, 0, bssid, 0, -1) == -1);
	CHECK(ops->flush(priv, -1) == 0);

	/* management frames must be at least a header long */
	CHECK(ops->send_mlme(priv, (const u8 *) "\xc0\x00", 2, 0, 0, NULL, 0,
			     0, 0, -1) == -1);

	ops->hapd_deinit(priv);
	CHECK(stat(sockpath, &st) != 0);

	/* A stale socket file (crashed process) is replaced, while a live
	 * socket (tested above) is not stolen. */
	{
		int stale = socket(PF_UNIX, SOCK_DGRAM, 0);
		struct sockaddr_un sun;

		CHECK(stale >= 0);
		os_memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		os_strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
		CHECK(bind(stale, (struct sockaddr *) &sun, sizeof(sun)) == 0);
		close(stale); /* path stays behind without a listener */
		CHECK(stat(sockpath, &st) == 0 && S_ISSOCK(st.st_mode));
		priv = ops->hapd_init((void *) &dummy_hapd, &params);
		CHECK(priv != NULL);
		if (priv)
			ops->hapd_deinit(priv);
		CHECK(stat(sockpath, &st) != 0);
	}

	rmdir(dir);
	ops->global_deinit(global);
}


int main(int argc, char *argv[])
{
	if (eloop_init()) {
		printf("eloop_init failed\n");
		return 1;
	}
	wpa_debug_level = MSG_INFO;

	test_hdr_roundtrip();
	test_hdr_malformed();
	test_sta_instance();
	test_ap_instance();

	eloop_destroy();
	if (failures) {
		printf("%d test failure(s)\n", failures);
		return 1;
	}
	printf("test-driver_test: all tests passed\n");
	return 0;
}
