/*
 * Testing driver interface for a simulated network driver - wire format
 * Copyright (c) 2004-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This header defines the datagram framing used between hostapd and
 * wpa_supplicant instances that use the "test" driver interface
 * (CONFIG_DRIVER_TEST). Every datagram sent over the local test socket
 * (UNIX domain SOCK_DGRAM or IPv4 UDP bound to the loopback address) starts
 * with struct test_drv_hdr followed by exactly payload_len octets of payload.
 *
 * The format is versioned; a receiver drops any datagram whose magic,
 * version, type, link_id, or length fields are not valid. Nothing in the
 * header is trusted beyond the validation performed in
 * test_drv_hdr_parse().
 */

#ifndef DRIVER_TEST_H
#define DRIVER_TEST_H

#include "utils/common.h"

/* "HTD1" - hostap test driver, framing revision 1 */
#define TEST_DRV_MAGIC_0 'H'
#define TEST_DRV_MAGIC_1 'T'
#define TEST_DRV_MAGIC_2 'D'
#define TEST_DRV_MAGIC_3 '1'

#define TEST_DRV_VERSION 1

/* Maximum payload carried in a single datagram. IEEE 802.11 management
 * frames and EAPOL frames are both well below this bound. */
#define TEST_DRV_MAX_PAYLOAD 4000
#define TEST_DRV_HDR_LEN 16
#define TEST_DRV_MAX_MSG (TEST_DRV_HDR_LEN + TEST_DRV_MAX_PAYLOAD)

/* Link ID value used when the message is not bound to an MLD link */
#define TEST_DRV_LINK_ID_NONE 0xff

/* Number of group key slots tracked per BSS (GTK 0-3, IGTK 4-5, BIGTK 6-7) */
#define TEST_DRV_MAX_GROUP_KEYS 8

enum test_drv_msg_type {
	/* payload: complete IEEE 802.11 management frame starting with the
	 * frame control field; minimum length 24 octets */
	TEST_DRV_MSG_MGMT = 1,
	/* payload: IEEE 802.3 header (dst, src, ethertype) followed by an
	 * EAPOL (or other control port) PDU; minimum length 14 + 4 octets */
	TEST_DRV_MSG_EAPOL = 2,
	/* payload: none; liveness probe for peer detection and client poll */
	TEST_DRV_MSG_NULL = 3,
};

/* Header flags */
/* Frame was "protected" (encrypted) by the sender; the test driver does not
 * implement any cipher, but it tracks key state and uses this flag to mimic
 * the protected/unprotected distinction that a real driver would provide. */
#define TEST_DRV_FLAG_PROTECTED BIT(0)
/* No acknowledgment was requested for this frame */
#define TEST_DRV_FLAG_NOACK BIT(1)

struct test_drv_hdr {
	u8 magic[4];
	u8 version;
	u8 type;
	u8 flags;
	u8 link_id;
	le32 freq; /* operating frequency of the sender in MHz, 0 = unknown */
	le16 payload_len; /* number of octets following the header */
	le16 seq; /* per-sender sequence counter (diagnostics only) */
} STRUCT_PACKED;

/**
 * test_drv_hdr_parse - Validate a received datagram header
 * @buf: Received datagram
 * @len: Length of the datagram in octets
 * @hdr: Buffer for the validated header (host byte order not applied)
 * @payload: Pointer to the payload start on success
 * @payload_len: Payload length on success
 * Returns: 0 on success, -1 if the datagram is not valid
 */
int test_drv_hdr_parse(const u8 *buf, size_t len, struct test_drv_hdr *hdr,
		       const u8 **payload, size_t *payload_len);

/**
 * test_drv_hdr_build - Fill in a datagram header
 * Returns: TEST_DRV_HDR_LEN on success, -1 if payload_len is too large
 */
int test_drv_hdr_build(u8 *buf, size_t buflen, u8 type, u8 flags,
		       int link_id, unsigned int freq, u16 seq,
		       size_t payload_len);

#endif /* DRIVER_TEST_H */
