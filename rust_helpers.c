#include <linux/usb.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/cfg80211.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>

/* Station info flags */
#ifndef STATION_INFO_RX_PACKETS
#define STATION_INFO_RX_PACKETS		(1ULL << 0)
#endif
#ifndef STATION_INFO_TX_PACKETS
#define STATION_INFO_TX_PACKETS		(1ULL << 1)
#endif
#ifndef STATION_INFO_RX_BYTES
#define STATION_INFO_RX_BYTES		(1ULL << 2)
#endif
#ifndef STATION_INFO_TX_BYTES
#define STATION_INFO_TX_BYTES		(1ULL << 3)
#endif
#ifndef STATION_INFO_RX_BITRATE
#define STATION_INFO_RX_BITRATE		(1ULL << 4)
#endif
#ifndef STATION_INFO_TX_BITRATE
#define STATION_INFO_TX_BITRATE		(1ULL << 5)
#endif
#ifndef STATION_INFO_RX_BW_20
#define STATION_INFO_RX_BW_20		(1ULL << 20)
#endif
#ifndef STATION_INFO_RX_BW_40
#define STATION_INFO_RX_BW_40		(1ULL << 21)
#endif
#ifndef STATION_INFO_RX_BW_80
#define STATION_INFO_RX_BW_80		(1ULL << 22)
#endif
#ifndef STATION_INFO_TX_BW_20
#define STATION_INFO_TX_BW_20		(1ULL << 23)
#endif
#ifndef STATION_INFO_TX_BW_40
#define STATION_INFO_TX_BW_40		(1ULL << 24)
#endif
#ifndef STATION_INFO_TX_BW_80
#define STATION_INFO_TX_BW_80		(1ULL << 25)
#endif
#ifndef STATION_INFO_SIGNAL
#define STATION_INFO_SIGNAL		(1ULL << 26)
#endif

/* ---------------------------------------------------------------------------
 * cfg80211 / wiphy helpers
 *
 * wiphy_new, wiphy_priv, and set_wiphy_dev are all inline in cfg80211.h so
 * Rust cannot link to them directly.  Expose them as named symbols here.
 * ---------------------------------------------------------------------------
 */

/* wiphy_new() is itself inline (calls wiphy_new_nm).  Wrap it here. */
struct wiphy *rust_helper_wiphy_new(const struct cfg80211_ops *ops,
				    int sizeof_priv)
{
	return wiphy_new(ops, sizeof_priv);
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_new);

void *rust_helper_wiphy_priv(struct wiphy *wiphy)
{
	return wiphy_priv(wiphy);
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_priv);

void rust_helper_set_wiphy_dev(struct wiphy *wiphy, struct device *dev)
{
	set_wiphy_dev(wiphy, dev);
}
EXPORT_SYMBOL_GPL(rust_helper_set_wiphy_dev);

/* Field setters — let Rust set wiphy fields without needing the struct layout
 * in the generated bindings.
 */
void rust_helper_wiphy_set_interface_modes(struct wiphy *wiphy, u16 modes)
{
	wiphy->interface_modes = modes;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_interface_modes);

void rust_helper_wiphy_set_max_scan_ssids(struct wiphy *wiphy, u8 val)
{
	wiphy->max_scan_ssids = val;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_max_scan_ssids);

void rust_helper_wiphy_set_max_scan_ie_len(struct wiphy *wiphy, u16 val)
{
	wiphy->max_scan_ie_len = val;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_max_scan_ie_len);

void rust_helper_wiphy_set_signal_type(struct wiphy *wiphy,
				       enum cfg80211_signal_type t)
{
	wiphy->signal_type = t;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_signal_type);

void rust_helper_wiphy_set_cipher_suites(struct wiphy *wiphy,
					 const u32 *suites, int n)
{
	wiphy->cipher_suites   = suites;
	wiphy->n_cipher_suites = n;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_cipher_suites);

void rust_helper_wiphy_set_mgmt_stypes(struct wiphy *wiphy,
				       const struct ieee80211_txrx_stypes *stypes)
{
	wiphy->mgmt_stypes = stypes;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_mgmt_stypes);

/* cfg80211_ops — function pointers set by Rust after init */
struct cfg80211_ops r92su_cfg80211_ops = {
	.scan                  = NULL,
	.abort_scan            = NULL,
	.connect               = NULL,
	.disconnect            = NULL,
	.add_key              = NULL,
	.del_key              = NULL,
	.set_default_key      = NULL,
	.get_station          = NULL,
	.dump_station         = NULL,
	.change_virtual_intf  = NULL,
	.join_ibss            = NULL,
	.leave_ibss           = NULL,
	.set_wiphy_params     = NULL,
	.set_monitor_channel  = NULL,
	.mgmt_tx              = NULL,
	.update_mgmt_frame_registrations = NULL,
	.tdls_mgmt = NULL,
	.tdls_oper = NULL,
};

/**
 * rust_helper_set_cfg80211_ops_scan - set the .scan callback
 *
 * Called from Rust to register the scan handler after device init.
 */
void rust_helper_set_cfg80211_ops_scan(int (*scan_fn)(struct wiphy *wiphy,
	struct cfg80211_scan_request *request))
{
	r92su_cfg80211_ops.scan = scan_fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_scan);

/**
 * rust_helper_set_cfg80211_ops_abort_scan - set the .abort_scan callback
 */
void rust_helper_set_cfg80211_ops_abort_scan(void (*abort_fn)(struct wiphy *wiphy,
	struct wireless_dev *wdev))
{
	r92su_cfg80211_ops.abort_scan = abort_fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_abort_scan);

/**
 * rust_helper_cfg80211_scan_done - notify cfg80211 that scan is complete
 *
 * @request: the scan request that was provided to the .scan callback
 * @aborted: true if the scan was aborted
 */
void rust_helper_cfg80211_scan_done(struct cfg80211_scan_request *request,
	bool aborted)
{
	struct cfg80211_scan_info info = {
		.aborted = aborted,
	};

	cfg80211_scan_done(request, &info);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_scan_done);

/**
 * rust_helper_cfg80211_inform_bss_data - inform cfg80211 of a discovered BSS
 *
 * This is a wrapper around cfg80211_inform_bss_data for use by Rust code.
 */
struct cfg80211_bss *rust_helper_cfg80211_inform_bss_data(
	struct wiphy *wiphy,
	struct ieee80211_channel *channel,
	const u8 *bssid,
	u64 tsf,
	u16 capability,
	u16 beacon_interval,
	const u8 *ie,
	size_t ielen,
	gfp_t gfp)
{
	struct cfg80211_inform_bss data = {
		.chan = channel,
		.signal = 0, /* will be set from RSSI in the BSS data */
	};

	return cfg80211_inform_bss_data(wiphy, &data,
		CFG80211_BSS_FTYPE_BEACON, bssid, tsf,
		capability, beacon_interval, ie, ielen, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_inform_bss_data);

/**
 * rust_helper_cfg80211_put_bss - release BSS reference
 */
void rust_helper_cfg80211_put_bss(struct wiphy *wiphy, struct cfg80211_bss *bss)
{
	cfg80211_put_bss(wiphy, bss);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_put_bss);

/**
 * rust_helper_ieee80211_channel_to_frequency - convert channel to frequency
 */
int rust_helper_ieee80211_channel_to_frequency(int chan, int band)
{
	return ieee80211_channel_to_frequency(chan, band);
}
EXPORT_SYMBOL_GPL(rust_helper_ieee80211_channel_to_frequency);

/* ---------------------------------------------------------------------------
 * 2.4 GHz band tables (mirrors r92su_channeltable / r92su_ratetable in
 * the C reference driver).  These are shared across all probed devices;
 * only the per-device ht_cap fields differ.
 * ---------------------------------------------------------------------------
 */
static struct ieee80211_channel r92su_channels_2ghz[] = {
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2412, .hw_value =  1 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2417, .hw_value =  2 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2422, .hw_value =  3 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2427, .hw_value =  4 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2432, .hw_value =  5 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2437, .hw_value =  6 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2442, .hw_value =  7 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2447, .hw_value =  8 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2452, .hw_value =  9 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2457, .hw_value = 10 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2462, .hw_value = 11 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2467, .hw_value = 12 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2472, .hw_value = 13 },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2484, .hw_value = 14 },
};

/* 802.11b/g rates: 1, 2, 5.5, 11 Mbps (CCK) + 6..54 Mbps (OFDM). */
static struct ieee80211_rate r92su_rates_2ghz[] = {
	{ .bitrate = 10,  .hw_value =  0 },
	{ .bitrate = 20,  .hw_value =  1 },
	{ .bitrate = 55,  .hw_value =  2 },
	{ .bitrate = 110, .hw_value =  3 },
	{ .bitrate = 60,  .hw_value =  4 },
	{ .bitrate = 90,  .hw_value =  5 },
	{ .bitrate = 120, .hw_value =  6 },
	{ .bitrate = 180, .hw_value =  7 },
	{ .bitrate = 240, .hw_value =  8 },
	{ .bitrate = 360, .hw_value =  9 },
	{ .bitrate = 480, .hw_value = 10 },
	{ .bitrate = 540, .hw_value = 11 },
};

/*
 * rust_helper_sizeof_band_2ghz — total size of the wiphy private area.
 *
 * The layout is:
 *   [void *dev_ptr][struct ieee80211_supported_band band]
 *
 * The first sizeof(void *) bytes hold a pointer to the Rust R92suDevice
 * written by r92su_alloc() after heap-allocating the device.  Callbacks
 * recover the device via rust_helper_wiphy_priv() → offset 0.
 *
 * The band struct follows immediately and is used by
 * rust_helper_wiphy_set_band_2ghz().
 */
int rust_helper_sizeof_band_2ghz(void)
{
	return (int)(sizeof(void *) + sizeof(struct ieee80211_supported_band));
}
EXPORT_SYMBOL_GPL(rust_helper_sizeof_band_2ghz);

/*
 * rust_helper_wiphy_set_band_2ghz — initialise 2.4 GHz band in the wiphy
 * private area and assign wiphy->bands[NL80211_BAND_2GHZ].
 *
 * Mirrors r92su_init_band() from main.c:
 *   band->channels  = r92su_channeltable;
 *   band->bitrates  = r92su_ratetable;
 *   memcpy(&band->ht_cap, &r92su_ht_info, ...);
 *   band->ht_cap.ht_supported = !r92su->disable_ht;
 *   wiphy->bands[NL80211_BAND_2GHZ] = band;
 *
 * Must be called after wiphy_new() with sizeof_priv >=
 * rust_helper_sizeof_band_2ghz().  The band struct is placed at
 * offset sizeof(void *) inside the private area, after the device pointer.
 */
void rust_helper_wiphy_set_band_2ghz(struct wiphy *wiphy,
				      bool ht_supported,
				      u8 rx_mask_1,
				      u16 rx_highest)
{
	/* Band struct lives after the device self-pointer slot. */
	struct ieee80211_supported_band *band =
		(struct ieee80211_supported_band *)
		((char *)wiphy_priv(wiphy) + sizeof(void *));

	memset(band, 0, sizeof(*band));

	band->band       = NL80211_BAND_2GHZ;
	band->channels   = r92su_channels_2ghz;
	band->n_channels = ARRAY_SIZE(r92su_channels_2ghz);
	band->bitrates   = r92su_rates_2ghz;
	band->n_bitrates = ARRAY_SIZE(r92su_rates_2ghz);

	band->ht_cap.ht_supported = ht_supported;
	if (ht_supported) {
		/* Mirrors r92su_ht_info from the C reference driver. */
		band->ht_cap.cap =
			IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
			IEEE80211_HT_CAP_SGI_40 |
			IEEE80211_HT_CAP_SGI_20 |
			IEEE80211_HT_CAP_DSSSCCK40 |
			IEEE80211_HT_CAP_SM_PS;
		band->ht_cap.ampdu_factor  = IEEE80211_HT_MAX_AMPDU_8K;
		band->ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE;
		band->ht_cap.mcs.rx_mask[0] = 0xff;
		band->ht_cap.mcs.rx_mask[1] = rx_mask_1;
		band->ht_cap.mcs.rx_highest = cpu_to_le16(rx_highest);
		band->ht_cap.mcs.tx_params  = IEEE80211_HT_MCS_TX_DEFINED;
	}

	wiphy->bands[NL80211_BAND_2GHZ] = band;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_set_band_2ghz);

/*
 * rust_helper_wiphy_get_channel - get ieee80211_channel by channel number.
 *
 * Looks up the channel from wiphy->bands[NL80211_BAND_2GHZ] by hw_value (channel number).
 * Returns NULL if not found.
 */
struct ieee80211_channel *rust_helper_wiphy_get_channel(struct wiphy *wiphy, u8 ch_num)
{
	struct ieee80211_supported_band *band;
	struct ieee80211_channel *chan;
	size_t i;

	band = wiphy->bands[NL80211_BAND_2GHZ];
	if (!band)
		return NULL;

	for (i = 0; i < band->n_channels; i++) {
		chan = &band->channels[i];
		if (chan->hw_value == ch_num)
			return chan;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(rust_helper_wiphy_get_channel);

/**
 * rust_helper_usb_bulk_out - synchronous bulk-out to a given endpoint.
 *
 * Wraps usb_bulk_msg() + usb_sndbulkpipe() so that Rust code does not need
 * access to the usb_sndbulkpipe() macro.
 *
 * Returns the usb_bulk_msg() return value (0 on success, negative errno on
 * error).  *actual_length is set to the number of bytes transferred.
 */
int rust_helper_usb_bulk_out(struct usb_device *udev,
			      unsigned int endpoint,
			      void *data, int len,
			      int *actual_length, int timeout_ms)
{
	return usb_bulk_msg(udev, usb_sndbulkpipe(udev, endpoint),
			    data, len, actual_length, timeout_ms);
}
EXPORT_SYMBOL_GPL(rust_helper_usb_bulk_out);

void rust_helper_usb_fill_bulk_urb(
    struct urb *urb,
    struct usb_device *dev,
    unsigned int pipe,
    void *transfer_buffer,
    int buffer_length,
    usb_complete_t complete_fn,
    void *context)
{
    usb_fill_bulk_urb(urb, dev, pipe, transfer_buffer,
                      buffer_length, complete_fn, context);
}
EXPORT_SYMBOL_GPL(rust_helper_usb_fill_bulk_urb);


 unsigned int rust_helper_usb_rcvbulkpipe(struct usb_device *dev, unsigned int endpoint)
 {
     return usb_rcvbulkpipe(dev, endpoint);
 }
 EXPORT_SYMBOL_GPL(rust_helper_usb_rcvbulkpipe);

 unsigned int rust_helper_usb_sndbulkpipe(struct usb_device *dev, unsigned int endpoint)
 {
     return usb_sndbulkpipe(dev, endpoint);
 }
 EXPORT_SYMBOL_GPL(rust_helper_usb_sndbulkpipe);

 unsigned int rust_helper_usb_rcvintpipe(struct usb_device *dev, unsigned int endpoint)
 {
     return usb_rcvintpipe(dev, endpoint);
 }
 EXPORT_SYMBOL_GPL(rust_helper_usb_rcvintpipe);

 unsigned int rust_helper_usb_sndctrlpipe(struct usb_device *dev, unsigned int endpoint)
 {
     return usb_sndctrlpipe(dev, endpoint);
 }
 EXPORT_SYMBOL_GPL(rust_helper_usb_sndctrlpipe);

 unsigned int rust_helper_usb_rcvctrlpipe(struct usb_device *dev, unsigned int endpoint)
 {
     return usb_rcvctrlpipe(dev, endpoint);
 }
 EXPORT_SYMBOL_GPL(rust_helper_usb_rcvctrlpipe);

/* ---------------------------------------------------------------------------
 * USB interface device accessor
 * ---------------------------------------------------------------------------
 */

/**
 * rust_helper_usb_intf_dev - return &intf->dev from a usb_interface pointer.
 *
 * @intf: the USB interface
 *
 * Used by Rust code to obtain the struct device * needed for set_wiphy_dev()
 * and SET_NETDEV_DEV() without requiring the full usb_interface layout in
 * the generated bindings.
 */
struct device *rust_helper_usb_intf_dev(struct usb_interface *intf)
{
	return &intf->dev;
}
EXPORT_SYMBOL_GPL(rust_helper_usb_intf_dev);

/* ---------------------------------------------------------------------------
 * wireless_dev helpers
 *
 * struct wireless_dev is opaque to Rust because cfg80211.h is not part of the
 * Rust kernel bindings.  Allocate and free it here via kzalloc/kfree.
 * ---------------------------------------------------------------------------
 */

/**
 * rust_helper_alloc_wdev - allocate and initialise a wireless_dev.
 *
 * @wiphy:  the wiphy this interface belongs to
 * @iftype: NL80211_IFTYPE_* value (e.g. NL80211_IFTYPE_STATION = 2)
 *
 * Mirrors the wdev initialisation performed inside r92su_alloc():
 *   r92su->wdev.wiphy  = wiphy;
 *   r92su->wdev.iftype = NL80211_IFTYPE_STATION;
 *
 * Returns a pointer to the new wireless_dev on success, NULL on -ENOMEM.
 * The caller owns the allocation; free with rust_helper_free_wdev().
 */
struct wireless_dev *rust_helper_alloc_wdev(struct wiphy *wiphy, u32 iftype)
{
	struct wireless_dev *wdev = kzalloc(sizeof(*wdev), GFP_KERNEL);

	if (!wdev)
		return NULL;
	wdev->wiphy  = wiphy;
	wdev->iftype = (enum nl80211_iftype)iftype;
	return wdev;
}
EXPORT_SYMBOL_GPL(rust_helper_alloc_wdev);

/**
 * rust_helper_free_wdev - free a wireless_dev allocated by rust_helper_alloc_wdev.
 *
 * Must only be called after unregister_netdev() has returned (so that cfg80211
 * has cleared its reference to the wdev) and before wiphy_free().
 */
void rust_helper_free_wdev(struct wireless_dev *wdev)
{
	kfree(wdev);
}
EXPORT_SYMBOL_GPL(rust_helper_free_wdev);

/* ---------------------------------------------------------------------------
 * net_device helpers
 *
 * Mirrors r92su_if_setup() and r92su_alloc_netdev() from main.c.
 * ---------------------------------------------------------------------------
 */

/*
 * TX head-room required by the RTL8192SU TX descriptor format.
 *
 * Mirrors R92SU_TX_HEAD_ROOM from r92su.h:
 *   TX_DESC_SIZE(32) + 4 (align) + 4*ETH_ALEN (mac addrs) +
 *   2+2+2+2 (fc/seq/dur/qos) + 8+8 (rfc1042 + IV) - ETH_HLEN(14)
 */
#define R92SU_TX_HEAD_ROOM 70

/* TX tail-room: TKIP/CCMP MIC (8) + ICV (4). */
#define R92SU_TX_TAIL_ROOM 12

/* Number of 802.11e Access Category TX queues (BK, BE, VI, VO). */
#define R92SU_NUM_ACS 4

static netdev_tx_t r92su_stub_start_xmit(struct sk_buff *skb,
					  struct net_device *ndev)
{
	/* TX path not yet implemented — drop all frames. */
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/*
 * rust_helper_set_ndo_open - register the Rust ndo_open handler.
 *
 * Called once during probe.  The handler receives the R92suDevice pointer
 * recovered from the wiphy private area (offset 0).
 */
static int (*r92su_ndo_open_fn)(void *dev_ptr);

void rust_helper_set_ndo_open(int (*fn_ptr)(void *dev_ptr))
{
	r92su_ndo_open_fn = fn_ptr;
}
EXPORT_SYMBOL_GPL(rust_helper_set_ndo_open);

static int r92su_ndo_open(struct net_device *ndev)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	void *dev_ptr;

	if (!wdev || !wdev->wiphy)
		return -ENODEV;
	/* Device pointer is stored at offset 0 of the wiphy private area. */
	dev_ptr = *(void **)wiphy_priv(wdev->wiphy);
	if (!dev_ptr || !r92su_ndo_open_fn)
		return -ENODEV;
	return r92su_ndo_open_fn(dev_ptr);
}

/* Forward declarations for functions defined later in this file. */
static int r92su_ndo_stop_impl(struct net_device *ndev);
static netdev_tx_t r92su_ndo_start_xmit_dispatch(struct sk_buff *skb,
						  struct net_device *ndev);

static const struct net_device_ops r92su_netdev_ops = {
	.ndo_open            = r92su_ndo_open,
	.ndo_stop            = r92su_ndo_stop_impl,
	.ndo_start_xmit      = r92su_ndo_start_xmit_dispatch,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_validate_addr   = eth_validate_addr,
};

static void r92su_if_setup(struct net_device *ndev)
{
	ether_setup(ndev);
	ndev->priv_flags     &= ~IFF_TX_SKB_SHARING;
	ndev->netdev_ops      = &r92su_netdev_ops;
	ndev->needed_headroom = R92SU_TX_HEAD_ROOM;
	ndev->needed_tailroom = R92SU_TX_TAIL_ROOM;
	ndev->flags          |= IFF_BROADCAST | IFF_MULTICAST;
	ndev->watchdog_timeo  = 5 * HZ;
	/* The kernel frees the net_device when the last reference is dropped. */
	ndev->needs_free_netdev = true;
}

/**
 * rust_helper_alloc_netdev - allocate a net_device and link it to @wdev.
 *
 * @wdev:     the wireless_dev allocated by rust_helper_alloc_wdev()
 * @parent:   &intf->dev of the USB interface (for SET_NETDEV_DEV)
 * @mac_addr: 6-byte permanent MAC address (copied from EEPROM)
 *
 * Mirrors r92su_alloc_netdev() from main.c:
 *   ndev = alloc_netdev_mqs(0, "wlan%d", NET_NAME_UNKNOWN,
 *                            r92su_if_setup, NUM_ACS, 1);
 *   ndev->ieee80211_ptr = wdev;
 *   wdev->netdev        = ndev;
 *   SET_NETDEV_DEV(ndev, wiphy_dev(r92su->wdev.wiphy));
 *   eth_hw_addr_set(ndev, mac_addr);
 *
 * Returns the net_device pointer on success, NULL on -ENOMEM.
 * After a successful call the caller must eventually call either
 * rust_helper_register_netdev() (and later rust_helper_unregister_netdev())
 * or rust_helper_free_netdev() if registration is never attempted.
 */
struct net_device *rust_helper_alloc_netdev(struct wireless_dev *wdev,
					     struct device *parent,
					     const u8 *mac_addr)
{
	struct net_device *ndev;

	ndev = alloc_netdev_mqs(0, "wlan%d", NET_NAME_UNKNOWN,
				r92su_if_setup, R92SU_NUM_ACS, 1);
	if (!ndev)
		return NULL;

	ndev->ieee80211_ptr = wdev;
	wdev->netdev        = ndev;
	SET_NETDEV_DEV(ndev, parent);
	eth_hw_addr_set(ndev, mac_addr);
	return ndev;
}
EXPORT_SYMBOL_GPL(rust_helper_alloc_netdev);

/**
 * rust_helper_register_netdev - register_netdev wrapper.
 *
 * Registers the net_device with the kernel networking stack and exposes it
 * to userspace as "wlanN".  Also causes cfg80211 to register the associated
 * wireless_dev.
 *
 * Returns 0 on success, negative errno on failure.
 */
int rust_helper_register_netdev(struct net_device *ndev)
{
	return register_netdev(ndev);
}
EXPORT_SYMBOL_GPL(rust_helper_register_netdev);

/**
 * rust_helper_unregister_netdev - unregister_netdev wrapper.
 *
 * Removes the net_device from the kernel networking stack.  After this
 * returns, cfg80211 has cleared its reference to the wdev.  If
 * needs_free_netdev is true (set by r92su_if_setup), the kernel will
 * release the net_device allocation when its refcount drops to zero.
 */
void rust_helper_unregister_netdev(struct net_device *ndev)
{
	unregister_netdev(ndev);
}
EXPORT_SYMBOL_GPL(rust_helper_unregister_netdev);

/**
 * rust_helper_free_netdev - free_netdev wrapper.
 *
 * Called for net_devices that were allocated but never registered.
 * For registered devices the kernel calls free_netdev automatically
 * through the needs_free_netdev / priv_destructor mechanism.
 */
void rust_helper_free_netdev(struct net_device *ndev)
{
	free_netdev(ndev);
}
EXPORT_SYMBOL_GPL(rust_helper_free_netdev);

/* ---------------------------------------------------------------------------
 * RX URB infrastructure
 *
 * Allocates and submits bulk-in URBs so the driver can receive C2H firmware
 * events (Survey, SurveyDone, etc.).  The completion handler calls back into
 * Rust via the registered rx_fn, then resubmits the URB to keep the pipe open.
 * ---------------------------------------------------------------------------
 */

#define R92SU_MAX_RX_URBS  8
#define R92SU_RX_BUF_SIZE  32768

static void (*r92su_rx_fn)(void *dev_ptr, const u8 *data, size_t len);
static void *r92su_rx_dev_ptr;

/* Forward declaration needed because submit calls kill on error. */
void rust_helper_kill_rx_urbs(void);

struct r92su_rx_ctx {
	struct urb *urb;
	u8 *buf;
};
static struct r92su_rx_ctx r92su_rx_urb_pool[R92SU_MAX_RX_URBS];
static int r92su_n_rx_urbs;

static void r92su_bulk_in_complete(struct urb *urb)
{
	struct r92su_rx_ctx *ctx = urb->context;

	if (urb->status == 0 && urb->actual_length > 0 && r92su_rx_fn)
		r92su_rx_fn(r92su_rx_dev_ptr, ctx->buf, urb->actual_length);

	/* Resubmit unless the device is being torn down. */
	if (urb->status != -ENOENT && urb->status != -ESHUTDOWN &&
	    urb->status != -EPROTO)
		usb_submit_urb(urb, GFP_ATOMIC);
}

/**
 * rust_helper_set_rx_fn - register the Rust RX data callback.
 *
 * @fn_ptr:  called from the bulk-in completion with (dev_ptr, data, len)
 * @dev_ptr: opaque R92suDevice pointer forwarded to every @fn_ptr call
 *
 * Must be called before rust_helper_submit_rx_urbs().
 */
void rust_helper_set_rx_fn(void (*fn_ptr)(void *dev_ptr, const u8 *data,
					   size_t len),
			    void *dev_ptr)
{
	r92su_rx_fn     = fn_ptr;
	r92su_rx_dev_ptr = dev_ptr;
}
EXPORT_SYMBOL_GPL(rust_helper_set_rx_fn);

/**
 * rust_helper_submit_rx_urbs - allocate and submit bulk-in URBs.
 *
 * @udev:     the USB device
 * @endpoint: bEndpointAddress of the bulk-in endpoint (direction bit set)
 * @n_urbs:   number of URBs to submit (capped at R92SU_MAX_RX_URBS)
 *
 * Returns 0 on success, negative errno if any URB could not be submitted.
 * On partial failure the successfully submitted URBs remain active.
 */
int rust_helper_submit_rx_urbs(struct usb_device *udev, u8 endpoint, int n_urbs)
{
	int i, err;
	unsigned int pipe;

	if (n_urbs > R92SU_MAX_RX_URBS)
		n_urbs = R92SU_MAX_RX_URBS;

	/* Strip the direction bit: usb_rcvbulkpipe wants the endpoint number. */
	pipe = usb_rcvbulkpipe(udev, endpoint & USB_ENDPOINT_NUMBER_MASK);

	r92su_n_rx_urbs = 0;
	for (i = 0; i < n_urbs; i++) {
		struct r92su_rx_ctx *ctx = &r92su_rx_urb_pool[i];

		ctx->buf = kmalloc(R92SU_RX_BUF_SIZE, GFP_KERNEL);
		if (!ctx->buf) {
			err = -ENOMEM;
			goto err_cleanup;
		}

		ctx->urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!ctx->urb) {
			kfree(ctx->buf);
			ctx->buf = NULL;
			err = -ENOMEM;
			goto err_cleanup;
		}

		usb_fill_bulk_urb(ctx->urb, udev, pipe,
				  ctx->buf, R92SU_RX_BUF_SIZE,
				  r92su_bulk_in_complete, ctx);

		err = usb_submit_urb(ctx->urb, GFP_KERNEL);
		if (err) {
			usb_free_urb(ctx->urb);
			ctx->urb = NULL;
			kfree(ctx->buf);
			ctx->buf = NULL;
			goto err_cleanup;
		}
		r92su_n_rx_urbs++;
	}
	return 0;

err_cleanup:
	rust_helper_kill_rx_urbs();
	return err;
}
EXPORT_SYMBOL_GPL(rust_helper_submit_rx_urbs);

/**
 * rust_helper_kill_rx_urbs - cancel and free all active RX URBs.
 *
 * Safe to call even if no URBs were submitted.  Called on device disconnect.
 */
void rust_helper_kill_rx_urbs(void)
{
	int i;

	for (i = 0; i < r92su_n_rx_urbs; i++) {
		struct r92su_rx_ctx *ctx = &r92su_rx_urb_pool[i];

		if (ctx->urb) {
			usb_kill_urb(ctx->urb);
			usb_free_urb(ctx->urb);
			ctx->urb = NULL;
		}
		kfree(ctx->buf);
		ctx->buf = NULL;
	}
	r92su_n_rx_urbs = 0;
	r92su_rx_fn      = NULL;
	r92su_rx_dev_ptr = NULL;
}
EXPORT_SYMBOL_GPL(rust_helper_kill_rx_urbs);

/* ---------------------------------------------------------------------------
 * TX URB infrastructure
 *
 * Submits bulk-out URBs for transmitting frames.  The completion handler calls
 * back into Rust via the registered tx_complete_fn, then triggers the TX
 * scheduler to submit the next pending URB.
 * ---------------------------------------------------------------------------
 */

#define R92SU_MAX_TX_URBS  16
#define R92SU_TX_BUF_SIZE  32768

struct r92su_tx_ctx {
	struct urb *urb;
	u8 *buf;
};

static struct r92su_tx_ctx r92su_tx_urb_pool[R92SU_MAX_TX_URBS];
static int r92su_n_tx_urbs;

static void (*r92su_tx_complete_fn)(void *dev_ptr);
static void *r92su_tx_dev_ptr;

/**
 * r92su_tx_complete - URB completion handler for TX.
 *
 * Calls the registered completion callback (if any), then re-arms the TX
 * scheduler to submit the next pending URB.
 */
static void r92su_tx_complete(struct urb *urb)
{
	struct r92su_tx_ctx *ctx = urb->context;

	if (r92su_tx_complete_fn)
		r92su_tx_complete_fn(r92su_tx_dev_ptr);

	usb_free_urb(urb);
	kfree(ctx->buf);
	ctx->urb = NULL;
	ctx->buf = NULL;
}

/**
 * rust_helper_netif_tx_wake_all_queues - wake all TX queues on a net_device.
 *
 * Called from the TX completion handler when pending URBs drop below the
 * threshold, allowing the network stack to resume transmitting.
 */
void rust_helper_netif_tx_wake_all_queues(struct net_device *ndev)
{
	netif_tx_wake_all_queues(ndev);
}
EXPORT_SYMBOL_GPL(rust_helper_netif_tx_wake_all_queues);

/**
 * rust_helper_set_tx_complete_fn - register the TX completion callback.
 *
 * @fn_ptr:  called from TX URB completion with (dev_ptr)
 * @dev_ptr: opaque R92suDevice pointer forwarded to every @fn_ptr call
 */
void rust_helper_set_tx_complete_fn(void (*fn_ptr)(void *dev_ptr),
				    void *dev_ptr)
{
	r92su_tx_complete_fn   = fn_ptr;
	r92su_tx_dev_ptr       = dev_ptr;
}
EXPORT_SYMBOL_GPL(rust_helper_set_tx_complete_fn);

/**
 * rust_helper_submit_one_tx_urb - submit a single TX URB.
 *
 * @udev:     the USB device
 * @endpoint: bEndpointAddress of the bulk-out endpoint (direction bit set)
 * @data:     data to transmit
 * @len:      length of data
 *
 * Returns 0 on success, negative errno on failure.
 */
int rust_helper_submit_one_tx_urb(struct usb_device *udev, u8 endpoint,
				  const u8 *data, size_t len)
{
	struct r92su_tx_ctx *ctx = NULL;
	int i, err;
	unsigned int pipe;

	/* Find an available slot in the pool. */
	for (i = 0; i < R92SU_MAX_TX_URBS; i++) {
		if (!r92su_tx_urb_pool[i].urb)
			break;
	}
	if (i >= R92SU_MAX_TX_URBS)
		return -ENOMEM;

	ctx = &r92su_tx_urb_pool[i];

	ctx->buf = kmalloc(len, GFP_ATOMIC);
	if (!ctx->buf)
		return -ENOMEM;

	memcpy(ctx->buf, data, len);

	ctx->urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!ctx->urb) {
		kfree(ctx->buf);
		ctx->buf = NULL;
		return -ENOMEM;
	}

	pipe = usb_sndbulkpipe(udev, endpoint & USB_ENDPOINT_NUMBER_MASK);
	usb_fill_bulk_urb(ctx->urb, udev, pipe,
			  ctx->buf, len, r92su_tx_complete, ctx);

	err = usb_submit_urb(ctx->urb, GFP_ATOMIC);
	if (err) {
		usb_free_urb(ctx->urb);
		ctx->urb = NULL;
		kfree(ctx->buf);
		ctx->buf = NULL;
		return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(rust_helper_submit_one_tx_urb);

/**
 * rust_helper_kill_tx_urbs - cancel all pending TX URBs.
 *
 * Safe to call even if no URBs were submitted.  Called on device disconnect.
 */
void rust_helper_kill_tx_urbs(void)
{
	int i;

	for (i = 0; i < R92SU_MAX_TX_URBS; i++) {
		struct r92su_tx_ctx *ctx = &r92su_tx_urb_pool[i];

		if (ctx->urb) {
			usb_kill_urb(ctx->urb);
			usb_free_urb(ctx->urb);
			ctx->urb = NULL;
		}
		kfree(ctx->buf);
		ctx->buf = NULL;
	}
	r92su_tx_complete_fn = NULL;
	r92su_tx_dev_ptr    = NULL;
}
EXPORT_SYMBOL_GPL(rust_helper_kill_tx_urbs);

/* ---------------------------------------------------------------------------
 * TX path — ndo_start_xmit dispatch to Rust
 * ---------------------------------------------------------------------------
 */

static netdev_tx_t (*r92su_ndo_start_xmit_fn)(void *dev_ptr,
					       const u8 *data, size_t len);

/**
 * rust_helper_set_ndo_start_xmit - register the Rust ndo_start_xmit handler.
 */
void rust_helper_set_ndo_start_xmit(
	netdev_tx_t (*fn_ptr)(void *dev_ptr, const u8 *data, size_t len))
{
	r92su_ndo_start_xmit_fn = fn_ptr;
}
EXPORT_SYMBOL_GPL(rust_helper_set_ndo_start_xmit);

/* ---------------------------------------------------------------------------
 * ndo_stop — device close
 * ---------------------------------------------------------------------------
 */

static int (*r92su_ndo_stop_fn)(void *dev_ptr);

/**
 * rust_helper_set_ndo_stop - register the Rust ndo_stop handler.
 */
void rust_helper_set_ndo_stop(int (*fn_ptr)(void *dev_ptr))
{
	r92su_ndo_stop_fn = fn_ptr;
}
EXPORT_SYMBOL_GPL(rust_helper_set_ndo_stop);

static int r92su_ndo_stop_impl(struct net_device *ndev)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	void *dev_ptr;

	if (!wdev || !wdev->wiphy)
		return 0;
	dev_ptr = *(void **)wiphy_priv(wdev->wiphy);
	if (!dev_ptr || !r92su_ndo_stop_fn)
		return 0;
	return r92su_ndo_stop_fn(dev_ptr);
}

/* ---------------------------------------------------------------------------
 * Update net_device_ops with real TX/stop handlers
 *
 * We replace the stub implementations by registering the real callbacks.
 * Since r92su_netdev_ops is const we use a separate ops struct that is
 * populated at runtime after the Rust callbacks are registered.
 * ---------------------------------------------------------------------------
 */

static netdev_tx_t r92su_ndo_start_xmit_dispatch(struct sk_buff *skb,
						  struct net_device *ndev)
{
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	void *dev_ptr;

	if (!wdev || !wdev->wiphy)
		goto drop;
	dev_ptr = *(void **)wiphy_priv(wdev->wiphy);
	if (!dev_ptr || !r92su_ndo_start_xmit_fn)
		goto drop;

	/* Pass the raw Ethernet frame (skb->data, skb->len) to Rust.
	 * The Rust handler is responsible for converting it to 802.11 and
	 * submitting it via the USB bulk-out endpoint.              */
	r92su_ndo_start_xmit_fn(dev_ptr, skb->data, skb->len);
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;

drop:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/* ---------------------------------------------------------------------------
 * RX delivery — 802.11 frame → 802.3 → netif_rx
 * ---------------------------------------------------------------------------
 */

/**
 * rust_helper_rx_deliver_80211 - deliver a 802.11 data frame to the network stack.
 *
 * @ndev:     the net_device to receive on
 * @data:     raw 802.11 frame bytes (including header, excluding FCS)
 * @len:      frame length in bytes
 *
 * Allocates an sk_buff, converts the 802.11 frame to Ethernet format via
 * ieee80211_data_to_8023(), then calls netif_rx().
 *
 * Returns 0 on success, negative errno on failure (frame is dropped).
 */
int rust_helper_rx_deliver_80211(struct net_device *ndev,
				  const u8 *data, size_t len)
{
	struct sk_buff *skb;
	int ret;

	skb = dev_alloc_skb(len + NET_IP_ALIGN);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, NET_IP_ALIGN);
	skb_put_data(skb, data, len);
	skb->dev = ndev;

	ret = ieee80211_data_to_8023(skb, ndev->dev_addr,
				     NL80211_IFTYPE_STATION);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	skb->protocol = eth_type_trans(skb, ndev);
	ndev->stats.rx_packets++;
	ndev->stats.rx_bytes += skb->len;
	netif_rx(skb);
	return 0;
}
EXPORT_SYMBOL_GPL(rust_helper_rx_deliver_80211);

/* ---------------------------------------------------------------------------
 * cfg80211 ops setters — connect / disconnect / key management
 * ---------------------------------------------------------------------------
 */

/**
 * rust_helper_set_cfg80211_ops_connect - set the .connect callback.
 */
void rust_helper_set_cfg80211_ops_connect(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  struct cfg80211_connect_params *sme))
{
	r92su_cfg80211_ops.connect = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_connect);

/**
 * rust_helper_set_cfg80211_ops_disconnect - set the .disconnect callback.
 */
void rust_helper_set_cfg80211_ops_disconnect(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev, u16 reason))
{
	r92su_cfg80211_ops.disconnect = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_disconnect);

/**
 * rust_helper_set_cfg80211_ops_add_key - set the .add_key callback.
 */
void rust_helper_set_cfg80211_ops_add_key(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  int link_id, u8 key_index, bool pairwise,
		  const u8 *mac_addr, struct key_params *params))
{
	r92su_cfg80211_ops.add_key = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_add_key);

/**
 * rust_helper_set_cfg80211_ops_del_key - set the .del_key callback.
 */
void rust_helper_set_cfg80211_ops_del_key(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  int link_id, u8 key_index, bool pairwise,
		  const u8 *mac_addr))
{
	r92su_cfg80211_ops.del_key = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_del_key);

/**
 * rust_helper_set_cfg80211_ops_set_default_key - set the .set_default_key callback.
 */
void rust_helper_set_cfg80211_ops_set_default_key(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  int link_id, u8 key_index, bool unicast, bool multicast))
{
	r92su_cfg80211_ops.set_default_key = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_set_default_key);

/**
 * rust_helper_key_params_get - extract key_params fields for Rust.
 *
 * Copies cipher suite, key data and seq data from a cfg80211 key_params
 * struct into caller-supplied buffers.  Returns 0 on success, -EINVAL if the
 * key or seq data exceeds the supplied buffer sizes.
 */
int rust_helper_key_params_get(const struct key_params *params,
				u32 *cipher_out,
				u8 *key_out, size_t *key_len_out, size_t key_buf_len,
				u8 *seq_out, size_t *seq_len_out, size_t seq_buf_len)
{
	if (params->key_len > key_buf_len)
		return -EINVAL;
	if (params->seq_len > seq_buf_len)
		return -EINVAL;

	*cipher_out  = params->cipher;
	*key_len_out = params->key_len;
	if (params->key && params->key_len)
		memcpy(key_out, params->key, params->key_len);
	else
		*key_len_out = 0;

	*seq_len_out = params->seq_len;
	if (params->seq && params->seq_len)
		memcpy(seq_out, params->seq, params->seq_len);
	else
		*seq_len_out = 0;

	return 0;
}
EXPORT_SYMBOL_GPL(rust_helper_key_params_get);

/**
 * rust_helper_cfg80211_connect_result - report BSS association result to cfg80211.
 *
 * Looks up the BSS by BSSID and SSID from wiphy's scan cache so that
 * cfg80211_connect_bss() receives an explicit BSS pointer.  Without this,
 * cfg80211 tries the lookup itself and fires WARN_ON(bss_not_found) when the
 * BSS cannot be matched (e.g. because the capability-inferred BSS type does
 * not match wdev->conn_bss_type).
 *
 * May only be called from process context (workqueue).
 */
void rust_helper_cfg80211_connect_result(struct net_device *ndev,
					  struct wiphy *wiphy,
					  const u8 *bssid,
					  const u8 *ssid, size_t ssid_len,
					  const u8 *req_ie, size_t req_ie_len,
					  const u8 *resp_ie, size_t resp_ie_len,
					  u16 status)
{
	struct cfg80211_bss *bss = NULL;

	if (status == WLAN_STATUS_SUCCESS && bssid && wiphy)
		bss = cfg80211_get_bss(wiphy, NULL, bssid,
				       ssid, ssid_len,
				       IEEE80211_BSS_TYPE_ANY,
				       IEEE80211_PRIVACY_ANY);

	cfg80211_connect_bss(ndev, bssid, bss,
			     req_ie, req_ie_len,
			     resp_ie, resp_ie_len,
			     status, GFP_KERNEL,
			     NL80211_TIMEOUT_UNSPECIFIED);

	if (bss)
		cfg80211_put_bss(wiphy, bss);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_connect_result);

/**
 * rust_helper_cfg80211_disconnected - notify cfg80211 that we disconnected.
 */
void rust_helper_cfg80211_disconnected(struct net_device *ndev, u16 reason)
{
	cfg80211_disconnected(ndev, reason, NULL, 0, true, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_disconnected);

/**
 * rust_helper_cfg80211_new_sta - notify cfg80211 of a new station association.
 *
 * Called when firmware sends C2H_ADD_STA_EVENT after successful association.
 * Informs the kernel about a new peer station so it can be tracked.
 */
void rust_helper_cfg80211_new_sta(struct net_device *ndev, const u8 *mac_addr,
				  u8 aid)
{
	struct station_info sinfo = {};

	sinfo.filled = 0;
	cfg80211_new_sta(ndev, mac_addr, &sinfo, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_new_sta);

/**
 * rust_helper_cfg80211_del_sta - notify cfg80211 that a station disassociated.
 *
 * Called when firmware sends C2H_DEL_STA_EVENT after a peer station leaves.
 * Removes the station from the kernel's station table.
 */
void rust_helper_cfg80211_del_sta(struct net_device *ndev, const u8 *mac_addr)
{
	cfg80211_del_sta(ndev, mac_addr, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_del_sta);

/* ---------------------------------------------------------------------------
 * Deferred connect-result work
 *
 * The c2h_join_bss_event arrives in softirq context; cfg80211_connect_result
 * must be called from process context.  We schedule a work item here and
 * call back into Rust from the worker.
 * ---------------------------------------------------------------------------
 */

static void (*r92su_join_result_fn)(void *dev_ptr);
static void *r92su_join_result_dev;
static struct work_struct r92su_join_result_work;
static bool r92su_join_result_work_init;

static void r92su_join_result_handler(struct work_struct *work)
{
	void (*fn)(void *dev_ptr) = r92su_join_result_fn;
	void *dev_ptr = r92su_join_result_dev;

	r92su_join_result_fn  = NULL;
	r92su_join_result_dev = NULL;

	if (fn && dev_ptr)
		fn(dev_ptr);
}

/**
 * rust_helper_schedule_join_result - schedule delivery of a join-BSS result.
 *
 * @dev_ptr: opaque R92suDevice pointer forwarded to @fn
 * @fn:      Rust callback invoked from process context
 *
 * Safe to call from softirq (RX completion) context.  At most one pending
 * work item; subsequent calls before the handler runs overwrite the previous
 * registration (duplicate join events are discarded by the caller).
 */
void rust_helper_schedule_join_result(void *dev_ptr,
				       void (*fn)(void *dev_ptr))
{
	if (!r92su_join_result_work_init) {
		INIT_WORK(&r92su_join_result_work, r92su_join_result_handler);
		r92su_join_result_work_init = true;
	}
	r92su_join_result_fn  = fn;
	r92su_join_result_dev = dev_ptr;
	schedule_work(&r92su_join_result_work);
}
EXPORT_SYMBOL_GPL(rust_helper_schedule_join_result);

/**
 * rust_helper_get_netdev_ptr - retrieve the net_device pointer from a wiphy.
 *
 * Returns ndev->ieee80211_ptr if available, NULL otherwise.
 * Used to cache the netdev pointer in R92suDevice after registration.
 */
struct net_device *rust_helper_get_netdev_ptr(struct wiphy *wiphy)
{
	struct wireless_dev *wdev;

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		if (wdev->netdev)
			return wdev->netdev;
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(rust_helper_get_netdev_ptr);

/**
 * rust_helper_cfg80211_connect_params_get - extract connect params for Rust.
 *
 * Copies the fields needed by the Rust connect handler from a
 * cfg80211_connect_params struct into caller-supplied buffers.
 *
 * Returns 0 on success, -EINVAL if the SSID is too long.
 */
int rust_helper_cfg80211_connect_params_get(
	struct cfg80211_connect_params *sme,
	u8 *ssid_out, size_t *ssid_len_out,
	u8 *bssid_out,
	u8 *ie_out, size_t *ie_len_out, size_t ie_buf_len,
	u32 *auth_type_out,
	u32 *privacy_out)
{
	if (sme->ssid_len > 32)
		return -EINVAL;

	memcpy(ssid_out, sme->ssid, sme->ssid_len);
	*ssid_len_out = sme->ssid_len;

	if (sme->bssid)
		memcpy(bssid_out, sme->bssid, ETH_ALEN);
	else
		eth_zero_addr(bssid_out);

	if (sme->ie && sme->ie_len > 0 && sme->ie_len <= ie_buf_len) {
		memcpy(ie_out, sme->ie, sme->ie_len);
		*ie_len_out = sme->ie_len;
	} else {
		*ie_len_out = 0;
	}

	*auth_type_out = sme->auth_type;
	*privacy_out   = sme->privacy ? 1 : 0;
	return 0;
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_connect_params_get);

/**
 * rust_helper_set_cfg80211_ops_get_station - set the .get_station callback.
 */
void rust_helper_set_cfg80211_ops_get_station(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  const u8 *mac, struct station_info *sinfo))
{
	r92su_cfg80211_ops.get_station = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_get_station);

/**
 * rust_helper_set_cfg80211_ops_dump_station - set the .dump_station callback.
 */
void rust_helper_set_cfg80211_ops_dump_station(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  int idx, u8 *mac, struct station_info *sinfo))
{
	r92su_cfg80211_ops.dump_station = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_dump_station);

/**
 * rust_helper_set_cfg80211_ops_change_virtual_intf - set the .change_virtual_intf callback.
 */
void rust_helper_set_cfg80211_ops_change_virtual_intf(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  enum nl80211_iftype type, struct vif_params *params))
{
	r92su_cfg80211_ops.change_virtual_intf = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_change_virtual_intf);

/**
 * rust_helper_set_cfg80211_ops_join_ibss - set the .join_ibss callback.
 */
void rust_helper_set_cfg80211_ops_join_ibss(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  struct cfg80211_ibss_params *params))
{
	r92su_cfg80211_ops.join_ibss = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_join_ibss);

/**
 * rust_helper_set_cfg80211_ops_leave_ibss - set the .leave_ibss callback.
 */
void rust_helper_set_cfg80211_ops_leave_ibss(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev))
{
	r92su_cfg80211_ops.leave_ibss = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_leave_ibss);

/**
 * rust_helper_set_cfg80211_ops_set_wiphy_params - set the .set_wiphy_params callback.
 */
void rust_helper_set_cfg80211_ops_set_wiphy_params(
	int (*fn)(struct wiphy *wiphy, int radio_idx, u32 changed))
{
	r92su_cfg80211_ops.set_wiphy_params = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_set_wiphy_params);

/**
 * rust_helper_set_cfg80211_ops_set_monitor_channel - set the .set_monitor_channel callback.
 */
void rust_helper_set_cfg80211_ops_set_monitor_channel(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  struct cfg80211_chan_def *chandef))
{
	r92su_cfg80211_ops.set_monitor_channel = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_set_monitor_channel);

/**
 * rust_helper_set_cfg80211_ops_update_mgmt_frame_registrations - set the .update_mgmt_frame_registrations callback.
 *
 * Note: The callback is stored as a void* function pointer to avoid strict
 * type checking issues with struct mgmt_frame_regs. The actual callback
 * receives the pointer cast from void*.
 */
void rust_helper_set_cfg80211_ops_update_mgmt_frame_registrations(
	void (*fn)(struct wiphy *wiphy, struct wireless_dev *wdev,
		   void *upd))
{
	r92su_cfg80211_ops.update_mgmt_frame_registrations = (void (*)(struct wiphy *, struct wireless_dev *, struct mgmt_frame_regs *))fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_update_mgmt_frame_registrations);

/**
 * rust_helper_set_cfg80211_ops_mgmt_tx - set the .mgmt_tx callback.
 */
void rust_helper_set_cfg80211_ops_mgmt_tx(
	int (*fn)(struct wiphy *wiphy, struct wireless_dev *wdev,
		  struct cfg80211_mgmt_tx_params *params, u64 *cookie))
{
	r92su_cfg80211_ops.mgmt_tx = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_mgmt_tx);

/**
 * rust_helper_set_cfg80211_ops_tdls_mgmt - set the .tdls_mgmt callback.
 */
void rust_helper_set_cfg80211_ops_tdls_mgmt(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  const u8 *peer, int link_id,
		  u8 action_code, u8 dialog_token,
		  u16 status_code, u32 peer_capability,
		  bool initiator, const u8 *buf, size_t len))
{
	r92su_cfg80211_ops.tdls_mgmt = fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_tdls_mgmt);

/**
 * rust_helper_set_cfg80211_ops_tdls_oper - set the .tdls_oper callback.
 */
void rust_helper_set_cfg80211_ops_tdls_oper(
	int (*fn)(struct wiphy *wiphy, struct net_device *ndev,
		  const u8 *peer, int oper))
{
	r92su_cfg80211_ops.tdls_oper = (int (*)(struct wiphy *, struct net_device *,
					       const u8 *, enum nl80211_tdls_operation))fn;
}
EXPORT_SYMBOL_GPL(rust_helper_set_cfg80211_ops_tdls_oper);

/**
 * rust_helper_cfg80211_mgmt_tx_status - report mgmt frame tx status.
 *
 * Called from Rust after tx attempt to inform cfg80211/wpa_supplicant
 * of the result.
 */
void rust_helper_cfg80211_mgmt_tx_status(
	struct wireless_dev *wdev, u64 cookie, const u8 *buf, size_t len,
	bool ack, gfp_t gfp)
{
	cfg80211_mgmt_tx_status(wdev, cookie, buf, len, ack, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_mgmt_tx_status);

/**
 * rust_helper_cfg80211_tdls_oper_request - request userspace to perform TDLS operation.
 */
void rust_helper_cfg80211_tdls_oper_request(
	struct net_device *ndev, const u8 *peer,
	enum nl80211_tdls_operation oper, u16 reason_code, gfp_t gfp)
{
	cfg80211_tdls_oper_request(ndev, peer, oper, reason_code, gfp);
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_tdls_oper_request);

/**
 * rust_helper_cfg80211_sta_info - extract station_info fields for Rust.
 *
 * Copies the fields needed by the Rust get_station/dump_station handlers
 * from a cfg80211 station_info struct into caller-supplied buffers.
 */
int rust_helper_cfg80211_sta_info(struct station_info *sinfo,
				  u64 *rx_packets_out, u64 *rx_bytes_out,
				  u64 *tx_packets_out, u64 *tx_bytes_out,
				  u32 *rx_rate_out, u32 *rx_rate_flags_out,
				  u32 *tx_rate_out, u32 *tx_rate_flags_out,
				  u32 *rx_bandwidth_out, u32 *tx_bandwidth_out,
				  u8 *signal_out)
{
	if (!sinfo)
		return -EINVAL;

	if (sinfo->filled & STATION_INFO_RX_PACKETS)
		*rx_packets_out = sinfo->rx_packets;
	if (sinfo->filled & STATION_INFO_RX_BYTES)
		*rx_bytes_out = sinfo->rx_bytes;
	if (sinfo->filled & STATION_INFO_TX_PACKETS)
		*tx_packets_out = sinfo->tx_packets;
	if (sinfo->filled & STATION_INFO_TX_BYTES)
		*tx_bytes_out = sinfo->tx_bytes;
	if (sinfo->filled & STATION_INFO_RX_BITRATE) {
		*rx_rate_out = sinfo->rxrate.legacy;
		*rx_rate_flags_out = sinfo->rxrate.flags;
	}
	if (sinfo->filled & STATION_INFO_TX_BITRATE) {
		*tx_rate_out = sinfo->txrate.legacy;
		*tx_rate_flags_out = sinfo->txrate.flags;
	}
	if (sinfo->filled & STATION_INFO_RX_BW_20)
		*rx_bandwidth_out = RATE_INFO_BW_20;
	else if (sinfo->filled & STATION_INFO_RX_BW_40)
		*rx_bandwidth_out = RATE_INFO_BW_40;
	else if (sinfo->filled & STATION_INFO_RX_BW_80)
		*rx_bandwidth_out = RATE_INFO_BW_80;
	else
		*rx_bandwidth_out = 0;
	if (sinfo->filled & STATION_INFO_TX_BW_20)
		*tx_bandwidth_out = RATE_INFO_BW_20;
	else if (sinfo->filled & STATION_INFO_TX_BW_40)
		*tx_bandwidth_out = RATE_INFO_BW_40;
	else if (sinfo->filled & STATION_INFO_TX_BW_80)
		*tx_bandwidth_out = RATE_INFO_BW_80;
	else
		*tx_bandwidth_out = 0;
	if (sinfo->filled & STATION_INFO_SIGNAL)
		*signal_out = (u8)sinfo->signal;

	return 0;
}
EXPORT_SYMBOL_GPL(rust_helper_cfg80211_sta_info);

/**
 * rust_helper_station_info_set - set station_info fields from Rust.
 *
 * Sets the fields in the cfg80211 station_info struct from the provided values.
 * Used by the Rust get_station/dump_station callbacks.
 */
void rust_helper_station_info_set(struct station_info *sinfo,
				  u64 rx_packets, u64 rx_bytes,
				  u64 tx_packets, u64 tx_bytes,
				  u32 rx_rate, u32 rx_rate_flags,
				  u32 tx_rate, u32 tx_rate_flags,
				  u8 signal)
{
	sinfo->rx_packets = rx_packets;
	sinfo->tx_packets = tx_packets;
	sinfo->rx_bytes = rx_bytes;
	sinfo->tx_bytes = tx_bytes;

	sinfo->rxrate.legacy = rx_rate;
	sinfo->rxrate.flags = rx_rate_flags;
	sinfo->txrate.legacy = tx_rate;
	sinfo->txrate.flags = tx_rate_flags;

	sinfo->signal = signal;
	sinfo->filled = STATION_INFO_RX_PACKETS | STATION_INFO_TX_PACKETS |
			STATION_INFO_RX_BYTES | STATION_INFO_TX_BYTES |
			STATION_INFO_RX_BITRATE | STATION_INFO_TX_BITRATE |
			STATION_INFO_SIGNAL;
}
EXPORT_SYMBOL_GPL(rust_helper_station_info_set);

/* ---------------------------------------------------------------------------
 * Debug ring buffer support
 *
 * Mirrors the ring buffer from debugfs.c (struct r92su_debug).
 * ---------------------------------------------------------------------------
 */

#define R92SU_DEBUG_RING_SIZE	64

struct r92su_debug_mem_rbe {
	u32 reg;
	u32 value;
	int type; /* 0=u8, 1=u16, 2=u32 */
};

struct r92su_debug_ring {
	struct r92su_debug_mem_rbe ring[R92SU_DEBUG_RING_SIZE];
	unsigned int ring_head;
	unsigned int ring_tail;
	unsigned int ring_len;
};

static const char * const r92su_mem_type_str[] = {
	[R92SU_DEBUG_RING_SIZE] = "byte",
	[R92SU_DEBUG_RING_SIZE + 1] = "word",
	[R92SU_DEBUG_RING_SIZE + 2] = " int",
};

/**
 * rust_helper_debug_ring_add - add a register read to the debug ring.
 *
 * @ring: pointer to the debug ring structure (stored in R92suDevice)
 * @reg:  register address
 * @value: read value
 * @type: 0=8-bit, 1=16-bit, 2=32-bit
 */
void rust_helper_debug_ring_add(struct r92su_debug_ring *ring,
				 u32 reg, u32 value, int type)
{
	if (!ring)
		return;

	ring->ring[ring->ring_tail].reg = reg;
	ring->ring[ring->ring_tail].value = value;
	ring->ring[ring->ring_tail].type = type;
	ring->ring_tail++;
	ring->ring_tail %= R92SU_DEBUG_RING_SIZE;

	if (ring->ring_len < R92SU_DEBUG_RING_SIZE)
		ring->ring_len++;
}
EXPORT_SYMBOL_GPL(rust_helper_debug_ring_add);

/* ---------------------------------------------------------------------------
 * Debugfs file operations
 *
 * Mirrors the debugfs entry points from debugfs.c.
 * The debugfs directory is created under wiphy->debugfsdir.
 * ---------------------------------------------------------------------------
 */

struct r92su_debugfs_data {
	void *dev_ptr;  /* pointer to R92suDevice */
};

static int r92su_debugfs_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

/* Forward declarations of file_operations structs */
extern const struct file_operations r92su_debugfs_tx_pending_urbs_fops;
extern const struct file_operations r92su_debugfs_hw_ioread_fops;
extern const struct file_operations r92su_debugfs_chip_rev_fops;
extern const struct file_operations r92su_debugfs_eeprom_type_fops;
extern const struct file_operations r92su_debugfs_rf_type_fops;
extern const struct file_operations r92su_debugfs_h2c_seq_fops;
extern const struct file_operations r92su_debugfs_c2h_seq_fops;
extern const struct file_operations r92su_debugfs_cpwm_fops;
extern const struct file_operations r92su_debugfs_rpwm_fops;
extern const struct file_operations r92su_debugfs_rx_queue_len_fops;
extern const struct file_operations r92su_debugfs_sta_table_fops;
extern const struct file_operations r92su_debugfs_connected_bss_fops;
extern const struct file_operations r92su_debugfs_eeprom_fops;
extern const struct file_operations r92su_debugfs_eeprom_raw_fops;
extern const struct file_operations r92su_debugfs_hw_iowrite_fops;

/* Stub debugfs read functions for files not yet fully implemented */
static ssize_t r92su_debugfs_hw_ioread_read(struct file *file,
					    char __user *userbuf,
					    size_t count, loff_t *ppos)
{
	char buf[128];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "(debug ring read not implemented)\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_hw_iowrite_write(struct file *file,
					      const char __user *userbuf,
					      size_t count, loff_t *ppos)
{
	char buf[64];
	u32 reg, val;
	int n;

	if (count > sizeof(buf) - 1)
		count = sizeof(buf) - 1;

	if (copy_from_user(buf, userbuf, count))
		return -EFAULT;
	buf[count] = '\0';

	/* Parse "0xADDR 0xVALUE" */
	n = sscanf(buf, "0x%x 0x%x", &reg, &val);
	if (n != 2)
		return -EINVAL;

	return count;
}

static ssize_t r92su_debugfs_sta_table_read(struct file *file,
					    char __user *userbuf,
					    size_t count, loff_t *ppos)
{
	char buf[1024];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "(station table read not implemented)\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_connected_bss_read(struct file *file,
						char __user *userbuf,
						size_t count, loff_t *ppos)
{
	char buf[512];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "(connected bss read not implemented)\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_eeprom_read(struct file *file,
					 char __user *userbuf,
					 size_t count, loff_t *ppos)
{
	char buf[1024];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "(eeprom read not implemented)\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_eeprom_raw_read(struct file *file,
					     char __user *userbuf,
					     size_t count, loff_t *ppos)
{
	char buf[1024];
	int len = 0;

	len = snprintf(buf, sizeof(buf), "(eeprom raw read not implemented)\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

/**
 * rust_helper_debugfs_create - create debugfs entries for the device.
 *
 * @dev:        the device pointer (passed to read/write callbacks)
 * @wiphy:     the wiphy (debugfs parent directory is wiphy->debugfsdir)
 *
 * Creates a directory named after the module and populates it with the
 * debugfs files (tx_pending_urbs, hw_ioread, hw_iowrite, chip_rev, etc.).
 * Returns a pointer to the created directory (or NULL on error).
 */
struct dentry *rust_helper_debugfs_create(void *dev, struct wiphy *wiphy)
{
	struct dentry *dfs;

	if (!wiphy || !wiphy->debugfsdir)
		return NULL;

	dfs = debugfs_create_dir("rtl8192su", wiphy->debugfsdir);
	if (!dfs)
		return NULL;

	/* Read-only files */
	debugfs_create_file("tx_pending_urbs", S_IRUSR, dfs, dev,
			    &r92su_debugfs_tx_pending_urbs_fops);
	debugfs_create_file("hw_ioread", S_IRUSR, dfs, dev,
			    &r92su_debugfs_hw_ioread_fops);
	debugfs_create_file("chip_rev", S_IRUSR, dfs, dev,
			    &r92su_debugfs_chip_rev_fops);
	debugfs_create_file("eeprom_type", S_IRUSR, dfs, dev,
			    &r92su_debugfs_eeprom_type_fops);
	debugfs_create_file("rf_type", S_IRUSR, dfs, dev,
			    &r92su_debugfs_rf_type_fops);
	debugfs_create_file("sta_table", S_IRUSR, dfs, dev,
			    &r92su_debugfs_sta_table_fops);
	debugfs_create_file("connected_bss", S_IRUSR, dfs, dev,
			    &r92su_debugfs_connected_bss_fops);
	debugfs_create_file("eeprom", S_IRUSR, dfs, dev,
			    &r92su_debugfs_eeprom_fops);
	debugfs_create_file("eeprom_raw", S_IRUSR, dfs, dev,
			    &r92su_debugfs_eeprom_raw_fops);
	debugfs_create_file("h2c_seq", S_IRUSR, dfs, dev,
			    &r92su_debugfs_h2c_seq_fops);
	debugfs_create_file("c2h_seq", S_IRUSR, dfs, dev,
			    &r92su_debugfs_c2h_seq_fops);
	debugfs_create_file("cpwm", S_IRUSR, dfs, dev,
			    &r92su_debugfs_cpwm_fops);
	debugfs_create_file("rpwm", S_IRUSR, dfs, dev,
			    &r92su_debugfs_rpwm_fops);
	debugfs_create_file("rx_queue_len", S_IRUSR, dfs, dev,
			    &r92su_debugfs_rx_queue_len_fops);

	/* Write-only files */
	debugfs_create_file("hw_iowrite", S_IWUSR, dfs, dev,
			    &r92su_debugfs_hw_iowrite_fops);

	return dfs;
}
EXPORT_SYMBOL_GPL(rust_helper_debugfs_create);

/**
 * rust_helper_debugfs_remove - remove debugfs entries.
 *
 * @dfs: the debugfs directory pointer returned by rust_helper_debugfs_create
 */
void rust_helper_debugfs_remove(struct dentry *dfs)
{
	if (dfs)
		debugfs_remove_recursive(dfs);
}
EXPORT_SYMBOL_GPL(rust_helper_debugfs_remove);

/* ---------------------------------------------------------------------------
 * Debugfs callbacks — called from debugfs read handlers to get Rust data
 * ---------------------------------------------------------------------------
 */

static int (*r92su_debugfs_get_tx_pending_urbs)(void *dev_ptr);
static int (*r92su_debugfs_get_chip_rev)(void *dev_ptr);
static int (*r92su_debugfs_get_rf_type)(void *dev_ptr);
static int (*r92su_debugfs_get_eeprom_type)(void *dev_ptr);
static u8 (*r92su_debugfs_get_h2c_seq)(void *dev_ptr);
static u8 (*r92su_debugfs_get_c2h_seq)(void *dev_ptr);
static u8 (*r92su_debugfs_get_cpwm)(void *dev_ptr);
static u8 (*r92su_debugfs_get_rpwm)(void *dev_ptr);
static int (*r92su_debugfs_get_rx_queue_len)(void *dev_ptr);
static void *r92su_debugfs_dev_ptr;

/**
 * rust_helper_debugfs_set_callbacks - register Rust callbacks for debugfs reads.
 *
 * @dev_ptr:              opaque R92suDevice pointer forwarded to each callback
 * @get_tx_pending_urbs:  returns count of pending TX URBs
 * @get_chip_rev:         returns chip revision (enum value)
 * @get_rf_type:          returns RF type (enum value)
 * @get_eeprom_type:      returns EEPROM type (enum value)
 * @get_h2c_seq:          returns H2C sequence number
 * @get_c2h_seq:          returns C2H sequence number
 * @get_cpwm:             returns CPWM value
 * @get_rpwm:             returns RPWM value
 * @get_rx_queue_len:     returns RX queue length
 */
void rust_helper_debugfs_set_callbacks(
	void *dev_ptr,
	int (*get_tx_pending_urbs)(void *),
	int (*get_chip_rev)(void *),
	int (*get_rf_type)(void *),
	int (*get_eeprom_type)(void *),
	u8 (*get_h2c_seq)(void *),
	u8 (*get_c2h_seq)(void *),
	u8 (*get_cpwm)(void *),
	u8 (*get_rpwm)(void *),
	int (*get_rx_queue_len)(void *))
{
	r92su_debugfs_dev_ptr = dev_ptr;
	r92su_debugfs_get_tx_pending_urbs = get_tx_pending_urbs;
	r92su_debugfs_get_chip_rev = get_chip_rev;
	r92su_debugfs_get_rf_type = get_rf_type;
	r92su_debugfs_get_eeprom_type = get_eeprom_type;
	r92su_debugfs_get_h2c_seq = get_h2c_seq;
	r92su_debugfs_get_c2h_seq = get_c2h_seq;
	r92su_debugfs_get_cpwm = get_cpwm;
	r92su_debugfs_get_rpwm = get_rpwm;
	r92su_debugfs_get_rx_queue_len = get_rx_queue_len;
}
EXPORT_SYMBOL_GPL(rust_helper_debugfs_set_callbacks);

static ssize_t r92su_debugfs_tx_pending_urbs_read(struct file *file,
						  char __user *userbuf,
						  size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_tx_pending_urbs && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "%d\n",
			       r92su_debugfs_get_tx_pending_urbs(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_chip_rev_read(struct file *file,
					    char __user *userbuf,
					    size_t count, loff_t *ppos)
{
	char buf[32];
	int len;
	static const char * const rev_str[] = { "FPGA", "A CUT", "B CUT", "C CUT" };
	int rev = 0;

	if (r92su_debugfs_get_chip_rev && r92su_debugfs_dev_ptr)
		rev = r92su_debugfs_get_chip_rev(r92su_debugfs_dev_ptr);

	if (rev >= 0 && rev < 4)
		len = snprintf(buf, sizeof(buf), "%s\n", rev_str[rev]);
	else
		len = snprintf(buf, sizeof(buf), "unknown (%d)\n", rev);
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_rf_type_read(struct file *file,
					  char __user *userbuf,
					  size_t count, loff_t *ppos)
{
	char buf[32];
	int len;
	static const char * const rf_str[] = { "1T1R", "1T2R", "2T2R" };
	int rf = 0;

	if (r92su_debugfs_get_rf_type && r92su_debugfs_dev_ptr)
		rf = r92su_debugfs_get_rf_type(r92su_debugfs_dev_ptr);

	switch (rf) {
	case 0x11: len = snprintf(buf, sizeof(buf), "1T1R\n"); break;
	case 0x12: len = snprintf(buf, sizeof(buf), "1T2R\n"); break;
	case 0x22: len = snprintf(buf, sizeof(buf), "2T2R\n"); break;
	default:   len = snprintf(buf, sizeof(buf), "unknown (0x%02x)\n", rf); break;
	}
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_eeprom_type_read(struct file *file,
					      char __user *userbuf,
					      size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_eeprom_type && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "0x%x\n",
			       r92su_debugfs_get_eeprom_type(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_h2c_seq_read(struct file *file,
					  char __user *userbuf,
					  size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_h2c_seq && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "%d\n",
			       r92su_debugfs_get_h2c_seq(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_c2h_seq_read(struct file *file,
					  char __user *userbuf,
					  size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_c2h_seq && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "%d\n",
			       r92su_debugfs_get_c2h_seq(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_cpwm_read(struct file *file,
				       char __user *userbuf,
				       size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_cpwm && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "0x%02x\n",
			       r92su_debugfs_get_cpwm(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_rpwm_read(struct file *file,
				       char __user *userbuf,
				       size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_rpwm && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "0x%02x\n",
			       r92su_debugfs_get_rpwm(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

static ssize_t r92su_debugfs_rx_queue_len_read(struct file *file,
					       char __user *userbuf,
					       size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	if (r92su_debugfs_get_rx_queue_len && r92su_debugfs_dev_ptr)
		len = snprintf(buf, sizeof(buf), "%d\n",
			       r92su_debugfs_get_rx_queue_len(r92su_debugfs_dev_ptr));
	else
		len = snprintf(buf, sizeof(buf), "0\n");
	return simple_read_from_buffer(userbuf, count, ppos, buf, len);
}

/* File operations for debugfs read files */
#define R92SU_DEBUGFS_RO_FILE(name) \
	static const struct file_operations r92su_debugfs_##name##_fops = { \
		.owner = THIS_MODULE, \
		.open  = r92su_debugfs_open, \
		.read  = r92su_debugfs_##name##_read, \
	}

R92SU_DEBUGFS_RO_FILE(tx_pending_urbs);
R92SU_DEBUGFS_RO_FILE(chip_rev);
R92SU_DEBUGFS_RO_FILE(rf_type);
R92SU_DEBUGFS_RO_FILE(eeprom_type);
R92SU_DEBUGFS_RO_FILE(h2c_seq);
R92SU_DEBUGFS_RO_FILE(c2h_seq);
R92SU_DEBUGFS_RO_FILE(cpwm);
R92SU_DEBUGFS_RO_FILE(rpwm);
R92SU_DEBUGFS_RO_FILE(rx_queue_len);
R92SU_DEBUGFS_RO_FILE(hw_ioread);
R92SU_DEBUGFS_RO_FILE(sta_table);
R92SU_DEBUGFS_RO_FILE(connected_bss);
R92SU_DEBUGFS_RO_FILE(eeprom);
R92SU_DEBUGFS_RO_FILE(eeprom_raw);

/* File operations for debugfs write files */
static const struct file_operations r92su_debugfs_hw_iowrite_fops = {
	.owner = THIS_MODULE,
	.open  = r92su_debugfs_open,
	.write = r92su_debugfs_hw_iowrite_write,
};

