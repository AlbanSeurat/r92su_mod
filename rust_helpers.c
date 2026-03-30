#include <linux/usb.h>
#include <linux/device.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/cfg80211.h>

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

/* cfg80211_ops — function pointers set by Rust after init */
struct cfg80211_ops r92su_cfg80211_ops = {
	.scan              = NULL,
	.abort_scan        = NULL,
	.connect           = NULL,
	.disconnect        = NULL,
	.add_key           = NULL,
	.del_key           = NULL,
	.change_virtual_intf = NULL,
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
		CFG80211_BSS_FTYPE_UNKNOWN, bssid, tsf,
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

static const struct net_device_ops r92su_netdev_ops = {
	.ndo_open            = r92su_ndo_open,
	.ndo_start_xmit      = r92su_stub_start_xmit,
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
