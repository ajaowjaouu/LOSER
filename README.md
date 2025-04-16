
**(dport == DHCP_SERVER_PORT && sport == DHCP_CLIENT_PORT) {
+		return fils_process_hlp_dhcp(hapd, sta, (const u8 *) (udph + 1),
+					     ulen - sizeof(*udph));
+	}
+
+	return 0;
+}
+
+
+static int fils_process_hlp_ip(struct hostapd_data *hapd,
+			       struct sta_info *sta, const u8 *dst,
+			       const u8 *pos, size_t len)
+{
+	const struct iphdr *iph;
+	u16 tot_len;
+
+	if (len < sizeof(*iph))
+		return 0;
+	iph = (const struct iphdr *) pos;
+	if (ip_checksum(iph, sizeof(*iph)) != 0) {
+		wpa_printf(MSG_DEBUG,
+			   "FILS: HLP request IPv4 packet had invalid header checksum - dropped");
+		return 0;
+	}
+	tot_len = ntohs(iph->tot_len);
+	if (tot_len > len)
+		return 0;
+	wpa_printf(MSG_DEBUG,
+		   "FILS: HLP request IPv4: saddr=%08x daddr=%08x protocol=%u",
+		   iph->saddr, iph->daddr, iph->protocol);
+	switch (iph->protocol) {
+	case 17:
+		return fils_process_hlp_udp(hapd, sta, dst, pos, len);
+	}
+
+	return 0;
+}
+
+
+static int fils_process_hlp_req(struct hostapd_data *hapd,
+				struct sta_info *sta,
+				const u8 *pos, size_t len)
+{
+	const u8 *pkt, *end;
+
+	wpa_printf(MSG_DEBUG, "FILS: HLP request from " MACSTR " (dst=" MACSTR
+		   " src=" MACSTR " len=%u)",
+		   MAC2STR(sta->addr), MAC2STR(pos), MAC2STR(pos + ETH_ALEN),
+		   (unsigned int) len);
+	if (os_memcmp(sta->addr, pos + ETH_ALEN, ETH_ALEN) != 0) {
+		wpa_printf(MSG_DEBUG,
+			   "FILS: Ignore HLP request with unexpected source address"
+			   MACSTR, MAC2STR(pos + ETH_ALEN));
+		return 0;
+	}
+
+	end = pos + len;
+	pkt = pos + 2 * ETH_ALEN;
+	if (end - pkt >= 6 &&
+	    os_memcmp(pkt, "\xaa\xaa\x03\x00\x00\x00", 6) == 0)
+		pkt += 6; /* Remove SNAP/LLC header */
+	wpa_hexdump(MSG_MSGDUMP, "FILS: HLP request packet", pkt, end - pkt);
+
+	if (end - pkt < 2)
+		return 0;
+
+	switch (WPA_GET_BE16(pkt)) {
+	case ETH_P_IP:
+		return fils_process_hlp_ip(hapd, sta, pos, pkt + 2,
+					   end - pkt - 2);
+	}
+
+	return 0;
+}
+
+
+int fils_process_hlp(struct hostapd_data *hapd, struct sta_info *sta,
+		     const u8 *pos, int left)
+{
+	const u8 *end = pos + left;
+	u8 *tmp, *tmp_pos;
+	int ret = 0;
+
+	if (sta->fils_pending_assoc_req &&
+	    eloop_is_timeout_registered(fils_hlp_timeout, hapd, sta)) {
+		/* Do not process FILS HLP request again if the station
+		 * retransmits (Re)Association Request frame before the previous
+		 * HLP response has either been received or timed out. */
+		wpa_printf(MSG_DEBUG,
+			   "FILS: Do not relay another HLP request from "
+			   MACSTR
+			   " before processing of the already pending one has been completed",
+			   MAC2STR(sta->addr));
+		return 1;
+	}
+**
 	S += src/crypto/crypto_internal-modexp.c
+OBJS += src/tls/bignum.c
+endif
+ifeq ($(CONFIG_CRYPTO), libtomcrypt)
+OBJS += src/crypto/crypto_libtomcrypt.c
+OBJS_p += src/crypto/crypto_libtomcrypt.c
+LIBS += -ltomcrypt -ltfm
+LIBS_p += -ltomcrypt -ltfm
+CONFIG_INTERNAL_SHA256=y
+CONFIG_INTERNAL_RC4=y
+CONFIG_INTERNAL_DH_GROUP5=y
+endif
+ifeq ($(CONFIG_CRYPTO), internal)
+OBJS += src/crypto/crypto_internal.c
+OBJS_p += src/crypto/crypto_internal.c
+NEED_AES_ENC=y
+L_CFLAGS += -DCONFIG_CRYPTO_INTERNAL
+ifdef CONFIG_INTERNAL_LIBTOMMATH
+L_CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
+ifdef CONFIG_INTERNAL_LIBTOMMATH_FAST
+L_CFLAGS += -DLTM_FAST
+endif
+else
+LIBS += -ltommath
+LIBS_p += -ltommath
+endif
+CONFIG_INTERNAL_AES=y
+CONFIG_INTERNAL_DES=y
+CONFIG_INTERNAL_SHA1=y
+CONFIG_INTERNAL_MD4=y
+CONFIG_INTERNAL_MD5=y
+CONFIG_INTERNAL_SHA256=y
+CONFIG_INTERNAL_SHA384=y
+CONFIG_INTERNAL_SHA512=y
+CONFIG_INTERNAL_RC4=y
+CONFIG_INTERNAL_DH_GROUP5=y
+endif
+ifeq ($(CONFIG_CRYPTO), cryptoapi)
+OBJS += src/crypto/crypto_cryptoapi.c
+OBJS_p += src/crypto/crypto_cryptoapi.c
+L_CFLAGS += -DCONFIG_CRYPTO_CRYPTOAPI
+CONFIG_INTERNAL_SHA256=y
+CONFIG_INTERNAL_RC4=y
+endif
+endif
+
+ifeq ($(CONFIG_TLS), none)
+ifdef TLS_FUNCS
+OBJS += src/crypto/tls_none.c
+L_CFLAGS += -DEAP_TLS_NONE
+CONFIG_INTERNAL_AES=y
+CONFIG_INTERNAL_SHA1=y
+CONFIG_INTERNAL_MD5=y
+endif
+OBJS += src/crypto/crypto_none.c
+OBJS_p += src/crypto/crypto_none.c
+CONFIG_INTERNAL_SHA256=y
+CONFIG_INTERNAL_RC4=y
 def GroupFinished(status, etc):
-	print "Disconnected"	
+	print("Disconnected")
 	os._exit(0)
 
 class P2P_Disconnect (threading.Thread):
@@ -81,10 +81,10 @@
 		try:
 			self.path = self.wpas.GetInterface(
 					self.interface_name)
-		except dbus.DBusException, exc:
+		except dbus.DBusException as exc:
 			error = 'Error:\n  Interface ' + self.interface_name \
 				+ ' was not found'
-			print error
+			print(error)
 			usage()
 			os._exit(0)
 
@@ -142,7 +142,7 @@
 
 	# Interface name is required and was not given
 	if (interface_name == None):
-		print "Error:\n  interface_name is required"
+		print("Error:\n  interface_name is required")
 		usage()
 		quit()
 
@@ -152,7 +152,7 @@
 						wpas_dbus_interface,timeout)
 
 	except:
-		print "Error:\n  Invalid wpas_dbus_interface"
+		print("Error:\n  Invalid wpas_dbus_interface")
 		usage()
 		quit()
 
@@ -165,5 +165,5 @@
 	except:
 		pass
