# Twinny — Writeup

**Category:** Forensics  
**Difficulty:** Medium  
**Author:** Gib  

---

## Description

> At Cybersphere 7.0, hundreds of attendees overloaded the public WiFi, causing constant disconnections and unstable connections. Hidden within the chaos, an attacker targeted one attendee's private WiFi network, blending in among the noise to carry out a stealthy attack.
>
> You've been given a packet capture from the hotel's monitoring system. Somewhere inside the flood of beacon frames and wireless traffic lies the full attack chain.
>
> Analyze the capture, identify the targeted network, and uncover what happened.

**Artifacts provided:**
- `Twinny.pcap`

---

## Understanding the Challenge

Before diving into the questions it helps to understand the attack taking place.

An **Evil Twin attack** is a WiFi-based attack where an attacker clones a legitimate access point — same network name, same channel — and forces nearby devices to connect to the fake one instead. The attacker achieves this by flooding the victim with **deauthentication frames**, which are management frames that force a device to disconnect from its current AP. Since the 802.11 protocol does not authenticate these frames, any device can send them spoofed as any source.

Once the victim reconnects, it performs a **WPA2 4-way handshake** with whichever AP responds first — in this case the evil twin. The handshake doesn't expose the password directly, but it contains enough cryptographic material (ANonce, SNonce, MIC) for an attacker to attempt an **offline dictionary attack** using a tool like aircrack-ng.

The attacker's goal here was to recover the WPA2 password of a private network belonging to one of the conference attendees.

---

## Solution

### Opening the artifact

Load `Twinny.pcap` in Wireshark. You will immediately notice this is a **802.11 wireless capture**, no IP addresses, just MAC addresses and 802.11 protocol frames. This is a monitor mode capture of raw WiFi traffic.

---

### Q1 — What is the SSID of the targeted network?

Navigate to **Wireless → WLAN Traffic** in Wireshark. This gives a summary table of every network visible in the capture.

Click the **Deauths** column header to sort by descending deauth count. One network immediately stands out — `Flybox-3C8L` with **72 deauth frames** attributed to it. Every other network in the capture shows 0 deauths.

![alt text](1.jpg)

A sudden flood of deauthentication frames targeting a specific network is the signature of an evil twin attack. This is the targeted network.

> **Answer: `Flybox-3C8L`**

---

### Q2 — What is the BSSID of the legitimate AP?

Still in the WLAN Statistics table, look at the two entries for `Flybox-3C8L`. Two different BSSIDs are broadcasting the same SSID — this is the core indicator of an evil twin attack.

![alt text](2.jpg)

The BSSID with **72 deauths** attributed to it is the legitimate AP. The attacker spoofed this MAC address as the source of all deauth frames, making them appear to come from the real router.

> **Answer: `50:C7:BF:39:0C:8C`**

---

### Q3 — What is the BSSID of the evil twin?

From the same WLAN Statistics table, the second `Flybox-3C8L` entry has **0 deauths** and fewer beacon frames, it appeared later than the legitimate AP.

> **Answer: `00:C0:CA:7D:72:47`**

---

### Q4 — What channel was the attack conducted on?

The **Channel** column in the WLAN Statistics table shows `6` for both `Flybox-3C8L` entries. The evil twin cloned the exact same channel as the legitimate AP to intercept reconnecting clients.

> **Answer: `6`**

---

### Q5 — What is the MAC address of the victim?

Apply this filter in Wireshark:

```
wlan.fc.type_subtype == 12 && wlan.ta == 50:c7:bf:39:0c:8c
```

- `wlan.fc.type_subtype == 12` filters for deauthentication frames
- `wlan.ta == 50:c7:bf:39:0c:8c` filters by transmitter address — the spoofed legitimate AP MAC

![alt text](3.jpg)

Click any of the resulting frames and read the **Destination** field. Every targeted deauth frame was addressed to the same MAC, that is the victim.

![alt text](4.jpg)

> **Answer: `F4:7B:5E:34:2C:D8`**

---

### Q6 — How many deauth frames were sent targeting the victim?

Apply this filter:

```
wlan.fc.type_subtype == 12 && wlan.da == f4:7b:5e:34:2c:d8
```

This filters deauth frames specifically addressed to the victim's MAC, excluding the 8 broadcast deauths (`ff:ff:ff:ff:ff:ff`) the attacker also sent. Read the packet count in the bottom right of Wireshark.

![alt text](5.jpg)

> **Answer: `64`**

---

### Q7 — What is the reason code in the deauth frames?

With the same filter applied, click any deauth frame and expand **IEEE 802.11 Wireless Management* --> **Fixed Parameters** in the packet details. The **Reason Code** field is visible directly.

![alt text](6.jpg)

Reason code `7` means *"Class 3 frame received from nonassociated station"* : the most common reason code used in deauth attacks. It tells the victim's device that it is sending data frames while not properly associated, prompting it to disconnect and reconnect.

> **Answer: `7`**

---

### Q8 — What protocol handles the 4-way handshake?

We know the victim is going to reconnect to the Fake AP so the best filter to apply is :

```
wlan.addr == 00:c0:ca:7d:72:47
```

![alt text](7.jpg)

After the association frames, four frames appear labeled **EAPOL** in the Protocol column. EAPOL — Extensible Authentication Protocol Over LAN — is the protocol responsible for carrying the WPA2 4-way handshake messages between the client and the access point. It operates on top of 802.11 and handles all authentication and key exchange during the connection process.

> **Answer: `EAPOL`**

---

### Q9 — What tool do you use to crack the WPA2 handshake directly from the pcap?

The capture contains a complete WPA2 4-way handshake. The standard tool for cracking WPA2 handshakes directly from a pcap file is **aircrack-ng** : it reads the EAPOL frames, extracts the cryptographic material, and performs an offline dictionary attack against the MIC.

> **Answer: `aircrack-ng`**

---

### Q10 — Crack the handshake using a very known wordlist — what is the PSK?

Run aircrack-ng directly against the capture, targeting the evil twin BSSID specifically to avoid ambiguity between the two `Flybox-3C8L` APs:

```bash
aircrack-ng Twinny.pcap -w /usr/share/wordlists/rockyou.txt -b 00:c0:ca:7d:72:47
```

aircrack-ng reads the EAPOL frames, extracts the ANonce, SNonce, MIC and MAC addresses, then iterates through rockyou.txt. For each candidate password it computes:

```
password + SSID → PBKDF2 → PMK → PTK → KCK → HMAC-SHA1 → MIC
```

When the computed MIC matches the captured MIC, the password is found.

![alt text](8.jpg)

> **Answer: `ricardo`**

---

## Flag

```
spark{s3cur3_y0ur_w1f1_tw1n}
```

---

## Attack Chain Summary


| 1 | Attacker identifies target network `Flybox-3C8L` broadcasting on channel 6 


| 2 | Evil twin AP cloned with same SSID and channel 


| 3 | 64 targeted deauth frames + 8 broadcast deauth frames sent, spoofed as legitimate AP 


| 4 | Victim `F4:7B:5E:34:2C:D8` disconnects from legitimate AP 


| 5 | Victim reconnects — evil twin responds first, victim associates with rogue AP |


| 6 | WPA2 4-way EAPOL handshake captured between victim and evil twin |


| 7 | Attacker cracks handshake offline using aircrack-ng + rockyou.txt |


| 8 | PSK `ricardo` recovered |
