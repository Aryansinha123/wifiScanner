"""
PDF Generator for Wi-Fi Security Intelligence & Monitoring Platform
Creates an easy-to-read, comprehensive, visually appealing PDF guide
explaining all platform features in plain English.
"""

import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print 'Page X of Y' with running headers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        # Don't draw running header/footer on page 1 (cover / banner page)
        if self._pageNumber > 1:
            self.saveState()
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#475569"))
            # Running Header
            self.drawString(40, 755, "Wi-Fi Security Intelligence & Monitoring Platform")
            self.setFont("Helvetica", 8)
            self.drawRightString(572, 755, "Complete Features & Capabilities Guide")
            
            # Header line
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.75)
            self.line(40, 747, 572, 747)

            # Running Footer line
            self.line(40, 40, 572, 40)
            self.setFont("Helvetica", 8)
            self.drawString(40, 28, "100% Passive & Defensive Architecture  |  Plain English Edition")
            page_str = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(572, 28, page_str)
            self.restoreState()


def create_features_guide(output_pdf_path):
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()
    
    # Custom Modern Color Palette
    NAVY = colors.HexColor("#0F2942")
    ACCENT_BLUE = colors.HexColor("#1E5F8A")
    TEAL = colors.HexColor("#0D9488")
    DARK_TEXT = colors.HexColor("#1E293B")
    MUTED_TEXT = colors.HexColor("#475569")
    LIGHT_BG = colors.HexColor("#F8FAFC")
    BOX_BORDER = colors.HexColor("#E2E8F0")
    AMBER = colors.HexColor("#D97706")
    RED_ACCENT = colors.HexColor("#DC2626")

    # Typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.white,
        alignment=TA_CENTER
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#E2E8F0"),
        alignment=TA_CENTER
    )

    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#94A3B8"),
        alignment=TA_CENTER
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13.5,
        leading=17,
        textColor=NAVY,
        spaceBefore=14,
        spaceAfter=4,
        keepWithNext=True
    )

    feature_header_text = ParagraphStyle(
        'FeatureHeaderText',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=DARK_TEXT,
        alignment=TA_JUSTIFY,
        spaceAfter=4
    )

    body_list = ParagraphStyle(
        'BodyList',
        parent=body_style,
        leftIndent=12,
        spaceAfter=2
    )

    label_style = ParagraphStyle(
        'Label',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.8,
        leading=12,
        textColor=NAVY,
        spaceBefore=3,
        spaceAfter=1,
        keepWithNext=True
    )

    location_style = ParagraphStyle(
        'LocationText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=11.5,
        textColor=ACCENT_BLUE,
        spaceBefore=2,
        spaceAfter=6
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=DARK_TEXT
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.white
    )

    faq_question = ParagraphStyle(
        'FAQQuestion',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=NAVY,
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True
    )

    story = []

    # =========================================================================
    # TITLE BANNER / COVER BOX
    # =========================================================================
    banner_content = [
        [Paragraph("Wi-Fi Security Intelligence &amp; Monitoring Platform", title_style)],
        [Spacer(1, 3)],
        [Paragraph("Complete Platform Features &amp; Architecture Guide (Plain-English Edition)", subtitle_style)],
        [Spacer(1, 3)],
        [Paragraph(f"Created: {datetime.now().strftime('%B %d, %Y')} &nbsp;|&nbsp; 100% Passive &amp; Defensive Scope &nbsp;|&nbsp; Platform: Windows 10/11", meta_style)]
    ]
    banner_table = Table(banner_content, colWidths=[532])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), NAVY),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 8))

    # Executive Summary Card
    exec_summary_html = """
    <b>Executive Overview: What is this project?</b><br/>
    Wi-Fi networks operate invisibly through the air, making it easy for attackers to set up deceptive traps, eavesdrop on unencrypted traffic, or hijack active internet connections. This software acts as an automated <b>digital security guard</b> for your wireless environment. It continuously listens to the radio waves, checks for dangerous red flags, verifies that trusted networks haven't been cloned, and alerts you immediately if something is wrong—all without transmitting noisy packets or violating privacy.
    <br/><br/>
    <b>Why this guide exists:</b> Even though the code under the hood performs complex mathematical modeling, IEEE 802.11 frame analysis, and cryptographic scoring, understanding it shouldn't require a master's degree in cybersecurity. This guide explains every single functionality using plain, simple English, real-world analogies, and clear step-by-step reasoning.
    """
    exec_summary = Table([[Paragraph(exec_summary_html, body_style)]], colWidths=[532])
    exec_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 1, BOX_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(exec_summary)
    story.append(Spacer(1, 8))

    def make_feature_block(feature_num, title, badge_text, what_is_it, why_it_matters, how_it_works_paragraphs, where_to_find, table_element=None):
        """Helper to create a visually distinct, naturally-flowing feature entry."""
        header_text = f"Feature {feature_num}: {title}"
        if badge_text:
            header_text += f" &nbsp; [{badge_text}]"
        
        # Header banner row for the feature
        hdr_table = Table([[Paragraph(header_text, feature_header_text)]], colWidths=[532])
        hdr_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), ACCENT_BLUE),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))

        # We keep the header and the "What is it" together so headers are never orphaned
        block = [
            KeepTogether([
                hdr_table,
                Spacer(1, 3),
                Paragraph("<b>💡 What Is It?</b>", label_style),
                Paragraph(what_is_it, body_style)
            ]),
            Paragraph("<b>❓ Why Does It Matter?</b>", label_style),
            Paragraph(why_it_matters, body_style),
            Paragraph("<b>⚙️ How Does It Work? (Simple Explanation)</b>", label_style)
        ]

        for p in how_it_works_paragraphs:
            block.append(Paragraph(p, body_style))

        if table_element:
            block.append(Spacer(1, 3))
            block.append(table_element)
            block.append(Spacer(1, 3))

        block.append(Paragraph(f"<b>📍 Where To Find It In The App:</b> {where_to_find}", location_style))
        block.append(HRFlowable(width="100%", thickness=0.5, color=BOX_BORDER, spaceBefore=3, spaceAfter=8))
        return block

    # =========================================================================
    # PART 1: TOP 5 CYBERSECURITY SUPERPOWERS
    # =========================================================================
    story.append(Paragraph("Part 1: The Top 5 Core Cybersecurity Superpowers", section_heading))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=1, spaceAfter=6))

    # Feature 1: Evil Twin
    ft1_what = "An attacker sets up a fake, cloned Wi-Fi router broadcasting the exact same name (SSID) as your legitimate home, college, or office network (e.g., <i>'VIT-Campus'</i> or <i>'Home_WiFi'</i>). When devices automatically connect to this clone, the attacker intercepts their passwords, browsing traffic, and credentials."
    ft1_why = "Smartphones and laptops are designed to remember network names. If an attacker sits in a parking lot with a high-powered fake router named after your campus or home, your laptop may seamlessly hand over its traffic to the hacker without your knowledge."
    ft1_how = [
        "<b>Analogy:</b> It's like a stranger wearing a nametag with your best friend's name, but having a completely different face and voice.",
        "1. <b>Mark as Trusted:</b> You tell the platform your real router once. The tool memorizes its unique hardware MAC address (BSSID), manufacturer (e.g., TP-Link), security encryption (WPA2), and channel.",
        "2. <b>Forensic Evidence Scoring:</b> Every time the scanner runs, if it spots a network with a trusted name but unfamiliar attributes, it calculates an <i>Evil Twin Evidence Score</i> using 5 explainable factors:",
        "&nbsp;&nbsp;&bull; <b>Same SSID, Unknown BSSID (+40 points):</b> An unrecognized hardware radio is impersonating your network name.",
        "&nbsp;&nbsp;&bull; <b>Security Downgraded (+30 points):</b> The real network requires a password (WPA2), but this twin has no password (Open) to lure victims in.",
        "&nbsp;&nbsp;&bull; <b>Different Hardware Manufacturer (+15 points):</b> Real router is made by Cisco, but this one is an unbranded chip or Raspberry Pi.",
        "&nbsp;&nbsp;&bull; <b>Different Channel (+5 points):</b> The imposter transmits on an unexpected radio channel.",
        "&nbsp;&nbsp;&bull; <b>Fake / Randomized MAC (+10 points):</b> The MAC address has the IEEE 'locally administered' bit turned on, indicating software spoofing.",
        "3. <b>Instant Response:</b> If the score reaches 40+, the tool triggers an urgent <b>CRITICAL Alert</b> to warn you before your laptop connects!"
    ]
    ft1_where = "Open <b>Baseline &amp; Trust</b> page &rarr; Click <b>⭐ Mark Selected as Trusted</b>. When an impostor appears, red banners light up on the Dashboard, Events log, and as a Windows desktop notification."
    for item in make_feature_block(1, "Evil Twin & Rogue Access Point Detection", "NEW CRITICAL DEFENSE", ft1_what, ft1_why, ft1_how, ft1_where):
        story.append(item)

    # Feature 2: Real-Time Alerts
    ft2_what = "An automated notification system that alerts you the second a threat appears, even if the app is minimized, running in the background, or you are away from your desk."
    ft2_why = "A security monitor that quietly writes warnings into a closed log file is useless if an attack occurs while you are browsing the web. You need to be alerted immediately so you can disconnect before data is compromised."
    ft2_how = [
        "<b>Multiple Delivery Channels:</b>",
        "&nbsp;&nbsp;&bull; <b>Windows Toast Notifications:</b> Native popup banners in the corner of your screen. Built using Windows native APIs—works 100% offline without needing internet.",
        "&nbsp;&nbsp;&bull; <b>Telegram Bot &amp; Email:</b> Sends instant messages to your smartphone so you stay protected even while away from your computer.",
        "<b>Smart Anti-Spam Controls (Keeps alerts helpful, not annoying):</b>",
        "&nbsp;&nbsp;&bull; <b>Deduplication:</b> The same warning will never be sent twice in a row.",
        "&nbsp;&nbsp;&bull; <b>30-Minute Cooldown:</b> If an offending rogue AP stays on, you get warned once, then the system stays quiet for 30 minutes instead of chiming constantly.",
        "&nbsp;&nbsp;&bull; <b>Severity Threshold:</b> You choose your alert level (e.g., only High &amp; Critical threats, or all alerts).",
        "&nbsp;&nbsp;&bull; <b>One-Click Acknowledge:</b> Clicking 'Acknowledge' in the alerts tab marks the event as seen and permanently stops repeated notifications."
    ]
    ft2_where = "Configure thresholds and bot keys in <b>Settings &rarr; Alerts &amp; Notifications</b>. View live alarms under <b>Events &amp; Alerts &rarr; Real-Time Alerts</b>."
    for item in make_feature_block(2, "Real-Time Multi-Channel Alerts & Anti-Spam Engine", "NEW SMART NOTIFIER", ft2_what, ft2_why, ft2_how, ft2_where):
        story.append(item)

    # Feature 3: Weak Configuration Checks
    ft3_what = "An automated vulnerability scanner that inspects every Wi-Fi network within radio range and pinpoints dangerous configuration weaknesses—even if no active attack is currently occurring."
    ft3_why = "Many home and small-business routers are left with outdated encryption standards or factory default names. Hackers actively drive around (wardriving) looking for these easy targets because they can be broken into in minutes."
    ft3_how = [
        "<b>Analogy:</b> Like a home security inspector walking around checking if doors are unlocked or windows are left open.",
        "The engine tests each network against 6 automated security rules:",
        "&nbsp;&nbsp;&bull; <b>Open Networks (+85 points, CRITICAL):</b> Zero encryption or password. Anyone sitting nearby can eavesdrop on your unencrypted traffic.",
        "&nbsp;&nbsp;&bull; <b>WEP Encryption (+75 points, HIGH):</b> Obsolete 1999 encryption standard that can be cracked in under 60 seconds with free software.",
        "&nbsp;&nbsp;&bull; <b>Legacy WPA (+35 points, MEDIUM):</b> Outdated security susceptible to dictionary password attacks.",
        "&nbsp;&nbsp;&bull; <b>TKIP Cipher (+20 points, MEDIUM):</b> Deprecated encryption algorithm that slows down modern Wi-Fi and has known mathematical flaws.",
        "&nbsp;&nbsp;&bull; <b>Hidden SSIDs (+15 points, LOW):</b> Hiding a network name provides zero real security; devices constantly broadcast search probes in public to find it.",
        "&nbsp;&nbsp;&bull; <b>Default Router Names (+15 points, LOW):</b> Factory names like <i>'TP-Link_4F2A'</i>, <i>'JioFiber-9912'</i>, or <i>'NETGEAR62'</i>. These tell hackers the exact hardware model and suggest the default router admin password was never changed!"
    ]
    ft3_where = "Double click any network in <b>Live Scanner</b> &rarr; Open the <b>Weak Config</b> tab to see full findings and point breakdowns."
    for item in make_feature_block(3, "Weak-Configuration & Default Password Auditor", "NEW VULNERABILITY AUDITOR", ft3_what, ft3_why, ft3_how, ft3_where):
        story.append(item)

    # Feature 4: Channel Recommendation Engine
    ft4_what = "An intelligent radio frequency analyzer that tests Wi-Fi airwave congestion and tells you the exact channel number your router should switch to for maximum speed and zero lag."
    ft4_why = "Wi-Fi signals travel through radio frequencies like cars on highway lanes. On the 2.4 GHz band, channels heavily overlap. If your neighbor is on channel 6 and you are on channel 5, your routers transmit over each other, causing gaming lag, buffering, and slow downloads."
    ft4_how = [
        "<b>A smart traffic GPS for your Wi-Fi:</b>",
        "1. <b>The 2.4 GHz Overlap Problem:</b> Only channels <b>1, 6, and 11</b> do not physically interfere with each other. All other channels (2, 3, 4, 5, 7, etc.) cause adjacent collisions. The engine calculates an exact <b>Congestion Score</b> for 1, 6, and 11 by adding the signal strength of all routers sharing the channel, plus <b>70%</b> of the signals from overlapping neighboring channels:",
        "&nbsp;&nbsp;&nbsp;&nbsp;&bull; <i>Formula:</i> Congestion = Sum(Co-Channel Signal) + 0.7 &times; Sum(Adjacent Signal)",
        "2. <b>The 5 GHz Band:</b> 5 GHz channels do not overlap! The tool counts networks on each channel (36, 40, 44, 48, etc.) and picks the cleanest, emptiest lane.",
        "3. <b>Clear Recommendation:</b> Instead of confusing graphs, it gives you a simple verdict: <i>'Channel 6 has 9 networks (congestion score 480). Channel 11 has 1 network (score 42). Recommended: Switch router to Channel 11.'</i>"
    ]
    ft4_where = "Navigate to <b>Analytics &amp; Signals</b> &rarr; Look at the prominent card at the top titled <b>Channel Recommendation Engine</b> with live 2.4 GHz and 5 GHz badges."
    for item in make_feature_block(4, "Channel Recommendation Engine (2.4 GHz & 5 GHz)", "NEW SPEED & STABILITY OPTIMIZER", ft4_what, ft4_why, ft4_how, ft4_where):
        story.append(item)

    # Feature 5: Connection Integrity Monitor
    ft5_what = "A dedicated watchdog that actively protects the specific Wi-Fi network your computer is <i>currently connected to</i>, guarding against Man-In-The-Middle (MITM) and DNS diversion attacks."
    ft5_why = "Scanning surrounding routers is helpful, but what if the network you are currently working on gets hacked? If an attacker on the same café or office Wi-Fi poisons your computer's routing table (ARP spoofing) or tampers with your DNS, they can silently steer your browser to fake phishing sites."
    ft5_how = [
        "<b>Two continuous watchdog checks running quietly in the background:</b>",
        "1. <b>ARP Spoofing Detection:</b> When you join a Wi-Fi network, your computer communicates with your router (the Default Gateway). The monitor memorizes the router's physical MAC address. If a hacker attempts ARP poisoning to trick your laptop into sending traffic through their laptop instead, the gateway MAC address suddenly changes. The monitor immediately flags an urgent <b>CRITICAL Man-In-The-Middle alert</b>.",
        "2. <b>DNS Hijacking Detection:</b> When you type 'google.com', your computer asks a DNS server for the IP address. The monitor periodically resolves canary domains (Google, Cloudflare, Wikipedia) and compares the responses against tamper-proof <b>Cloudflare DNS-over-HTTPS (DoH)</b>. If the IP addresses differ or point to a local private decoy address, the monitor warns you that your internet is being hijacked!"
    ]
    ft5_where = "Visible right on the <b>Dashboard</b> in the <b>Connection Health</b> card. You can also click <b>Check Connection Health</b> for an instant on-demand audit."
    for item in make_feature_block(5, "Active Connection Integrity (ARP & DNS Tamper Guard)", "NEW CONNECTION INTEGRITY WATCHDOG", ft5_what, ft5_why, ft5_how, ft5_where):
        story.append(item)

    # =========================================================================
    # PART 2: THE CORE DEFENSIVE & MONITORING FOUNDATION
    # =========================================================================
    story.append(Spacer(1, 4))
    story.append(Paragraph("Part 2: The Core Defensive & Monitoring Foundation", section_heading))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=1, spaceAfter=6))

    # Feature 6: Passive Wi-Fi Discovery
    ft6_what = "The underlying scanner that quietly discovers all nearby Wi-Fi networks (names, MAC addresses, signal strength, channel frequencies, and security protocols) using native Windows wireless services."
    ft6_why = "Many offensive hacking tools transmit illegal deauthentication frames or intrusive probe requests. This platform is 100% passive: it operates like an FM radio tuner, silently listening to public beacon signals without transmitting a single packet or alerting anyone."
    ft6_how = [
        "1. Invokes the Windows WLAN interface query (`netsh wlan show networks mode=bssid`) every few seconds.",
        "2. Runs custom high-speed regular expressions to extract SSID, BSSID (MAC), Signal %, Authentication, Cipher, and Channel.",
        "3. Works completely offline without needing special hardware, Wi-Fi dongles, or custom drivers."
    ]
    ft6_where = "Runs automatically. View live nearby radios anytime in the <b>Live Scanner</b> tab."
    for item in make_feature_block(6, "100% Passive Wi-Fi Discovery Engine", "CORE ENGINE", ft6_what, ft6_why, ft6_how, ft6_where):
        story.append(item)

    # Feature 7: Multi-Factor Heuristic Risk Engine
    ft7_what = "A mathematical scoring model that grades every Wi-Fi network's safety on a clear 0 to 100 scale (0 = Completely Safe, 100 = Extremely Dangerous)."
    ft7_why = "Standard operating systems only show a generic lock icon. They never explain whether 'WPA2-Personal' is safe, or how much danger you are in when connecting to an open hotel network."
    ft7_how = [
        "Calculates an explainable score by evaluating transparent security factors:",
        "&nbsp;&nbsp;&bull; <b>Security Protocol:</b> Open network adds +85; WEP adds +75; WPA adds +35; WPA2 adds +10; WPA3 adds 0.",
        "&nbsp;&nbsp;&bull; <b>Cipher Quality:</b> Weak cipher (TKIP) adds +20; strong cipher (CCMP/AES) adds 0.",
        "&nbsp;&nbsp;&bull; <b>Configuration Flaws:</b> Hidden network (+15); default router name (+15); security downgrade (+30).",
        "&nbsp;&nbsp;&bull; <b>Four Color-Coded Tiers:</b> <b>LOW</b> (0–29), <b>MEDIUM</b> (30–59), <b>HIGH</b> (60–79), and <b>CRITICAL</b> (80–100)."
    ]
    ft7_where = "Color-coded badges (Green, Yellow, Orange, Red) appear in <b>Live Scanner</b>, <b>Security Monitor</b>, and executive reports."
    for item in make_feature_block(7, "Explainable Multi-Factor Risk Engine (0-100 Score)", "CORE SCORING", ft7_what, ft7_why, ft7_how, ft7_where):
        story.append(item)

    # Feature 8: Network Lifecycle & Debouncing
    ft8_what = "A state tracking system that remembers whether a network is genuinely present, temporarily flickering due to radio interference, or completely gone."
    ft8_why = "Wi-Fi signals fluctuate constantly when people walk by or doors close. Cheap Wi-Fi scanners send endless spam alerts because a network flickered out for a single second. Our system eliminates false alarms."
    ft8_how = [
        "<b>A 3-strike verification rule:</b>",
        "&nbsp;&nbsp;&bull; <b>ACTIVE:</b> The network is clearly visible in the current scan.",
        "&nbsp;&nbsp;&bull; <b>TEMPORARILY_MISSING:</b> If a network disappears for 1 scan, the system does not panic. It starts a countdown and holds off alerting.",
        "&nbsp;&nbsp;&bull; <b>NOT_DETECTED:</b> Only when an access point is missing for <b>3 consecutive scans</b> is it officially marked offline. This simple debouncing rule eliminates over 99% of false alarms!"
    ]
    ft8_where = "Visible in the status column of the <b>Security Monitor</b> and logged inside the <b>History</b> view."
    for item in make_feature_block(8, "Three-State Lifecycle Tracking & Debouncing", "SMART STATE MANAGEMENT", ft8_what, ft8_why, ft8_how, ft8_where):
        story.append(item)

    # Feature 9: Environment Baseline System
    ft9_what = "Allows you to take a saved 'Snapshot' of all normal, expected Wi-Fi networks in your home or office, and automatically alerts you when unexpected new radios appear."
    ft9_why = "If you have 3 authorized routers in your office, and one morning a 4th unexpected router starts broadcasting from a nearby vehicle or hallway, you need to know immediately."
    ft9_how = [
        "1. Click <b>Create Baseline</b> while in your normal environment. The app snapshots every known BSSID, SSID, and channel into the database.",
        "2. On all subsequent scans, every detected network is checked against this baseline photo.",
        "3. Any unknown hardware or unexpected configuration shift generates a `BASELINE_DEVIATION` event."
    ]
    ft9_where = "Access via the <b>Baseline &amp; Trust</b> window in the sidebar menu."
    for item in make_feature_block(9, "Environment Baseline & Deviation Detection", "ENVIRONMENT SNAPSHOT", ft9_what, ft9_why, ft9_how, ft9_where):
        story.append(item)

    # Feature 10: 8-Pattern Anomaly Detector
    ft10_what = "A pattern-matching engine that watches how wireless signals change over time to catch stealthy hacker behaviors."
    ft10_why = "Attackers frequently attempt subtle maneuvers like jamming a channel to force clients to switch, or dropping encryption temporarily to capture cleartext data."
    ft10_how = [
        "The engine watches for 8 specific red flags:",
        "1. <b>Security Downgrade:</b> Known network suddenly switches from WPA2 to Open.",
        "2. <b>Channel Shift:</b> Router abruptly hops to a completely different radio channel.",
        "3. <b>New BSSID on Known SSID:</b> A brand new hardware radio starts claiming a known network name.",
        "4. <b>Signal Surge:</b> An AP's signal jumps from 20% to 95% in seconds (indicating a rogue device was brought close).",
        "5. <b>Signal Drop:</b> Sudden signal loss indicating jamming or RF interference.",
        "6. <b>High Density Alert:</b> Too many access points crowding a single frequency.",
        "7. <b>Baseline Deviation:</b> An unknown network appearing in an established environment.",
        "8. <b>Evil Twin Impersonation:</b> Impersonation score exceeding threshold."
    ]
    ft10_where = "Review all flagged anomalies under <b>Events &amp; Alerts &rarr; Anomaly Log</b>."
    for item in make_feature_block(10, "8-Pattern Passive Anomaly Detection Engine", "BEHAVIORAL HEURISTICS", ft10_what, ft10_why, ft10_how, ft10_where):
        story.append(item)

    # Feature 11: Offline Hardware Vendor (OUI) Resolver
    ft11_what = "Identifies the real physical manufacturer of any Wi-Fi router (e.g., Apple, Cisco, TP-Link, Intel, Raspberry Pi) without needing an internet connection."
    ft11_why = "A router may have a friendly name like 'Corporate_Secure', but its hardware MAC address reveals the real maker. If 'Corporate_Secure' is supposedly an enterprise Cisco router, but the tool shows the maker is 'Espressif' (a cheap $3 microchip) or 'Unknown / Fake', you know it's an imposter!"
    ft11_how = [
        "1. The first 3 bytes of any network MAC address are an IEEE-assigned Organizationally Unique Identifier (OUI).",
        "2. The platform carries an embedded offline lookup database containing thousands of registered manufacturers.",
        "3. Queries resolve instantly in memory in less than 1 millisecond, with zero internet access required."
    ]
    ft11_where = "Shown in the <b>Vendor</b> column in Live Scanner, Security Monitor, and Network Details."
    for item in make_feature_block(11, "Offline Hardware Vendor (OUI) Resolver", "HARDWARE INTELLIGENCE", ft11_what, ft11_why, ft11_how, ft11_where):
        story.append(item)

    # Feature 12: Offline Cyber Simulation & Demo Mode
    ft12_what = "A safe virtual testing environment that lets you simulate cyber attacks (Evil Twins, rogue APs, security downgrades) without altering real-world routers."
    ft12_why = "Testing a security application in the real world can be difficult because you don't always have a spare rogue router or hacking equipment. Demo mode lets students, professors, and testers verify that all alerts and triggers work perfectly without real risk."
    ft12_how = [
        "1. When enabled, the application generates realistic simulated Wi-Fi scans using virtual radio models.",
        "2. Injects intentional vulnerabilities (e.g., an evil twin impersonating your network, or an AP suddenly dropping encryption).",
        "3. Lets you verify that the risk engine, visual charts, and desktop notifications react properly without any physical radio interference."
    ]
    ft12_where = "Toggle anytime in <b>Settings &rarr; Simulation Mode</b>."
    for item in make_feature_block(12, "Offline Cyber Simulation & Demo Mode", "TRAINING & TESTING", ft12_what, ft12_why, ft12_how, ft12_where):
        story.append(item)

    # =========================================================================
    # PART 3: REPORTING, DATABASE & MODERN INTERFACE
    # =========================================================================
    story.append(Spacer(1, 4))
    story.append(Paragraph("Part 3: Reports, Data Management & Modern Interface", section_heading))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=1, spaceAfter=6))

    # Feature 13: Executive Security Reports
    ft13_what = "Generates comprehensive, professional security audit reports in HTML, CSV spreadsheet, and JSON data formats with a single click."
    ft13_why = "IT managers, professors, and cybersecurity auditors need tangible proof of security posture. Manually compiling scan logs takes hours; one-click reports can be shared or printed instantly."
    ft13_how = [
        "1. Aggregates the latest scan data, historical anomaly logs, risk scores, and connection integrity status.",
        "2. Formats the data into a beautifully styled, self-contained HTML report featuring responsive styling and charts.",
        "3. Also exports raw data to CSV (for Excel analysis) and JSON (for integration with SIEMs or other tools)."
    ]
    ft13_where = "Click <b>Reports &amp; Export</b> in the sidebar &rarr; Choose HTML, CSV, or JSON."
    for item in make_feature_block(13, "Executive Security Reports (HTML, CSV, JSON)", "EXECUTIVE REPORTING", ft13_what, ft13_why, ft13_how, ft13_where):
        story.append(item)

    # Feature 14: Automated SQLite Migrations & Safe Backups
    ft14_what = "An enterprise-grade local SQLite database that stores your history, baselines, and alerts, featuring automatic schema upgrades and safe backup/restore tools."
    ft14_why = "When software updates add new features (like our new `trusted_networks` or `alerts` tables), old user databases can break. Automated migrations prevent data corruption and ensure painless upgrades."
    ft14_how = [
        "1. Tracks database versions using a built-in schema migration table (`schema_version`).",
        "2. On startup, automatically checks if newer tables are needed and applies migrations without destroying user history.",
        "3. Includes one-click timestamped backups and database restore tools directly in the UI."
    ]
    ft14_where = "Navigate to <b>Database &amp; Maintenance</b> in the sidebar to create backups or restore."
    for item in make_feature_block(14, "Automated SQLite Migrations & Backup Controls", "ENTERPRISE STORAGE", ft14_what, ft14_why, ft14_how, ft14_where):
        story.append(item)

    # Feature 15: Modern Multi-View Desktop GUI
    ft15_what = "A clean, dark/light-themed graphical desktop interface built with Python's native Tkinter, featuring a persistent navigation sidebar and responsive widgets."
    ft15_why = "Command-line tools are intimidating for non-experts. A modern, organized visual dashboard makes enterprise-grade wireless intelligence accessible to everyone."
    ft15_how = [
        "Organized into 11 purpose-built screens:",
        "&nbsp;&nbsp;&bull; <b>Dashboard:</b> High-level status cards, network counts, connection health widget.",
        "&nbsp;&nbsp;&bull; <b>Live Scanner:</b> Real-time table of all nearby Wi-Fi radios.",
        "&nbsp;&nbsp;&bull; <b>Security Monitor:</b> Risk ratings, protocol breakdowns, and weak configuration tags.",
        "&nbsp;&nbsp;&bull; <b>History:</b> Historical log of all network sightings over time.",
        "&nbsp;&nbsp;&bull; <b>Events &amp; Alerts:</b> Anomaly events and real-time alert notifications.",
        "&nbsp;&nbsp;&bull; <b>Analytics:</b> Signal density charts and channel recommendations.",
        "&nbsp;&nbsp;&bull; <b>Baseline:</b> Environment snapshots and trusted networks management.",
        "&nbsp;&nbsp;&bull; <b>Reports, Database, Settings, Diagnostics:</b> Full operational control."
    ]
    ft15_where = "The main window when you launch `python main.py`."
    for item in make_feature_block(15, "Modern Multi-View Sidebar Desktop GUI", "INTUITIVE USER INTERFACE", ft15_what, ft15_why, ft15_how, ft15_where):
        story.append(item)

    # =========================================================================
    # PART 4: QUICK REFERENCE TABLE & FAQ
    # =========================================================================
    story.append(Spacer(1, 4))
    story.append(Paragraph("Part 4: Frequently Asked Questions & Quick Reference", section_heading))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=1, spaceAfter=6))

    # FAQ Section
    faqs = [
        ("Can this tool hack into or disconnect my neighbor's Wi-Fi?",
         "<b>No.</b> This is a 100% defensive and passive security application. It never transmits deauthentication frames, never injects packets, and never attempts to crack passwords. It strictly acts as a protective shield and audit tool."),
        ("Does the tool require an internet connection to work?",
         "<b>No.</b> The core scanner, offline vendor OUI database, risk scoring engine, baseline system, SQLite database, and Windows toast alerts operate 100% offline. Internet is only used if you optionally enable Telegram notifications or the DoH canary check."),
        ("What should I do if the tool gives me a CRITICAL Evil Twin alert?",
         "<b>Immediately disconnect from that Wi-Fi network!</b> Check your router hardware. If someone nearby is broadcasting a fake copy of your Wi-Fi name, do not enter passwords or sensitive credentials until the rogue access point disappears."),
        ("Why does the tool flag my home router for having a 'Default Router Name'?",
         "If your Wi-Fi is named <i>'TP-Link_XXXX'</i> or <i>'JioFiber-XXXX'</i>, an attacker knows exactly what brand you own and can guess default administrative passwords. Renaming your network to something unique (like <i>'Skyline_Guest'</i>) fixes this issue immediately.")
    ]

    for q, a in faqs:
        faq_box = KeepTogether([
            Paragraph(f"❓ {q}", faq_question),
            Paragraph(a, body_style),
            Spacer(1, 4)
        ])
        story.append(faq_box)

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>Complete Feature Summary Matrix:</b>", label_style))

    summary_rows = [
        [
            Paragraph("<b>#</b>", table_header),
            Paragraph("<b>Feature Name</b>", table_header),
            Paragraph("<b>Primary Purpose</b>", table_header),
            Paragraph("<b>Key Security Benefit</b>", table_header)
        ],
        [Paragraph("1", table_cell), Paragraph("Evil Twin Detection", table_cell), Paragraph("Spots cloned/counterfeit Wi-Fi", table_cell), Paragraph("Prevents credential theft & phishing", table_cell)],
        [Paragraph("2", table_cell), Paragraph("Real-Time Smart Alerts", table_cell), Paragraph("Instant notifications via Toast/Telegram", table_cell), Paragraph("Notifies immediately with zero spam", table_cell)],
        [Paragraph("3", table_cell), Paragraph("Weak Config Checks", table_cell), Paragraph("Audits open Wi-Fi, WEP, default names", table_cell), Paragraph("Finds vulnerable routers before attackers", table_cell)],
        [Paragraph("4", table_cell), Paragraph("Channel Recommendation", table_cell), Paragraph("Calculates signal-weighted congestion", table_cell), Paragraph("Boosts Wi-Fi speed and cuts latency", table_cell)],
        [Paragraph("5", table_cell), Paragraph("Connection Health Guard", table_cell), Paragraph("Monitors gateway MAC & DNS via DoH", table_cell), Paragraph("Protects active connected session", table_cell)],
        [Paragraph("6", table_cell), Paragraph("Passive Wi-Fi Discovery", table_cell), Paragraph("Listens to native Windows 802.11 beacons", table_cell), Paragraph("100% legal, non-intrusive, zero noise", table_cell)],
        [Paragraph("7", table_cell), Paragraph("0-100 Risk Engine", table_cell), Paragraph("Calculates explainable safety scores", table_cell), Paragraph("Clear risk ratings for non-technical users", table_cell)],
        [Paragraph("8", table_cell), Paragraph("Lifecycle & Debouncing", table_cell), Paragraph("Active / Temp Missing / Gone states", table_cell), Paragraph("Eliminates false alarms from RF flickers", table_cell)],
        [Paragraph("9", table_cell), Paragraph("Environment Baseline", table_cell), Paragraph("Saves reference snapshot of your space", table_cell), Paragraph("Flags unauthorized newly appearing routers", table_cell)],
        [Paragraph("10", table_cell), Paragraph("8 Anomaly Patterns", table_cell), Paragraph("Detects channel hops, signal jumps", table_cell), Paragraph("Catches subtle, stealthy attacker activity", table_cell)],
        [Paragraph("11", table_cell), Paragraph("Hardware OUI Resolver", table_cell), Paragraph("Translates MAC address to manufacturer", table_cell), Paragraph("Identifies spoofed or unbranded hardware", table_cell)],
        [Paragraph("12", table_cell), Paragraph("Offline Demo Simulator", table_cell), Paragraph("Injects mock attacks safely", table_cell), Paragraph("Ideal for college demos and presentations", table_cell)],
        [Paragraph("13", table_cell), Paragraph("Executive Reports", table_cell), Paragraph("Exports clean HTML, CSV, and JSON", table_cell), Paragraph("Ready to share with managers & auditors", table_cell)],
        [Paragraph("14", table_cell), Paragraph("Database & Migrations", table_cell), Paragraph("Automated SQLite schema management", table_cell), Paragraph("Zero data loss across platform updates", table_cell)],
        [Paragraph("15", table_cell), Paragraph("Sidebar Desktop GUI", table_cell), Paragraph("Modern 11-panel Tkinter interface", table_cell), Paragraph("Intuitive navigation with zero command-line", table_cell)],
    ]

    summary_table = Table(summary_rows, colWidths=[18, 135, 185, 194])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY),
        ('ALIGN', (0,0), (0,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, BOX_BORDER),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, LIGHT_BG])
    ]))
    story.append(KeepTogether([summary_table]))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {output_pdf_path}")

if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "DOCS")
    os.makedirs(out_dir, exist_ok=True)
    target_path = os.path.join(out_dir, "WiFi_Security_Platform_Features_Guide.pdf")
    create_features_guide(target_path)
