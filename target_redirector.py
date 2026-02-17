# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IProxyListener
from javax.swing import (
    JPanel, JCheckBox, JLabel, JTextField, BoxLayout, Box,
    BorderFactory, JSeparator, SwingConstants
)
from java.awt import (
    Dimension, Font, Color, GridBagLayout, GridBagConstraints, Insets,
    BorderLayout
)


class BurpExtender(IBurpExtender, ITab, IHttpListener, IProxyListener):
    """
    Burp Suite extension that redirects requests from one domain to another.
    Provides a UI tab with controls for enabling/disabling redirection,
    specifying original and redirect domains, and forcing HTTPS.
    """

    # ------------------------------------------------------------------ #
    #  IBurpExtender
    # ------------------------------------------------------------------ #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Target Redirector")

        self._build_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)

        callbacks.customizeUiComponent(self._main_panel)

        print("[Target Redirector] Extension loaded successfully.")

    # ------------------------------------------------------------------ #
    #  ITab
    # ------------------------------------------------------------------ #
    def getTabCaption(self):
        return "Target Redirector"

    def getUiComponent(self):
        return self._main_panel

    # ------------------------------------------------------------------ #
    #  UI construction
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        # Outer wrapper that pushes content to the top-left
        self._main_panel = JPanel(BorderLayout())

        # Inner content panel using GridBagLayout for clean alignment
        inner = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.NONE
        row = 0

        # ---- Title ----
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(10, 10, 4, 10)
        title = JLabel("Target Redirector")
        title.setFont(Font("SansSerif", Font.BOLD, 18))
        inner.add(title, gbc)
        row += 1

        # ---- Subtitle ----
        gbc.gridy = row
        gbc.insets = Insets(0, 10, 10, 10)
        subtitle = JLabel("Redirect HTTP requests from one domain to another")
        subtitle.setFont(Font("SansSerif", Font.PLAIN, 12))
        subtitle.setForeground(Color(100, 100, 100))
        inner.add(subtitle, gbc)
        row += 1

        # ---- Separator ----
        gbc.gridy = row
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(2, 10, 8, 10)
        inner.add(JSeparator(SwingConstants.HORIZONTAL), gbc)
        gbc.fill = GridBagConstraints.NONE
        row += 1

        # ---- Enable checkbox ----
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(6, 10, 10, 10)
        self._chk_enabled = JCheckBox("Enable Redirection")
        self._chk_enabled.setFont(Font("SansSerif", Font.BOLD, 13))
        inner.add(self._chk_enabled, gbc)
        row += 1

        # ---- Original Domain label ----
        gbc.gridy = row
        gbc.gridwidth = 1
        gbc.gridx = 0
        gbc.insets = Insets(6, 10, 4, 8)
        lbl_orig = JLabel("Original Domain:")
        lbl_orig.setFont(Font("SansSerif", Font.PLAIN, 13))
        inner.add(lbl_orig, gbc)

        # ---- Original Domain text field ----
        gbc.gridx = 1
        gbc.insets = Insets(6, 0, 4, 10)
        self._txt_original = JTextField(28)
        self._txt_original.setToolTipText("e.g. abc.cd")
        inner.add(self._txt_original, gbc)
        row += 1

        # ---- Redirect To label ----
        gbc.gridy = row
        gbc.gridx = 0
        gbc.insets = Insets(4, 10, 6, 8)
        lbl_redir = JLabel("Redirect To:")
        lbl_redir.setFont(Font("SansSerif", Font.PLAIN, 13))
        inner.add(lbl_redir, gbc)

        # ---- Redirect To text field ----
        gbc.gridx = 1
        gbc.insets = Insets(4, 0, 6, 10)
        self._txt_redirect = JTextField(28)
        self._txt_redirect.setToolTipText("e.g. abcd.com")
        inner.add(self._txt_redirect, gbc)
        row += 1

        # ---- Separator ----
        gbc.gridy = row
        gbc.gridx = 0
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(8, 10, 8, 10)
        inner.add(JSeparator(SwingConstants.HORIZONTAL), gbc)
        gbc.fill = GridBagConstraints.NONE
        row += 1

        # ---- Force HTTPS checkbox ----
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(4, 10, 10, 10)
        self._chk_https = JCheckBox("Force HTTPS on redirected request")
        self._chk_https.setFont(Font("SansSerif", Font.PLAIN, 13))
        inner.add(self._chk_https, gbc)
        row += 1

        # ---- Separator ----
        gbc.gridy = row
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(4, 10, 8, 10)
        inner.add(JSeparator(SwingConstants.HORIZONTAL), gbc)
        gbc.fill = GridBagConstraints.NONE
        row += 1

        # ---- Status label ----
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.insets = Insets(4, 10, 10, 10)
        self._lbl_status = JLabel("Status: Idle")
        self._lbl_status.setFont(Font("SansSerif", Font.ITALIC, 12))
        self._lbl_status.setForeground(Color(80, 80, 80))
        inner.add(self._lbl_status, gbc)

        # Place inner panel at the top-left of the outer panel
        self._main_panel.add(inner, BorderLayout.NORTH)

    # ------------------------------------------------------------------ #
    #  Core redirect logic (shared by both listeners)
    # ------------------------------------------------------------------ #
    def _do_redirect(self, messageInfo, source_name):
        """
        Performs the host, header, and protocol rewrite on the given
        IHttpRequestResponse if the destination matches the Original Domain.
        Returns True if a redirect was applied, False otherwise.
        """
        # Check if redirection is enabled
        if not self._chk_enabled.isSelected():
            return False

        # Read user-supplied domains (strip whitespace, use str() for Jython)
        original_domain = str(self._txt_original.getText()).strip()
        redirect_domain = str(self._txt_redirect.getText()).strip()

        if not original_domain or not redirect_domain:
            return False

        # ---- Host check ----
        http_service = messageInfo.getHttpService()
        current_host = str(http_service.getHost())

        if current_host.lower() != original_domain.lower():
            # Not our target - pass through without any modification
            return False

        # ---- Determine new protocol / port ----
        if self._chk_https.isSelected():
            new_port = 443
            use_https = True
        else:
            new_port = http_service.getPort()
            use_https = str(http_service.getProtocol()) == "https"

        new_protocol = "https" if use_https else "http"

        # ---- Update Host, Origin, and Referer headers ----
        request_bytes = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(request_bytes)
        headers = list(request_info.getHeaders())

        new_headers = []
        for header in headers:
            h = str(header)
            h_lower = h.lower()

            if h_lower.startswith("host:"):
                # Replace Host header with redirect domain
                new_headers.append("Host: " + str(redirect_domain))

            elif h_lower.startswith("origin:"):
                # Replace the original domain in Origin header
                origin_val = h.split(":", 1)[1].strip()
                origin_val = origin_val.replace(str(original_domain), str(redirect_domain))
                # Also fix protocol if forcing HTTPS
                if use_https:
                    origin_val = origin_val.replace("http://", "https://")
                new_headers.append("Origin: " + origin_val)

            elif h_lower.startswith("referer:"):
                # Replace the original domain in Referer header too
                referer_val = h.split(":", 1)[1].strip()
                referer_val = referer_val.replace(str(original_domain), str(redirect_domain))
                if use_https:
                    referer_val = referer_val.replace("http://", "https://")
                new_headers.append("Referer: " + referer_val)

            else:
                new_headers.append(h)

        body_offset = request_info.getBodyOffset()
        body = request_bytes[body_offset:]
        new_request = self._helpers.buildHttpMessage(new_headers, body)
        messageInfo.setRequest(new_request)

        # ---- Build and set new HttpService (AFTER headers so everything is consistent) ----
        try:
            new_service = self._helpers.buildHttpService(
                str(redirect_domain),
                new_port,
                use_https,
            )
            messageInfo.setHttpService(new_service)
        except Exception as e:
            print("[Target Redirector] Warning: buildHttpService raised: %s - continuing anyway" % str(e))

        # ---- Logging ----
        protocol_info = " (forced HTTPS)" if use_https else ""
        print(
            "[Target Redirector] %s | Redirected: %s -> %s%s"
            % (source_name, original_domain, redirect_domain, protocol_info)
        )

        self._lbl_status.setText(
            "Status: Last redirect  %s -> %s" % (original_domain, redirect_domain)
        )
        return True

    # ------------------------------------------------------------------ #
    #  IProxyListener  (fires EARLY, before the request leaves the proxy)
    # ------------------------------------------------------------------ #
    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return
        msg_info = message.getMessageInfo()
        self._do_redirect(msg_info, "Proxy")
        # Re-set on the intercepted proxy message to ensure Burp picks it up
        message.setInterceptAction(message.ACTION_FOLLOW_RULES)

    # ------------------------------------------------------------------ #
    #  IHttpListener  (fires for ALL tools: Repeater, Scanner, Intruder, etc.)
    # ------------------------------------------------------------------ #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        # Skip Proxy here - already handled by IProxyListener above
        if toolFlag == self._callbacks.TOOL_PROXY:
            return
        self._do_redirect(messageInfo, "Tool-%d" % toolFlag)
