function ListenerUI(mode_create) {

    // ── Bind host / port ─────────────────────────────────────────────────────
    let labelHost    = form.create_label("Host & port (Bind):");
    let comboHost    = form.create_combo();
    comboHost.setEnabled(mode_create);
    for (let item of ax.interfaces()) comboHost.addItem(item);

    let spinPort = form.create_spin();
    spinPort.setRange(1, 65535);
    spinPort.setValue(443);
    spinPort.setEnabled(mode_create);

    // ── Trusted host settings ─────────────────────────────────────────────────
    let checkTrustXFH = form.create_check("Trust X-Forwarded-Host");

    let labelTrustedHosts = form.create_label("Additional Trusted Hosts:");
    let textTrustedHosts  = form.create_textmulti();
    textTrustedHosts.setPlaceholder("domain1.com\ndomain2.com");

    // ── Block User Agents ─────────────────────────────────────────────────────
    let labelBlockUA = form.create_label("Block User Agents:");
    let textBlockUA  = form.create_textmulti();
    textBlockUA.setPlaceholder("curl*\nwget*\npython-requests*");

    // ── Domain Rotation ───────────────────────────────────────────────────────
    let labelRotation = form.create_label("Domain Rotation:");
    let comboRotation = form.create_combo();
    comboRotation.addItem("Random");
    comboRotation.addItem("Round Robin");
    comboRotation.addItem("Failover");
    comboRotation.setCurrentIndex(0);

    // ── C2 Profile upload ─────────────────────────────────────────────────────
    let labelProfile = form.create_label("Upload Profile:");
    let fileProfile  = form.create_selector_file();
    fileProfile.setPlaceholder("Select a .json profile file");

    // ── Proxy Settings (groupbox, collapsed by default) ───────────────────────
    let labelProxyUrl  = form.create_label("Proxy URL:");
    let textProxyUrl   = form.create_textline();
    textProxyUrl.setPlaceholder("http://127.0.0.1:8080");

    let labelProxyUser = form.create_label("Username:");
    let textProxyUser  = form.create_textline();

    let labelProxyPass = form.create_label("Password:");
    let textProxyPass  = form.create_textline();

    let proxyGrid = form.create_gridlayout();
    proxyGrid.addWidget(labelProxyUrl,  0, 0, 1, 1);
    proxyGrid.addWidget(textProxyUrl,   0, 1, 1, 2);
    proxyGrid.addWidget(labelProxyUser, 1, 0, 1, 1);
    proxyGrid.addWidget(textProxyUser,  1, 1, 1, 2);
    proxyGrid.addWidget(labelProxyPass, 2, 0, 1, 1);
    proxyGrid.addWidget(textProxyPass,  2, 1, 1, 2);

    let proxyPanel = form.create_panel();
    proxyPanel.setLayout(proxyGrid);

    let proxyGroup = form.create_groupbox("Proxy Settings", true);
    proxyGroup.setPanel(proxyPanel);
    proxyGroup.setChecked(false);

    // ── SSL / HTTPS (groupbox, collapsed by default) ──────────────────────────
    let fileCert = form.create_selector_file();
    fileCert.setPlaceholder("SSL certificate  (leave empty to auto-generate)");

    let fileKey = form.create_selector_file();
    fileKey.setPlaceholder("SSL key          (leave empty to auto-generate)");

    let sslGrid = form.create_gridlayout();
    sslGrid.addWidget(fileCert, 0, 0, 1, 3);
    sslGrid.addWidget(fileKey,  1, 0, 1, 3);

    let sslPanel = form.create_panel();
    sslPanel.setLayout(sslGrid);

    let sslGroup = form.create_groupbox("Use SSL (HTTPS)", true);
    sslGroup.setPanel(sslPanel);
    sslGroup.setChecked(false);

    // ── Listener config label ─────────────────────────────────────────────────
    let labelSection = form.create_label("Listener config");

    // ── Main layout ───────────────────────────────────────────────────────────
    let layout = form.create_gridlayout();

    // row 0: host + port
    layout.addWidget(labelHost,     0, 0, 1, 1);
    layout.addWidget(comboHost,     0, 1, 1, 1);
    layout.addWidget(spinPort,      0, 2, 1, 1);

    // row 1: section label
    layout.addWidget(labelSection,  1, 0, 1, 3);

    // row 2-3: trust X-Forwarded-Host + additional trusted hosts
    layout.addWidget(checkTrustXFH,     2, 0, 1, 3);
    layout.addWidget(labelTrustedHosts, 3, 0, 1, 3);
    layout.addWidget(textTrustedHosts,  4, 0, 1, 3);

    // row 5-6: block user agents
    layout.addWidget(labelBlockUA,  5, 0, 1, 3);
    layout.addWidget(textBlockUA,   6, 0, 1, 3);

    // row 7: domain rotation
    layout.addWidget(labelRotation, 7, 0, 1, 1);
    layout.addWidget(comboRotation, 7, 1, 1, 2);

    // row 8: profile upload
    layout.addWidget(labelProfile,  8, 0, 1, 1);
    layout.addWidget(fileProfile,   8, 1, 1, 2);

    // row 9: proxy groupbox
    layout.addWidget(proxyGroup,    9, 0, 1, 3);

    // row 10: SSL groupbox
    layout.addWidget(sslGroup,     10, 0, 1, 3);

    layout.setColumnStretch(1, 1);

    let panel = form.create_panel();
    panel.setLayout(layout);

    // ── Container (keys MUST match json:"..." tags in ListenerConfig) ─────────
    let container = form.create_container();

    container.put("host_bind",                  comboHost);
    container.put("port_bind",                  spinPort);
    container.put("trust_x_forwarded_host",     checkTrustXFH);
    container.put("additional_trusted_hosts",   textTrustedHosts);
    container.put("block_user_agents",          textBlockUA);
    container.put("domain_rotation_strategy",   comboRotation);
    container.put("uploaded_file",              fileProfile);
    container.put("proxy_url",                  textProxyUrl);
    container.put("proxy_user",                 textProxyUser);
    container.put("proxy_pass",                 textProxyPass);
    container.put("ssl",                        sslGroup);
    container.put("ssl_cert",                   fileCert);
    container.put("ssl_key",                    fileKey);

    return {
        ui_panel:     panel,
        ui_container: container,
        ui_width:     620,
        ui_height:    580,
    };
}
