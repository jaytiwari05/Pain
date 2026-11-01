function ListenerUI(mode_create) {
    let container = form.create_container();

    let comboHost = form.create_combo();
    comboHost.setEnabled(mode_create);
    for (let item of ax.interfaces()) comboHost.addItem(item);

    let spinPort = form.create_spin();
    spinPort.setRange(1, 65535);
    spinPort.setValue(8080);
    spinPort.setEnabled(mode_create);

    let textCrc = form.create_textline("deadbeef");
    textCrc.setEnabled(mode_create);

    let certSelector = form.create_selector_file();
    certSelector.setPlaceholder("SSL Certificate (optional - auto-generated if empty)");
    let keySelector = form.create_selector_file();
    keySelector.setPlaceholder("SSL Key (optional - auto-generated if empty)");

    let layout_ssl = form.create_vlayout();
    layout_ssl.addWidget(certSelector);
    layout_ssl.addWidget(keySelector);
    let panel_ssl = form.create_panel();
    panel_ssl.setLayout(layout_ssl);
    let ssl_group = form.create_groupbox("Enable HTTPS (TLS)", true);
    ssl_group.setPanel(panel_ssl);
    ssl_group.setChecked(false);

    let layout = form.create_gridlayout();
    layout.addWidget(form.create_label("Bind Host:"),  0, 0, 1, 1);
    layout.addWidget(comboHost,                        0, 1, 1, 2);
    layout.addWidget(form.create_label("Bind Port:"),  1, 0, 1, 1);
    layout.addWidget(spinPort,                         1, 1, 1, 1);
    layout.addWidget(form.create_label("Agent CRC:"),  2, 0, 1, 1);
    layout.addWidget(textCrc,                          2, 1, 1, 1);
    layout.addWidget(form.create_label("hex magic matched by the agent on check-in"), 2, 2, 1, 1);
    layout.addWidget(ssl_group,                        3, 0, 1, 3);
    layout.setColumnStretch(1, 1);

    let panel = form.create_panel();
    panel.setLayout(layout);

    container.put("host",      comboHost);
    container.put("port",      spinPort);
    container.put("agent_crc", textCrc);
    container.put("ssl",       ssl_group);
    container.put("ssl_cert",  certSelector);
    container.put("ssl_key",   keySelector);

    return {
        ui_panel:     panel,
        ui_container: container,
        ui_height:     340,
        ui_width:      580
    };
}
