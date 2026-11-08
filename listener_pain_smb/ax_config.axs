function ListenerUI(mode_create) {

    // ── Pipe name ─────────────────────────────────────────────────────────────
    let labelPipe = form.create_label("Pipe Name:");
    let textPipe  = form.create_textline("\\\\.\\pipe\\pain");
    if (!mode_create) {
        textPipe.setReadOnly(true);
    }

    // ── Main layout ───────────────────────────────────────────────────────────
    let layout = form.create_gridlayout();

    layout.addWidget(labelPipe, 0, 0, 1, 1);
    layout.addWidget(textPipe,  0, 1, 1, 2);

    layout.setColumnStretch(1, 1);

    let panel = form.create_panel();
    panel.setLayout(layout);

    // ── Container (keys MUST match json:"..." tags in ListenerConfig) ─────────
    let container = form.create_container();

    container.put("pipe_name", textPipe);

    return {
        ui_panel:     panel,
        ui_container: container,
        ui_width:     420,
        ui_height:    80,
    };
}
