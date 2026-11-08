// ========= [ Agent build UI ] =========
function GenerateUI(listeners_type) {
    let container = form.create_container();

    // ---- Timing group ----
    let spinSleep  = form.create_spin();
    spinSleep.setRange(1, 3600);
    spinSleep.setValue(5);

    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(0);

    let timingLayout = form.create_gridlayout();
    timingLayout.addWidget(form.create_label("Sleep (s):"),   0, 0, 1, 1);
    timingLayout.addWidget(spinSleep,                          0, 1, 1, 1);
    timingLayout.addWidget(form.create_label("Jitter (%):"),  1, 0, 1, 1);
    timingLayout.addWidget(spinJitter,                         1, 1, 1, 1);
    timingLayout.setColumnStretch(1, 1);

    let timingPanel = form.create_panel();
    timingPanel.setLayout(timingLayout);

    let timingGroup = form.create_groupbox("Timing");
    timingGroup.setPanel(timingPanel);

    // ---- Agent info group ----
    let labelArch   = form.create_label("x64");
    let labelOs     = form.create_label("Windows");

    let infoLayout = form.create_gridlayout();
    infoLayout.addWidget(form.create_label("Arch:"),      0, 0, 1, 1);
    infoLayout.addWidget(labelArch,                        0, 1, 1, 1);
    infoLayout.addWidget(form.create_label("Platform:"),  1, 0, 1, 1);
    infoLayout.addWidget(labelOs,                          1, 1, 1, 1);
    infoLayout.setColumnStretch(1, 1);

    let infoPanel = form.create_panel();
    infoPanel.setLayout(infoLayout);

    let infoGroup = form.create_groupbox("Agent");
    infoGroup.setPanel(infoPanel);

    // ---- Authentication group ----
    let comboAuth = form.create_combo();
    comboAuth.addItems(["None  (no key baked in)", "Command Auth  (per-build key, multiple runs)", "One Time Auth  (key consumed on first check-in)"]);
    comboAuth.setCurrentIndex(0);

    let authLayout = form.create_gridlayout();
    authLayout.addWidget(form.create_label("Mode:"), 0, 0, 1, 1);
    authLayout.addWidget(comboAuth,                   0, 1, 1, 1);
    authLayout.setColumnStretch(1, 1);

    let authPanel = form.create_panel();
    authPanel.setLayout(authLayout);

    let authGroup = form.create_groupbox("Authentication");
    authGroup.setPanel(authPanel);

    // ---- Evasion group (sleep obfuscation + live stack spoof) ----
    let comboSleepTech = form.create_combo();
    comboSleepTech.addItems(["Timer Spoof", "Ekko Graft", "Ekko"]);
    comboSleepTech.setCurrentIndex(0);

    let checkStackSpoof = form.create_check("Live Stack Spoof");
    checkStackSpoof.setChecked(false);
    checkStackSpoof.setEnabled(false);  // only active with plain Ekko

    form.connect(comboSleepTech, "currentTextChanged", function(text) {
        let isEkko = (text === "Ekko");
        checkStackSpoof.setEnabled(isEkko);
        if (!isEkko) checkStackSpoof.setChecked(false);
    });

    let sleepTechLayout = form.create_gridlayout();
    sleepTechLayout.addWidget(form.create_label("Sleep Tech:"),  0, 0, 1, 1);
    sleepTechLayout.addWidget(comboSleepTech,                     0, 1, 1, 1);
    sleepTechLayout.addWidget(checkStackSpoof,                    1, 0, 1, 2);
    sleepTechLayout.setColumnStretch(1, 1);

    let sleepTechPanel = form.create_panel();
    sleepTechPanel.setLayout(sleepTechLayout);

    let sleepTechGroup = form.create_groupbox("Evasion");
    sleepTechGroup.setPanel(sleepTechPanel);

    // ---- Output format group ----
    let comboFormat = form.create_combo();
    comboFormat.addItems(["Exe", "Service Exe", "DLL", "Shellcode"]);
    comboFormat.setCurrentIndex(0);

    let fmtLayout = form.create_gridlayout();
    fmtLayout.addWidget(form.create_label("Format:"), 0, 0, 1, 1);
    fmtLayout.addWidget(comboFormat,                   0, 1, 1, 1);
    fmtLayout.setColumnStretch(1, 1);

    let fmtPanel = form.create_panel();
    fmtPanel.setLayout(fmtLayout);

    let fmtGroup = form.create_groupbox("Output Format");
    fmtGroup.setPanel(fmtPanel);

    // ---- Root layout: groups stacked vertically ----
    let rootLayout = form.create_gridlayout();
    rootLayout.addWidget(infoGroup,      0, 0, 1, 1);
    rootLayout.addWidget(timingGroup,    1, 0, 1, 1);
    rootLayout.addWidget(sleepTechGroup, 2, 0, 1, 1);
    rootLayout.addWidget(authGroup,      3, 0, 1, 1);
    rootLayout.addWidget(fmtGroup,       4, 0, 1, 1);
    rootLayout.setColumnStretch(0, 1);

    let rootPanel = form.create_panel();
    rootPanel.setLayout(rootLayout);

    container.put("format",       comboFormat);
    container.put("sleep",        spinSleep);
    container.put("jitter",       spinJitter);
    container.put("sleep_tech",   comboSleepTech);
    container.put("stack_spoof",  checkStackSpoof);
    container.put("auth_mode",    comboAuth);


    return {
        ui_panel:      rootPanel,
        ui_container:  container,
        ui_height:     510,
        ui_width:      580
    };
}

// ========= [ Command registration ] =========
function RegisterCommands(listenerType) {
    let cmd_shell = ax.create_command("shell", "Run a shell command via cmd.exe", "shell {cmd}", "Running shell...");
    cmd_shell.addArgString("cmd", true, "Command to execute");

    let cmd_pwd = ax.create_command("pwd", "Print the current working directory", "pwd", "Queuing pwd...");

    let cmd_ls = ax.create_command("ls", "List directory contents", "ls {path}", "Queuing ls...");
    cmd_ls.addArgString("path", false, "Directory to list (default: current)");

    let cmd_exit = ax.create_command("exit", "Terminate the Pain agent", "exit", "Sending exit...");

    let cmd_bof = ax.create_command("execute_bof", "Execute a BOF (Beacon Object File)", "execute_bof {bof_path} {bof_args}", "Sending BOF...");
    cmd_bof.addArgString("bof_path", true,  "Path to the compiled .o file");
    cmd_bof.addArgString("bof_args", false, "Packed arguments from ax.bof_pack() (hex string)");

    let cmd_link_smb = ax.create_command("smb", "Link a child SMB beacon via named pipe", "link smb 192.168.1.1", "Linking SMB child...");
    cmd_link_smb.addArgString("target", true, "Target hostname or IP address");
    cmd_link_smb.addArgString("pipe_name", false, "Pipe name (default: pain)");

    let cmd_link = ax.create_command("link", "Link to a child beacon for pivoting");
    cmd_link.addSubCommands([cmd_link_smb]);

    let cmd_unlink = ax.create_command("unlink", "Disconnect a linked SMB child beacon", "unlink <agent_id>", "Unlinking SMB child...");
    cmd_unlink.addArgString("agent_id", true, "Agent ID of the SMB child to disconnect");

    let group = ax.create_commands_group("pain", [cmd_shell, cmd_pwd, cmd_ls, cmd_exit, cmd_bof, cmd_link, cmd_unlink]);
    return { commands_windows: group };


}
