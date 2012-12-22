int Command_start(Command *cmd);
int Command_stop(Command *cmd);
int Command_load(Command *cmd);
int Command_reload(Command *cmd);
int Command_running(Command *cmd);
int Command_control(Command *cmd);
int Command_shell(Command *cmd);


tns_value_t *tns_filter_str_field(tns_value_t *orig_res, bstring value, int field);
