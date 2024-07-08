@load policy/frameworks/management/controller
@load policy/frameworks/management/supervisor/config

redef Management::Controller::name = "controller";

# Disable metrics port assignment by default to reduce baseline noise.
redef Management::Controller::auto_assign_metrics_ports = F;

# For testing it's helpful to see all node output on the console, because it
# then becomes visible via "docker logs".
redef Management::Supervisor::print_stdout = T;
redef Management::Supervisor::print_stderr = T;

# This gives tests a way to overide settings:
@load ./controller-local.zeek
@load ./local.zeek
