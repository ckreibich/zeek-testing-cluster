# This test verifies that by default the controller listens globally on ports
# 2149 (websockets) and 2150 (Broker).

# @TEST-REQUIRES: $SCRIPTS/docker-requirements
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff output

. $SCRIPTS/docker-setup
. $SCRIPTS/test-helpers

docker_populate singlehost

# Only run controller, no agent:
ZEEK_ENTRYPOINT=controller.zeek docker_compose_up

# This needs "netstat":
controller_cmd "apt-get -q update && apt-get install -q -y --no-install-recommends net-tools"

# Wait a bit until the services are available from within the container.
try_until controller_cmd "exec 3<>/dev/tcp/127.0.0.1/2149" \
    || fail "controller never offered websocket port"
try_until controller_cmd "exec 3<>/dev/tcp/127.0.0.1/2150" \
    || fail "controller never offered Broker port"

# The controller should be listening on 0.0.0.0:2149 and 0.0.0.0:2150 now.
# The Supervisor should *not* be listening.
controller_cmd "netstat -tpln | grep zeek | awk '{ print \$4 }' | sort" >output
