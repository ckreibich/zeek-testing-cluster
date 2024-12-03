redef Log::enable_local_logging = T;

# Where to send the ping. See zeek_init() below, which may adapt this depending
# on which node is generating load. The manager always sends to the node
# generating the load (the sender), not the one getting clogged (the receiver).
global ping_topic = Cluster::worker_topic;

global ping_ival: interval = 0.5sec;
global counter_tx = 0;
global counter_rx = 0;

# This came back to us from the target, completing a ping roundtrip.
event manager_ping(ctr: count)
	{
	counter_rx = ctr;
	}

event driver() {
	Broker::publish(Cluster::worker_topic, manager_ping, ++counter_tx);

	# If we haven't heard back in a long time, the target has issues.
	# We use 10 seconds / 0.5 secs = 20 as the trigger.
	if ( counter_tx - counter_rx > 20 )
		print fmt("%s LOCKUP", current_time());

	schedule ping_ival { driver() };
}

event zeek_init() {
	if ( getenv("SENDER") == "proxy" )
		ping_topic = Cluster::proxy_topic;

	schedule ping_ival { driver() };
}
