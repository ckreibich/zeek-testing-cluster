redef Log::enable_local_logging = T;

# Where to send the ping. See zeek_init() below, which adapts this
# depending on whether we generate load worker->proxy or proxy->worker.
global ping_topic = Cluster::proxy_topic;

global padding: string = string_fill(256, "1234567890"); # To eat buffer space
global ping_ival: interval = 0.01sec; # Rapdid, to eat up space quickly
global ping_batch = 20; # Pings to send in one batch. Matters hugely.
global epoch = 0; # Epochs increase with every backpressure-triggered de-peering
global counter = 0; # A ping counter.

# A ping from manager to worker that the worker echoes back, to verify
# liveness of that peering. This should always keep chugging -- if not, it means
# the worker's I/O troubles propagate to the manager: global lockup.
global manager_ping: event(ctr: count);

# A one-way ping to our target. It consumes space via a padding string to speed
# up backpressure. The epoch increases every time a backpressure unpeering
# occurs in the target.
global ping: event(epoch: count, ctr: count, padding: string);

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg )
		return;

	# This is our signal that the proxy is gone. We keep sending pings
	# and bump up the epoch to distinguish before/after the de-peering.

	++epoch;
	print fmt("%s UNPEERED, epoch now %d", current_time(), epoch);
	}

# This comes from the manager. We echo it back.
event manager_ping(ctr: count) &is_used
	{
	Broker::publish(Cluster::manager_topic, manager_ping, ctr);
	}

event driver()
	{
	local i = 0;
	while ( ++i < ping_batch )
		Broker::publish(ping_topic, ping, epoch, ++counter, padding);

	schedule ping_ival { driver() };
	}

event zeek_init() {
	if ( getenv("SENDER") == "proxy" )
		ping_topic = Cluster::worker_topic;

	schedule ping_ival { driver() };
}
