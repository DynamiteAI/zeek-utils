# Adds the orientation field to zeek conn log.  
# Orientation is merely a way to describe the hosts/networks
# involved in the communication, and how it was initiated.  

# Note:: Update Site::local_nets and Site::neighbor_nets 
# for this to be as accurrate as possible.  
module Site;

export {
    redef record Conn::Info += {
        orientation: string &log &optional;
    };
    
    const LOCAL: string = "local";
    const NEIGHBOR: string = "neighbor";
    const EXTERNAL: string = "external";
    const MULTICAST: string = "multicast";
    const BROADCAST: string = "broadcast";
    const INTERNAL: string = "internal";
    const EGRESS: string = "egress";
    const INGRESS: string = "ingress";
    const TO_NEIGHBOR: string = "to_neighbor";
    const FROM_NEIGHBOR: string = "from_neighbor"; 
    const UNKNOWN: string = "unknown";
}

function get_oriented(id: conn_id): string
    {
    if ( |Site::local_nets| == 0 )
        return UNKNOWN;

    local o = "";
    local r = "";

    # test orig 
    if ( Site::is_local_addr(id$orig_h) )
        o = LOCAL;
    else if ( Site::is_neighbor_addr(id$orig_h))
        o = NEIGHBOR;
    else 
        o = EXTERNAL;

    # test resp 
    if ( Site::is_local_addr(id$resp_h) )
        r = LOCAL;
    else if ( Site::is_neighbor_addr(id$resp_h))
        r = NEIGHBOR;
    else if ( id$resp_h in 224.0.0.0/4 )
        r = MULTICAST;    
    else if ( /^255\./ in cat(id$resp_h) || /\.255$/ in cat(id$resp_h) )
        r = BROADCAST;    
    else 
        r = EXTERNAL;

    # now evaluate 
    if ( o == LOCAL && r == LOCAL )
        return INTERNAL;
    else if ( o == LOCAL && r == EXTERNAL )
        return EGRESS;
    else if ( o == EXTERNAL && r == LOCAL )
        return INGRESS;
    else if ( o == EXTERNAL && r == EXTERNAL )
        return EXTERNAL;
    else if ( o == LOCAL && r == NEIGHBOR ) 
        return TO_NEIGHBOR;
    else if ( o == NEIGHBOR && r == LOCAL )
        return FROM_NEIGHBOR;
    else if ( o == LOCAL && r == MULTICAST)
        return MULTICAST;
    else if ( o == LOCAL && r == BROADCAST)
        return BROADCAST;
    else 
        return UNKNOWN;
    }

event connection_state_remove(c: connection) 
    {
    # Populate orientation field 
    c$conn$orientation = get_oriented(c$id);
    }