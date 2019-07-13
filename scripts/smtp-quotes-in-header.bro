@load base/frameworks/notice
@load base/utils/addrs
@load base/utils/directions-and-hosts

module SMTP;

export {
        redef record Info += {
                from:          string          &log &optional;
                to:            set[string]     &log &optional;
        };
@load base/frameworks/notice
}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5
        {
        if ( ! c?$smtp ) return;

        if ( h$name == "MESSAGE-ID" )
                c$smtp$msg_id = h$value;

        else if ( h$name == "RECEIVED" )
                {
                if ( c$smtp?$first_received )
                        c$smtp$second_received = c$smtp$first_received;
                c$smtp$first_received = h$value;
                }

        else if ( h$name == "IN-REPLY-TO" )
                c$smtp$in_reply_to = h$value;

        else if ( h$name == "SUBJECT" )
                c$smtp$subject = h$value;

        else if ( h$name == "FROM" )
                c$smtp$from = to_string_literal(h$value);

        else if ( h$name == "REPLY-TO" )
                c$smtp$reply_to = h$value;

        else if ( h$name == "DATE" )
                c$smtp$date = h$value;

        else if ( h$name == "TO" )
                {
                if ( ! c$smtp?$to )
                        c$smtp$to = set();

                local to_parts = split_string(h$value, /[[:blank:]]*,[[:blank:]]*/);
                for ( i in to_parts )
                        add c$smtp$to[to_string_literal(to_parts[i])];
                }

        else if ( h$name == "X-ORIGINATING-IP" )
                {
                local addresses = extract_ip_addresses(h$value);
                if ( 1 in addresses )
                        c$smtp$x_originating_ip = to_addr(addresses[1]);
                }

        else if ( h$name == "X-MAILER" ||
                  h$name == "USER-AGENT" ||
                  h$name == "X-USER-AGENT" )
                c$smtp$user_agent = h$value;
        }
