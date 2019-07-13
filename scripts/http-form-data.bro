##! This script extracts POSTed HTTP Data

module HTTP;

export {
    redef record Info += {
       body: string &optional &log;
       reassemble_body: bool &optional;
    };

    ## Do not buffer more than this amount of bytes per HTTP message.
    const max_body_size = 5000000;

    ## Only Extract Bodies with these Content-Types
    const extracted_content_types: set[string] =  { "application/x-www-form-urlencoded" } &redef;
}

event http_post_body_complete(c: connection, body: string) &priority=-5
    {
    delete c$http$body;
    }

event http_begin_entity(c: connection, is_orig: bool)
    {
    if (! is_orig)
        return;
    
    if (c$http$method != "POST")
        return;
    
    if ( (! c$http?$client_header_names) || (! c$http?$client_header_values) )
        return;
        
    local header_idx = 0;

    for ( i in c$http$client_header_names ) 
        {
        if ( c$http$client_header_names[i] == "CONTENT-TYPE" )
            {
            local header_value = c$http$client_header_values[i];
            local parts = split_string(header_value, /;/);
            if ( parts[0] in extracted_content_types ) 
                {
                c$http$body = "";  
                }
            }
        }
    if ( c$http$reassemble_body )
        c$http$body = "";
    }

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
    {
    if (! is_orig)
        return;
    
    if (c$http$method != "POST")
        return;
    
    if ( ! c$http?$reassemble_body ) 
        {
        for ( i in c$http$client_header_names ) 
            {
            if ( c$http$client_header_names[i] == "CONTENT-TYPE" )
                {
                local header_value = c$http$client_header_values[i];
                local parts = split_string(header_value, /;/);
                if ( parts[0] in extracted_content_types ) 
                    {
                    c$http$reassemble_body = T;
                    c$http$body = "";  
                    }
                else
                    {
                    c$http$reassemble_body = F;
                    }
                break;
                } 
            }
        }
    
    if ( c$http?$body )
        {
        c$http$body += data;

        if ( c$http$response_body_len < max_body_size )
            return;

        c$http$reassemble_body = F;
        event http_post_body_complete(c, c$http$body);
        }
    }

event http_end_entity(c: connection, is_orig: bool)
    {
    if ( ! c$http?$body )
        return;

    c$http$reassemble_body = F;
    event http_post_body_complete(c, c$http$body);
    }