# Based on many templates including
# https://github.com/mattiasgeniar/varnish-4.0-configuration-templates/blob/master/default.vcl

vcl 4.0;

import std;
import directors;

backend server1 {
  .host = "127.0.0.1";             # IP or Hostname of backend
  .port = "8080";                  # Port Apache or whatever is listening
  .max_connections = 800;          # That's it
  .first_byte_timeout = 300s;      # How long to wait before we receive a first byte from our backend?
  .connect_timeout = 300s;         # How long to wait for a backend connection?
  .between_bytes_timeout = 300s;   # How long to wait between bytes received from our backend?
}

# Only allow purging from specific IPs
acl purge {
    "localhost";
    "127.0.0.1";
    "104.131.26.178"; # eth0
    "10.132.122.116"; # eth1
    "psynapticmedia.com";
}

sub vcl_init {
  # Called when VCL is loaded, before any requests pass through it. Typically used to initialize VMODs.
  new vdir = directors.round_robin();
  vdir.add_backend(server1);
  #vdir.add_backend(server2);
  #vdir.add_backend(server3);
}


sub vcl_recv {
  # Called at the beginning of a request, after the complete request has been received and parsed.
  # Its purpose is to decide whether or not to serve the request, how to do it, and, if applicable,
  # which backend to use.
  # also used to modify the request

  # send all traffic to the vdir director
  set req.backend_hint = vdir.backend();

  # TURN OFF CACHE when needed (just uncomment this only when needed)
  # return(pass);

  # Allow purging from ACL
  if (req.method == "PURGE") {
    if (!client.ip ~ purge) {
    return(synth(405,"Not allowed."));
    }
    return (purge);
  }


  # Normalize the header, remove the port (in case you're testing this on various TCP ports)
  set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

  # set or append the client.ip to X-Forwarded-For header. Important for logging and correct IPs.
  if (req.restarts == 0) {
    if (req.http.X-Forwarded-For) {
      set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    } else {
      set req.http.X-Forwarded-For = client.ip;
    }
  }

###
### Do not Cache: special cases
###

  # Do not cache AJAX requests.
    if (req.http.X-Requested-With == "XMLHttpRequest") {
        return(pass);
    }

  # Post requests will not be cached
    if (req.http.Authorization || req.method == "POST") {
        return (pass);
    }

  # Only cache GET or HEAD requests. This makes sure the POST requests are always passed.
  #if (req.method != "GET" && req.method != "HEAD") {
  #  return (pass);
  #}

  # Dont Cache WordPress post pages and edit pages
    if (req.url ~ "(wp-admin|post\.php|edit\.php|wp-login)") {
        return(pass);
    }
    if (req.url ~ "/wp-cron.php" || req.url ~ "preview=true") {
        return (pass);
    }

  # Woocommerce
    if (req.url ~ "(cart|my-account|checkout|addons)") {
        return (pass);
    }
    if ( req.url ~ "\?add-to-cart=" ) {
        return (pass);
    }

  # Paid memberships Pro PMP
    if ( req.url ~ "(membership-account|membership-checkout)" ) {
        return (pass);
    }

  # WordPress Social Login Plugin. Note: Need to develop this. Please share if you have an example.
    if (req.url ~ "(wordpress-social-login|wp-social-login)") {
        return (pass);
    }

  # WP-Affiliate
    if ( req.url ~ "\?ref=" ) {
        return (pass);
    }

  # phpBB Logged in users and ACP
    if ( req.url ~ "(/forumPM/adm/|ucp.php?mode=|\?mode=edit)" ) {
        return (pass);
    }


###
###    http header Cookie
###    Remove some cookies (if found)
###    Cache This Stuff
###
# https://www.varnish-cache.org/docs/4.0/users-guide/increasing-your-hitrate.html#cookies

  ### COOKIE MADNESS.

    # Remove the "has_js" cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

    # Remove any Google Analytics based cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");

    # Remove the Quant Capital cookies (added by some plugin, all __qca)
    set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

    # Remove the wp-settings-1 cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-1=[^;]+(; )?", "");

    # Remove the wp-settings-time-1 cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-time-1=[^;]+(; )?", "");

    # Remove the wp test cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wordpress_test_cookie=[^;]+(; )?", "");

    # Remove the phpBB cookie. This will help us cache bots and anonymous users.
    set req.http.Cookie = regsuball(req.http.Cookie, "style_cookie=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "phpbb3_psyfx_track=[^;]+(; )?", "");

    # Remove the cloudflare cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "__cfduid=[^;]+(; )?", "");

    # Remove the PHPSESSID in members area cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "PHPSESSID=[^;]+(; )?", "");

    # Are there cookies left with only spaces or that are empty?
    if (req.http.cookie ~ "^\s*$") {
    unset req.http.cookie;
    }

  # MEGA DROP. Drop ALL cookies sent to WordPress, except those originating from the URLs defined.
  # This increases HITs significantly, but be careful it can also break plugins that need cookies.
  # Note: The /members/ directory had problems with PMP login and social login plugin.
  # Adding it to the exclude list here (and including it below in the "Retain cookies" list) fixed login.
  # This works better than than other cookie removal examples found on varnish's website.
  # Note phpBB directory (forumPM) also passes cookies here.
  if (!(req.url ~ "(wp-login|wp-admin|cart|my-account|checkout|addons|wordpress-social-login|wp-login\.php|forumPM|members)")) {
  unset req.http.cookie;
  }

  # Normalize the query arguments.
  # Note: Placing this above the "do not cache" section breaks some WP theme elements and admin functionality.
  set req.url = std.querysort(req.url);

  # Large static files are delivered directly to the end-user without
  # waiting for Varnish to fully read the file first.
  # Varnish 4 fully supports Streaming, so see do_stream in vcl_backend_response() to witness the glory.
  if (req.url ~ "^[^?]*\.(mp[34]|rar|tar|tgz|wav|zip|bz2|xz|7z|avi|mov|ogm|mpe?g|mk[av])(\?.*)?$") {
    unset req.http.Cookie;
    return (hash);
  }

  # Cache all static files by Removing all cookies for static files
  # Remember, do you really need to cache static files that don't cause load? Only if you have memory left.
  # Here I decide to cache these static files. For me, most of them are handled by the CDN anyway.
  if (req.url ~ "^[^?]*\.(bmp|bz2|css|doc|eot|flv|gif|ico|jpeg|jpg|js|less|pdf|png|rtf|swf|txt|woff|xml)(\?.*)?$") {
    unset req.http.Cookie;
    return (hash);
  }

  # Cache all static files by Removing all cookies for static files - These file extensions are generated by WP Super Cache.
  if (req.url ~ "^[^?]*\.(html|htm|gz)(\?.*)?$") {
    unset req.http.Cookie;
    return (hash);
  }

  # Do not cache Authorized requests.
    if (req.http.Authorization) {
        return(pass);
    }

 # Cache all others requests.
 # Note Varnish v4: vcl_recv must now return hash instead of lookup
    return (hash);
}


sub vcl_pipe {
  # Called upon entering pipe mode.
  # In this mode, the request is passed on to the backend, and any further data from both the client
  # and backend is passed on unaltered until either end closes the connection. Basically, Varnish will
  # degrade into a simple TCP proxy, shuffling bytes back and forth. For a connection in pipe mode,
  # no other VCL subroutine will ever get called after vcl_pipe.

  # Note that only the first request to the backend will have
  # X-Forwarded-For set.  If you use X-Forwarded-For and want to
  # have it set for all requests, make sure to have:
  # set bereq.http.connection = "close";
  # here.  It is not set by default as it might break some broken web
  # applications, like IIS with NTLM authentication.

  # set bereq.http.Connection = "Close";

  return (pipe);
}


sub vcl_pass {
  # Called upon entering pass mode. In this mode, the request is passed on to the backend, and the
  # backend's response is passed on to the client, but is not entered into the cache. Subsequent
  # requests submitted over the same client connection are handled normally.

  # return (pass);
}


# The data on which the hashing will take place
sub vcl_hash {
  # Called after vcl_recv to create a hash value for the request. This is used as a key
  # to look up the object in Varnish.

  hash_data(req.url);

  if (req.http.host) {
    hash_data(req.http.host);
  } else {
    hash_data(server.ip);
  }

  # hash cookies for requests that have them
  if (req.http.Cookie) {
    hash_data(req.http.Cookie);
  }

  # If the client supports compression, keep that in a different cache
  if (req.http.Accept-Encoding) {
      hash_data(req.http.Accept-Encoding);
  }

  return (lookup);
}


# Handle the HTTP request coming from our backend
sub vcl_backend_response {
  # Called after the response headers has been successfully retrieved from the backend.

  # Sometimes, a 301 or 302 redirect formed via Apache's mod_rewrite can mess with the HTTP port that is being passed along.
  # This often happens with simple rewrite rules in a scenario where Varnish runs on :80 and Apache on :8080 on the same box.
  # A redirect can then often redirect the end-user to a URL on :8080, where it should be :80.
  # This may need fine tuning on your setup.
  # To prevent accidental replace, we only filter the 301/302 redirects for now.
  if (beresp.status == 301 || beresp.status == 302) {
    set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
  }

###
### Overall TTL
### Note: The TTL is designed to be somewhat aggressive here, to keep things in cache.
###
  # Lets get this party started.
  # This will keep things in cache longer
  if (beresp.ttl > 0s) {
  unset beresp.http.expires;
  set beresp.http.cache-control = "max-age=900";
  set beresp.ttl = 4d; # how long you cache objects
  set beresp.http.magicmarker = "1";
  }

  # Allow stale content, in case the backend goes down.
  # make Varnish keep all objects for x hours beyond their TTL
  set beresp.grace = 12h;

###
### Static Files
###
  # Enable cache for all static files
  # Monitor your cache size, if you get data nuked out of it, consider giving up the static file cache.
  # More reading here: https://ma.ttias.be/stop-caching-static-files/
  if (bereq.url ~ "^[^?]*\.(bmp|bz2|css|doc|eot|flv|gif|ico|jpeg|jpg|js|less|mp[34]|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip)(\?.*)?$") {
    set beresp.ttl = 2d; # set a TTL for these optional.
    unset beresp.http.set-cookie;
  }

  # Cache all static files by Removing all cookies for static files - Note: These file extensions are generated by WordPress WP Super Cache.
  if (bereq.url ~ "^[^?]*\.(html|htm|gz)(\?.*)?$") {
    set beresp.ttl = 1d; # set a TTL for these optional.
    unset beresp.http.set-cookie;
  }

###
### Targeted TTL
###
  # Members section is very dynamic and uses cookies (see cookie settings in vcl_recv).
  if (bereq.url ~ "/members/") {
    set beresp.ttl = 2d;
  }
  # My Shop section is fairly static when browsing the catalog, but woocommerce is passed in vcl_recv.
  if (bereq.url ~ "/psyshop/") {
    set beresp.ttl = 1d;
  }
  # phBB Forum
  # Note: Cookies are dropped for phpBB in vcl_recv which disables the forums cookies, however, logged in users still get a hash.
  # I set the anonymous user as a bot in phpBB admin settings. As bots dont use cookies, this gives 99% hit rate.
  if (bereq.url ~ "/forumPM/") {
    set beresp.ttl = 2h;
  }
  # Long ttl sites
  if (bereq.url ~ "(example.com|example2.com)") {
    set beresp.ttl = 1w;
  }

  # Large static files are delivered directly to the end-user without
  # waiting for Varnish to fully read the file first.
  # Varnish 4 fully supports Streaming, so use streaming here to avoid locking.
  # I do not stream large files from my server, I use a CDN or dropbox, so I have not tested this.
  if (bereq.url ~ "^[^?]*\.(mp[34]|rar|tar|tgz|wav|zip|bz2|xz|7z|avi|mov|ogm|mpe?g|mk[av])(\?.*)?$") {
    unset beresp.http.set-cookie;
    set beresp.do_stream = true;  # Check memory usage it'll grow in fetch_chunksize blocks (128k by default) if the backend doesn't send a Content-Length header, so only enable it for big objects
    set beresp.do_gzip = false;   # Don't try to compress it for storage
  }

  # don't cache response to posted requests or those with basic auth
  if ( bereq.method == "POST" || bereq.http.Authorization ) {
    set beresp.uncacheable = true;
    set beresp.ttl = 120s;
    return (deliver);
        }

  return (deliver);
}


# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
  # Called before a cached object is delivered to the client.

  if (obj.hits > 0) { # Add debug header to see if it's a HIT/MISS and the number of hits, disable when not needed
    set resp.http.X-Cache = "HIT";
  } else {
    set resp.http.X-Cache = "MISS";
  }

  # Please note that obj.hits behaviour changed in 4.0, now it counts per objecthead, not per object
  # and obj.hits may not be reset in some cases where bans are in use. See bug 1492 for details.
  # So take hits with a grain of salt
  set resp.http.X-Cache-Hits = obj.hits;

  # Remove some headers: PHP version
   unset resp.http.X-Powered-By;

  # Remove some headers: Apache version & OS
  unset resp.http.Server;
  unset resp.http.X-Drupal-Cache;
  unset resp.http.X-Varnish;
  unset resp.http.Age;
  unset resp.http.Via;
  unset resp.http.Link;
  unset resp.http.X-Generator;

  if (resp.http.magicmarker) {
  unset resp.http.magicmarker;
  set resp.http.age = "0";
  }

  return (deliver);
}



sub vcl_synth {
  if (resp.status == 720) {
    # We use this special error status 720 to force redirects with 301 (permanent) redirects
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 301;
    return (deliver);
  } elseif (resp.status == 721) {
    # And we use error status 721 to force redirects with a 302 (temporary) redirect
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 302;
    return (deliver);
  }

  return (deliver);
}


sub vcl_fini {
  # Called when VCL is discarded only after all requests have exited the VCL.
  # Typically used to clean up VMODs.

  return (ok);
}
