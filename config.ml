open Mirage

(** Keys *)

let http_ip =
  let doc = Key.Arg.info ~doc:"Listening HTTP IP address." ["http_ip"] in
  Key.(create "http_ip" Arg.(opt string "127.0.0.1" doc))

let http_port =
  let doc = Key.Arg.info ~doc:"Listening HTTP port." ["http_port"] in
  Key.(create "http_port" Arg.(opt int 8080 doc))

let https_ip =
  let doc = Key.Arg.info ~doc:"Listening HTTPS IP address." ["https_ip"] in
  Key.(create "https_ip" Arg.(opt string "0.0.0.0" doc))

let https_port =
  let doc = Key.Arg.info ~doc:"Listening HTTPS port." ["https_port"] in
  Key.(create "https_port" Arg.(opt int 4433 doc))

let certificate =
  let doc = Key.Arg.info
      ~docv:"FILE"
      ~doc:"The full path to PEM encoded certificate chain FILE\
           \ (may also include the private key)"
      ["cert"]
  in
  Key.(create "cert" Arg.(required string doc))

let privkey =
  let doc = Key.Arg.info
      ~docv:"FILE"
      ~doc:"The full path to PEM encoded unencrypted private key in FILE"
      ["privkey"]
  in
  Key.(create "privkey" Arg.(required string doc))

let haproxy1 =
  let doc = Key.Arg.info
      ~doc:
        "Forward protocol, IP, and port numbers to the destination using\
        \ HA PROXY protocol v1 (for use with nginx, Varnish, etc --\
        \ see http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt)"
      ["haproxy1"]
  in
  Key.(create "haproxy1" Arg.(opt bool false doc))
