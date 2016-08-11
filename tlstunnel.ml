open Lwt.Infix

(** Logging. *)
let http_src = Logs.Src.create "tlstunnel/http" ~doc:"TLS Tunnel: HTTP"
module Http_log = (val Logs.src_log http_src : Logs.LOG)

let https_src = Logs.Src.create "tlstunnel/https" ~doc:"TLS Tunnel: HTTPS"
module Https_log = (val Logs.src_log https_src : Logs.LOG)

module Stats = struct
  type stats = {
    mutable read : int ;
    mutable written : int
  }

  let new_stats () = { read = 0 ; written = 0 }

  let inc_read s v = s.read <- s.read + v
  let inc_written s v = s.written <- s.written + v

  let print_stats stats =
    "read " ^ (string_of_int stats.read) ^ " bytes, " ^
    "wrote " ^ (string_of_int stats.written) ^ " bytes"
end

module Haproxy1 = struct
  (* implementation of the PROXY protocol as used by haproxy
   * http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
   * This module only implements the protocol detailed in the
   * "2.1. Human-readable header format (Version 1)" section.
   *
   * *)

  let make_header socket =
    (* basically it looks like:
     * PROXY TCP4 SOURCEIP DESTIP SRCPORT DESTPORT\r\n *)
    let own_sockaddr = Lwt_unix.getsockname socket in
    let peer_sockaddr = Lwt_unix.getpeername socket in
    let protocol_string =
      begin
        let open Unix in
        match domain_of_sockaddr own_sockaddr with
        | PF_UNIX  -> failwith "TODO unix socket log and drop"
        | PF_INET  -> "TCP4"
        | PF_INET6 -> "TCP6"
      end in
    let get_addr_port = function
      | Lwt_unix.ADDR_INET (inet_addr , port)
        ->  (Unix.string_of_inet_addr inet_addr) , string_of_int port
      | Lwt_unix.ADDR_UNIX _ -> failwith "TODO addr_unix" in
    let peer_addr, peer_port = get_addr_port peer_sockaddr
    and own_addr, own_port = get_addr_port own_sockaddr in
    let header = String.concat " "
        [ "PROXY" ; protocol_string ; peer_addr ; own_addr ; peer_port ; own_port ]
    in
    header ^ "\r\n"
end

let bufsize = 4096

type res = Stop | Continue

module Main (Clock: V1.CLOCK) (Keys: V1_LWT.KV_RO) = struct

  module X509 = Tls_mirage.X509(Keys)(Clock)
  module Logs_reporter = Mirage_logs.Make(Clock)

  let start _clock keys _entropy =

    Logs.(set_level (Some Info));
    Logs_reporter.(create () |> run) @@ fun () ->

    X509.certificate keys `Default
    >>= fun cert ->

    Lwt.return (Tls.Config.server ~certificates:(`Single cert) ())
    >>= fun cfg ->

    let https_port = Key_gen.https_port () in
    let _tls = `TLS (cfg, `TCP https_port) in
    Https_log.info (fun f -> f "listening on %d/TCP" https_port);

    let http_port = Key_gen.http_port () in
    let _tcp = `TCP http_port in
    Http_log.info (fun f -> f "listening on %d/TCP" http_port);

    Lwt.return_unit
end
