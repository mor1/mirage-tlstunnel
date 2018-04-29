open Lwt.Infix
open Mirage_types_lwt

let src = Logs.Src.create "tlstunnel" ~doc:"TlsTunnel"
module Log = (val Logs.src_log src : Logs.LOG)

module Main (Clock: PCLOCK) (Keys: KV_RO) (Stack: STACKV4) = struct

  let https_src = Logs.Src.create "https" ~doc:"HTTPS server"
  module Https_log = (val Logs.src_log https_src : Logs.LOG)

  let http_src = Logs.Src.create "http" ~doc:"HTTP server"
  module Http_log = (val Logs.src_log http_src : Logs.LOG)

  module Logs_reporter = Mirage_logs.Make(Clock)

  module TCP = Stack.TCPV4
  module TLS = Tls_mirage.Make(TCP)
  module X509 = Tls_mirage.X509(Keys)(Clock)

  type rd_wr_result = Stop | Continue

  let rec read_write ~info ~debug ~error plain tls =
    info "read_write";

    let inbound =
      TLS.read tls
      >>= (function
          | Ok (`Data buf) -> (
              let buflen = Cstruct.len buf in
              info (Fmt.strf "inbound read %d bytes" buflen);
              debug (Fmt.strf "inbound buf:\n%s" (Cstruct.to_string buf));
              if      buflen = 0 then Lwt.return Continue
              else if buflen < 0 then Lwt.return Stop
              else (* buflen > 0 *)
                TCP.write plain buf
                >>= function
                | Ok () ->
                  info (Fmt.strf "inbound wrote %d bytes" buflen);
                  Lwt.return Continue
                | Error e ->
                  error (Fmt.strf "inbound write: %a" TCP.pp_write_error e);
                  Lwt.return Stop
            )
          | Ok `Eof ->
            info "inbound read: EOF.";
            Lwt.return Stop
          | Error e ->
            error (Fmt.strf "read error: %a" TLS.pp_error e);
            Lwt.return Stop
        )
    in

    let outbound =
      TCP.read plain
      >>= (function
          | Ok (`Data buf) -> (
              let buflen = Cstruct.len buf in
              info (Fmt.strf "outbound read %d bytes" buflen);
              debug (Fmt.strf "outbound buf:\n%s" (Cstruct.to_string buf));
              if      buflen = 0 then Lwt.return Continue
              else if buflen < 0 then Lwt.return Stop
              else (* buflen > 0 *)
                TLS.write tls buf
                >>= function
                | Ok () ->
                  info ("outbound wrote "^(string_of_int buflen)^" bytes");
                  Lwt.return Continue
                | Error e ->
                  error (Fmt.strf "outbound write: %a" TLS.pp_write_error e);
                  Lwt.return Stop
            )
          | Ok `Eof ->
            info "outbound read: EOF.";
            Lwt.return Stop
          | Error e ->
            error (Fmt.strf "outbound read: %a" TCP.pp_error e);
            Lwt.return Stop
        )
    in

    Lwt.catch
      (fun () -> inbound <?> outbound)
      (function
        | exn ->
          info ("tls_rdwr: fail: "^(Printexc.to_string exn));
          Lwt.return Stop
      )
    >>= function
    | Stop -> Lwt.return_unit
    | Continue -> read_write ~info ~debug ~error plain tls

  let tls_info t =
    let v, c =
      match TLS.epoch t with
      | Ok data -> (data.Tls.Core.protocol_version, data.Tls.Core.ciphersuite)
      | Error _ -> assert false
    in
    let version = Sexplib.Sexp.to_string_hum (Tls.Core.sexp_of_tls_version v)
    and cipher =
      Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite c)
    in
    version ^ ", " ^ cipher

  let accept_tls config to_plain flow f =
    let peer = TCP.dst flow in
    let pp_peer ppf (addr,port) =
      Format.fprintf ppf "%s/%d" (Ipaddr.V4.to_string addr) port
    in

    let info  f = Logs.info  @@ fun m -> m "[%a]" pp_peer peer in
    let debug f = Logs.debug @@ fun m -> m "[%a]" pp_peer peer in
    let error f = Logs.err   @@ fun m -> m "[%a]" pp_peer peer in

    TLS.server_of_flow config flow
    >>= function
    | Ok tls ->
      info (fun f -> f "connect: %a" (tls_info tls));
      to_plain ()
      >>= fun plain ->
      read_write ~info ~debug ~error plain tls
      >>= fun () ->
      TLS.close tls
    | Error e ->
      error (fun f -> f "%a" TLS.pp_error e);
      TCP.close flow

  let tls_init keys =
    X509.certificate keys `Default

    >>= fun cert ->
    let config = Tls.Config.server ~certificates:(`Single cert) () in
    Lwt.return config

  let start clock keys stack _entropy =
    Logs.(set_level (Some Info));
    Logs_reporter.(create clock |> run) @@ fun () ->

    let http_ip = Key_gen.http_ip () in
    let http_port = Key_gen.http_port () in
    Http_log.info (fun f -> f "forwarding to [%s]:%d/TCP" http_ip http_port);

    let to_plain () =
      let http_ipv4 =
        Ipaddr.V4.of_string http_ip |> function
        | None -> failwith ("bad HTTP target IP: "^http_ip)
        | Some ip -> ip
      in
      TCP.create_connection (Stack.tcpv4 stack) (http_ipv4, http_port)
      >>= (function
          | Error e ->
            failwith
              (Fmt.strf "outbound [%s]:%d %a" http_ip http_port TCP.pp_error e)
          | Ok flow -> Lwt.return flow
        )
    in

    tls_init keys

    >>= fun config ->
    let https_ip = "0.0.0.0" in
    let https_port = Key_gen.https_port () in
    let https_of flow = accept_tls config to_plain flow read_write in
    Stack.listen_tcpv4 stack ~port:https_port https_of;
    Https_log.info (fun f -> f "listening on [%s]:%d/TCP" https_ip https_port);
    Stack.listen stack

end
