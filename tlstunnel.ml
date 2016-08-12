open Lwt.Infix

(** Logging. *)
let http_src = Logs.Src.create "tlstunnel/http" ~doc:"TLS Tunnel: HTTP"
module Http_log = (val Logs.src_log http_src : Logs.LOG)

let https_src = Logs.Src.create "tlstunnel/https" ~doc:"TLS Tunnel: HTTPS"
module Https_log = (val Logs.src_log https_src : Logs.LOG)

(** *)

module Main
    (Clock: V1.CLOCK)
    (Keys: V1_LWT.KV_RO)
    (Stack: V1_LWT.STACKV4)
= struct

  module TLS = Tls_mirage.Make(Stack.TCPV4)
  module X509 = Tls_mirage.X509(Keys)(Clock)
  module Https = Cohttp_mirage.Server(TLS)
  module Logs_reporter = Mirage_logs.Make(Clock)

  let tls_info t =
    let v, c =
      match TLS.epoch t with
      | `Ok data -> (data.Tls.Core.protocol_version, data.Tls.Core.ciphersuite)
      | `Error -> assert false
    in
    let version = Sexplib.Sexp.to_string_hum (Tls.Core.sexp_of_tls_version v)
    and cipher =
      Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite c)
    in
    version ^ ", " ^ cipher

  let rec handle flush tls =
    Https_log.info (fun f -> f "handle called! %s" (tls_info tls)) ;
    TLS.read tls
    >>= fun res ->
    flush () >>= fun () -> match res with
    | `Ok buf ->
      TLS.write tls buf
      >>= (function
          | `Ok _ -> handle flush tls
          | `Error _ | `Eof as e -> Lwt.return e
        )
    | err -> Lwt.return err

  let flush () = Https_log.info (fun f -> f "flushing!") ; Lwt.return_unit

  let accept config handler flow =
    Https_log.info (fun f ->
        let a,p = Stack.TCPV4.get_dest flow in
        f "accept called! %s:%d" (Ipaddr.V4.to_string a) p
      ) ;
    TLS.server_of_flow config flow
    >>= (function
        | `Ok tls -> handler flush tls
        | `Error _ | `Eof as e -> Lwt.return e
      )
    >>= (function
        | `Ok _ -> assert false
        | `Error e ->
          Https_log.info (fun f -> f "error: %s" (TLS.error_message e)) ;
          Lwt.return_unit
        | `Eof -> Https_log.info (fun f -> f "EOF.") ;
          Lwt.return_unit
      )

  let start _clock keys stack _entropy =
    Logs.(set_level (Some Info));
    Logs_reporter.(create () |> run) @@ fun () ->

    let http_port = Key_gen.http_port () in
    Http_log.info (fun f -> f "listening on %d/TCP" http_port) ;

    X509.certificate keys `Default
    >>= fun cert ->
    let config = Tls.Config.server ~certificates:(`Single cert) () in
    let https_port = Key_gen.https_port () in
    Https_log.info (fun f -> f "listening on %d/TCP" https_port) ;

    Stack.listen_tcpv4 stack ~port:https_port (accept config handle) ;
    Stack.listen stack
end
