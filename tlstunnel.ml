open Lwt.Infix
open Mirage_types_lwt

let src = Logs.Src.create "tlstunnel" ~doc:"TlsTunnel"
module Log = (val Logs.src_log src : Logs.LOG)

module Main (Clock: PCLOCK) (Keys: KV_RO) (Stack: STACKV4) = struct

  module TCP = Stack.TCPV4
  module TLS = Tls_mirage.Make(TCP)
  module X509 = Tls_mirage.X509(Keys)(Clock)

  type rd_wr_result = Stop | Continue

  let stored_tags = Lwt.new_key ()

  let rec read_write plain tls =
    let tags = Lwt.get stored_tags in
    Log.info (fun m -> m ?tags "read_write");
    let inbound =
      TLS.read tls >>= function
      | Ok (`Data buf) ->
        begin
          let buflen = Cstruct.len buf in
          Log.info (fun m -> m ?tags "inbound TLS read %d bytes" buflen);
          Log.debug (fun m -> m ?tags "inbound TLS buf: %s" (Cstruct.to_string buf));
          if      buflen = 0 then Lwt.return Continue
          else if buflen < 0 then Lwt.return Stop
          else (* buflen > 0 *)
            TCP.write plain buf >>= function
            | Ok () ->
              Log.info (fun m -> m ?tags "inbound TCP wrote %d bytes" buflen);
              Lwt.return Continue
            | Error e ->
              Log.err (fun m -> m ?tags "inbound TCP write: %a" TCP.pp_write_error e);
              Lwt.return Stop
        end
      | Ok `Eof ->
        Log.info (fun m -> m ?tags "inbound TLS read: EOF.");
        Lwt.return Stop
      | Error e ->
        Log.err (fun m -> m ?tags "read TLS error: %a" TLS.pp_error e);
        Lwt.return Stop
    and outbound =
      TCP.read plain >>= function
      | Ok (`Data buf) ->
        begin
          let buflen = Cstruct.len buf in
          Log.info (fun m -> m ?tags "outbound TCP read %d bytes" buflen);
          Log.debug (fun m -> m ?tags "outbound TCP buf: %s" (Cstruct.to_string buf));
          if      buflen = 0 then Lwt.return Continue
          else if buflen < 0 then Lwt.return Stop
          else (* buflen > 0 *)
            TLS.write tls buf >>= function
            | Ok () ->
              Log.info (fun m -> m ?tags "outbound TLS wrote %d bytes" buflen);
              Lwt.return Continue
            | Error e ->
              Log.err (fun m -> m ?tags "outbound TLS write: %a" TLS.pp_write_error e);
              Lwt.return Stop
        end
      | Ok `Eof ->
        Log.info (fun m -> m ?tags "outbound TCP read: EOF.");
        Lwt.return Stop
      | Error e ->
        Log.err (fun m -> m ?tags "outbound read: %a" TCP.pp_error e);
        Lwt.return Stop
    in
    Lwt.catch
      (fun () -> inbound <?> outbound)
      (fun exn ->
         Log.info (fun m -> m ?tags:(Lwt.get stored_tags)
                      "tls_rdwr: fail: %s" (Printexc.to_string exn));
         Lwt.return Stop) >>= function
    | Stop -> Lwt.return_unit
    | Continue -> read_write plain tls

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

  let add_tag ntag nval =
    let other = match Lwt.get stored_tags with
      | None -> Logs.Tag.empty
      | Some x -> x
    in
    Logs.Tag.add ntag nval other

  let with_tag ntag nval f =
    Lwt.with_value stored_tags (Some (add_tag ntag nval)) f

  let peer_tag : (Ipaddr.V4.t * int) Logs.Tag.def =
    Logs.Tag.def "peer" ~doc:"connection endpoint"
      Fmt.(pair ~sep:(unit ":") Ipaddr.V4.pp_hum int)

  let accept_tls config to_plain flow =
    with_tag peer_tag (TCP.dst flow) @@ (fun () ->
        TLS.server_of_flow config flow >>= function
        | Ok tls ->
          Log.info (fun f -> f ?tags:(Lwt.get stored_tags)
                       "connect: %s" (tls_info tls));
          to_plain () >>= fun plain ->
          read_write plain tls >>= fun () ->
          TCP.close plain >>= fun () ->
          TLS.close tls
        | Error e ->
          Log.err (fun f -> f ?tags:(Lwt.get stored_tags)
                      "TLS error: %a" TLS.pp_write_error e);
          TCP.close flow)

  let tls_init keys =
    X509.certificate keys `Default >>= fun cert ->
    let config = Tls.Config.server ~certificates:(`Single cert) () in
    Lwt.return config

  let start _clock keys stack _entropy =
    let http_ip = Key_gen.http_ip () in
    let http_port = Key_gen.http_port () in
    Log.info (fun f -> f "forwarding to [%a]:%d/TCP"
                 Ipaddr.V4.pp_hum http_ip http_port);
    let to_plain () =
      TCP.create_connection (Stack.tcpv4 stack) (http_ip, http_port) >>= function
      | Error e ->
        Lwt.fail_with
          (Fmt.strf "outbound [%a]:%d %a"
             Ipaddr.V4.pp_hum http_ip http_port TCP.pp_error e)
      | Ok flow -> Lwt.return flow
    in
    tls_init keys >>= fun config ->
    let https_ip = Key_gen.https_ip ()
    and https_port = Key_gen.https_port ()
    in
    let https_of flow = accept_tls config to_plain flow in
    Stack.listen_tcpv4 stack ~port:https_port https_of;
    Log.info (fun f -> f "listening on [%a]:%d/TCP"
                 Ipaddr.V4.pp_hum https_ip https_port);
    Stack.listen stack

end
