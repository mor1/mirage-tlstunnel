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

let haproxy1 =
  let doc = Key.Arg.info
      ~doc:
        "Forward protocol, IP, and port numbers to the destination using\
        \ HA PROXY protocol v1 (for use with nginx, Varnish, etc --\
        \ see http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt)"
      ["haproxy1"]
  in
  Key.(create "haproxy1" Arg.(opt bool false doc))

(* can't create devices from parameters at present; cf
     https://github.com/mirage/mirage/issues/571#issuecomment-237903266

let certificate =
  let doc = Key.Arg.info
      ~docv:"FILE"
      ~doc:"The full path to PEM encoded certificate chain FILE\
           \ (may also include the private key)"
      ["cert"]
  in
  Key.(create "cert" Arg.(required ~stage:`Configure string doc))

let privkey =
  let doc = Key.Arg.info
      ~docv:"FILE"
      ~doc:"The full path to PEM encoded unencrypted private key in FILE"
      ["privkey"]
  in
  Key.(create "privkey" Arg.(required ~stage:`Configure string doc))

(** Devices *)

let privkey_disk =
  match Key.(default @@ value privkey) with
  | None -> failwith "BAD PRIVKEY! BAD!"
  | Some file -> generic_kv_ro file

let certificate_disk =
  match Key.(default @@ value certificate) with
  | None -> failwith "BAD CERTIFICATE! BAD!"
  | Some file -> generic_kv_ro file
*)

let privkey_disk = generic_kv_ro "privkey"
let certificate_disk = generic_kv_ro "certificate"

(** Go! *)
let main =
  let keys =
    let a = Key.abstract in
    [ a http_ip; a http_port; a https_ip; a https_port; a haproxy1 ]
  in
  foreign ~keys "Tlstunnel.Main" (clock @-> kv_ro @-> kv_ro @-> job)

let () =
  register "tlstunnel" [
    main $ default_clock $ certificate_disk $ privkey_disk
  ]
