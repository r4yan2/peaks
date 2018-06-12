(***********************************************************************)
(*                                                                     *)
(*                           Objective Caml                            *)
(*                                                                     *)
(*          Francois Rouaix, projet Cristal, INRIA Rocquencourt        *)
(*                                                                     *)
(*  Copyright 1996 Institut National de Recherche en Informatique et   *)
(*  en Automatique.  All rights reserved.  This file is distributed    *)
(*  under the terms of the GNU Library General Public License, with    *)
(*  the special exception on linking described in file ../../LICENSE.  *)
(*                                                                     *)
(***********************************************************************)

(* $Id: db.ml,v 1.1.1.1 2002/10/01 00:10:14 yminsky Exp $ *)

(* Module [Db]: interface to the DB databases *)

(* this collides with Unix *)
type open_flag =
    O_CREAT
  | O_EXCL
  | O_RDONLY
  | O_RDWR
  | O_TRUNC

type routine_flag =
    R_CURSOR
  | R_FIRST
  | R_LAST
  | R_NEXT
  | R_NOOVERWRITE
  | R_PREV
  | R_SETCURSOR


(* All other fields have default values *)
type btree_flag =
    Duplicates        (* means R_DUP *)
  | Cachesize of int


type file_perm = int

exception DB_error of string
  (* Raised by the following functions when an error is encountered. *)

external caml_db_init : unit -> unit
    = "caml_db_init"

let _ = Callback.register_exception "dberror" (DB_error "")
let _ = caml_db_init()

type key = string
type data = string
type t

(* Raw access *)
external dbopen : string -> open_flag list -> file_perm -> btree_flag list -> t
    = "caml_db_open"
    (* [dbopen file flags mode dupentries] *)

(* The common subset of available primitives *)
external close : t -> unit
    = "caml_db_close"

external del : t -> key -> routine_flag list -> unit
    = "caml_db_del"
    (* raise Not_found if the key was not in the file *)

external get : t -> key -> routine_flag list -> data
    = "caml_db_get"
    (* raise Not_found if the key was not in the file *)

external put : t -> key:key -> data:data -> routine_flag list -> unit
    = "caml_db_put"

external seq : t -> key -> routine_flag list -> (key * data)
    = "caml_db_seq"

external sync : t -> unit
    = "caml_db_sync"


(* Wrap-up as for other table-like types *)
let add db ~key:x ~data:v = put db x v [R_NOOVERWRITE]
let find db x = get db x []
let find_all db x =
  try
    match seq db x [R_CURSOR] with
      k, v when k = x ->
        let l = ref [v] in
        begin
          try
            while true do
              let k, v = seq db x [R_NEXT] in
              if k = x then l := v :: !l
              else raise Exit
            done;
            !l
          with
            Exit | Not_found -> !l
        end
    | _ -> (* its greater than x *) []
  with
    Not_found -> []

let remove db x = del db x []

let iter ~f db =
  let rec walk = function
      None -> ()
    | Some(k, v) ->
        f ~key:k ~data:v;
        walk (try Some(seq db k [R_NEXT]) with Not_found -> None)
  in
  walk (try Some(seq db "" [R_FIRST]) with Not_found -> None)
