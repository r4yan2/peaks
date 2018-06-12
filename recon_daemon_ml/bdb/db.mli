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

(* $Id: db.mli,v 1.1.1.1 2002/10/01 00:10:14 yminsky Exp $ *)

(* Module [Db]: interface to the DB databases of type btree. Cf dbopen(3) *)

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

type key = string
type data = string

type t

(* Raw access *)
external dbopen :
    string -> open_flag list -> file_perm -> btree_flag list -> t
    = "caml_db_open"
    (* [dbopen file flags mode] *)

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


val add : t -> key:key -> data:data -> unit
val find : t -> key -> data
val find_all : t -> key -> data list
val remove : t -> key -> unit
val iter : f:(key:string -> data:string -> unit) -> t -> unit
