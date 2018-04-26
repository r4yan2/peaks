(***********************************************************************)
(* catchup.ml - code used by the reconserver to catch up on whatever   *)
(*              updates have been made to the key database             *)
(*                                                                     *)
(* Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, *)
(*               2011, 2012, 2013  Yaron Minsky and Contributors       *)
(*                                                                     *)
(* This file is part of SKS.  SKS is free software; you can            *)
(* redistribute it and/or modify it under the terms of the GNU General *)
(* Public License as published by the Free Software Foundation; either *)
(* version 2 of the License, or (at your option) any later version.    *)
(*                                                                     *)
(* This program is distributed in the hope that it will be useful, but *)
(* WITHOUT ANY WARRANTY; without even the implied warranty of          *)
(* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU   *)
(* General Public License for more details.                            *)
(*                                                                     *)
(* You should have received a copy of the GNU General Public License   *)
(* along with this program; if not, write to the Free Software         *)
(* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 *)
(* USA or see <http://www.gnu.org/licenses/>.                          *)
(***********************************************************************)

open StdLabels
open Common
open PTreeDB

(***************************************************************)
(*  Catchup Code   *********************************************)
(***************************************************************)
module Keydb = Keydb.Safe

let count = 5000

let update_ptree () = 
  try
    (*(try
      if (not (Sys.is_directory Settings.csv_path)) then 
        failwith "Impossible to create CSV folder"
    with
      Sys_error e ->
        if (Sys.command ("mkdir " ^ Settings.csv_path) <> 0) then
          failwith "Impossible to create CSV folder");*)
    let txn = new_txnopt () in
    plerror 2 "Deleting removed hash";
    let removed_hash = Keydb.get_removed_hash () in
    let count_del = ref 0 in
    List.iter ~f:(fun h -> 
                  PTree.delete_str (get_ptree ()) txn h;
                  incr count_del; 
                  Keydb.delete_removed_hash h;
                  ()) removed_hash;
    plerror 2 "Updating ptree";
    let new_hash = Keydb.get_new_key count in
    let count_ins = ref 0 in
    List.iter ~f:(fun hash ->
      try
        PTree.insert_str (get_ptree ()) txn hash;
        plerror 6 "Inserting hash %s" (KeyHash.hexify hash);
        PTree.clean txn (get_ptree ());
        Keydb.set_as_sync hash;
        incr count_ins;
      with
        _ -> ()
    ) new_hash;
    plerror 2 "%d keys added to the ptree" !count_ins;
    PTree.set_synctime (get_ptree ()) (Unix.gettimeofday ());
    perror "Cleaning Tree.";
    PTree.clean txn (get_ptree ());
    (try commit_txnopt txn with
      e ->
        eplerror 1 e "sync_tree transaction aborting";
        abort_txnopt txn;
        ignore (raise e););

    (*if (Sys.file_exists Settings.deleted_key_csv) then begin
      Keydb.update_deleted_key ();
      (*Sys.remove Settings.deleted_key_csv*) end
    else
      plerror 1 "ERROR! The synk key file does not exist!!";

    if Sys.file_exists Settings.sync_key_csv then begin
      Keydb.update_synced_key ();
      (*Sys.remove Settings.sync_key_csv*) end
    else
      plerror 1 "ERROR! The synk key file does not exist!!"*)
  with
    e -> eplerror 1 e "Error during catchup";
  () 

let catchup_interval = 5.

