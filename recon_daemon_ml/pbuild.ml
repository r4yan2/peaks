(***********************************************************************)
(* pbuild.ml - Executable:  Builds a prefix-tree database from an      *)
(*             existing Keydb                                          *)
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

module F(M:sig end) =
struct
  open StdLabels
  open MoreLabels
  open Printf
  open Common
  open Bdb
  module PTree = PrefixTree

  module Keydb = Keydb.Safe

  open PTreeDB

  let ptree_settings = {
    mbar = !Settings.mbar;
    bitquantum = !Settings.bitquantum;
    treetype = `ondisk;
    max_nodes = !Settings.max_ptree_nodes;
    dbdir = Lazy.force Settings.ptree_dbdir;
    cache_bytes = !Settings.ptree_cache_bytes;
    pagesize = !Settings.ptree_pagesize;
  }

  let num_samples = ptree_settings.mbar + 1


  let rec get_n n str = match n with
      0 -> []
    | _ ->
        match SStream.next str with
            None -> []
          | Some x -> x::(get_n (n-1) str)

  let process_hashes hashes ptree txn =
    printf "Pbuild process_hashes. Hashes dimension: %d\n" (List.length hashes);
    List.iter ~f:(fun h -> PTree.insert_str ptree txn h) hashes

  let run str () =
    let txn = new_txnopt () in
    let ptree = PTree.create ?db:(get_db ()) ~txn:None
                  ~num_samples ~bitquantum:ptree_settings.bitquantum
                  ~thresh:(ptree_settings.mbar * !Settings.ptree_thresh_mult) ()
    in
    let count = ref 0 in
    while
      match get_n 5000 str with
          [] -> false
        | hashes ->
            process_hashes hashes ptree txn;
            count := !count + List.length hashes;
            perror "%d hashes processed" !count;
            true
    do () done;
    PTree.set_synctime ptree (Unix.gettimeofday ());
    perror "Cleaning Tree.";
    PTree.clean txn ptree;
    perror "committing";
    (try commit_txnopt txn with
      e ->
        eplerror 1 e "sync_tree transaction aborting";
        perror "aborting";
        abort_txnopt txn;
        ignore (raise e);)

 (***************************************************************)

  let () = Sys.set_signal Sys.sigusr1 Sys.Signal_ignore
  let () = Sys.set_signal Sys.sigusr2 Sys.Signal_ignore

  (***************************************************************)

  let run () =
    set_logfile "pbuild";
        perror "Running SKS %s%s" Common.version Common.version_suffix;

    if Sys.file_exists (Lazy.force Settings.ptree_dbdir) then (
      printf "PTree directory already exists.  Exiting.\n";
      exit (-1)
    );

    PTreeDB.init_db ptree_settings;

    let (hstr,hstr_close) = Keydb.create_hashstream () in
    protect ~f:(run hstr)
      ~finally:(fun () ->
                  PTreeDB.closedb ();
                  hstr_close ();
                  Keydb.close_dbs ();
               )
end
