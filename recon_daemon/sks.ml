(***********************************************************************)
(* sks.ml - Executable: Ueber-executable replacing all others          *)
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
open MoreLabels
open Printf
open Scanf
open Common

type command =
    { name: string;
      usage: string;
      desc: string;
      func: unit -> unit
    }

let usage command =
  sprintf "Usage: sks %s %s" command.name command.usage

let space = Str.regexp " ";;

let rec commands = [
  { name = "recon";
    usage = "";
    desc = "Initiates reconciliation server";
    func = (fun () ->
              let module M = Reconserver.F(struct end) in
              M.run ()
           )
  };
  { name = "pbuild";
    usage = "-cache [mbytes] -ptree_cache [mbytes]";
    desc = "Build prefix-tree database, used by reconciliation server, " ^
           "from key database.  Allows for specification of cache for " ^
           "key database and for ptree database.";
    func = (fun () ->
              let module M = Pbuild.F(struct end) in
              M.run ()
           )
  };
  { name = "help";
    usage = "";
    desc = "Prints this message";
    func = help;
  };
  { name = "version";
    usage = "";
    desc = "Show version information";
    func = Version.run;
  };
]

and help () =
  printf "This is a list of the available commands\n\n";
  List.iter commands
    ~f:(fun c ->
          Format.open_box 3;
          Format.print_string "sks ";
          Format.print_string c.name;
          if c.usage <> "" then (
            Format.print_string " ";
            Format.print_string c.usage);
          Format.print_string ":  ";
          List.iter (fun s ->
                       Format.print_string s;
                       Format.print_space ();)
            (Str.split space c.desc);
          Format.close_box ();
          Format.print_newline ();
       );
printf "\n"


(****************************************************)

let rec find name commands = match commands with
  | [] -> raise Not_found
  | hd::tl ->
      if hd.name = name
      then hd else find name tl


let () =
  match !Settings.anonlist with
    | [] ->
        eprintf "No command specified\n";
        exit (-1)
    | name::tl ->
        let command =
          try find name commands
             with Not_found ->
            eprintf "Unknown command %s\n" name;
            exit (-1)
        in
        Settings.anonlist := tl;
        printf "Executing %s" command.name;
        try command.func ()
        with
            Argument_error s ->
              eprintf "Argument error: %s\n" s;
              eprintf "Usage: sks %s %s\n%!" command.name command.usage;
              exit (-1)
